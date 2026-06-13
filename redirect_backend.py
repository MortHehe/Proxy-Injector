from __future__ import annotations

import argparse
import ctypes
import json
import socket
import sys
import time
from pathlib import Path
from typing import Any

import psutil
from colorama import Fore, Style, init as colorama_init

from proxy_server import (
    Config,
    append_debug_log,
    clear_redirect_targets,
    forget_redirect_target,
    ignore_pid,
    remember_redirect_target,
)


COLOR_LOGS = True
LOG_COLORS = {
    "redirect-ready": Fore.CYAN,
    "redirect": Fore.BLUE,
    "track": Fore.MAGENTA,
    "warn": Fore.YELLOW,
    "error": Fore.RED,
}
MAPPING_TTL_SECONDS = 300.0
CLEANUP_INTERVAL_SECONDS = 30.0
TRACK_DNS_REFRESH_SECONDS = 300.0
LOOPBACK_HOSTS = {"127.0.0.1", "::1"}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def load_map(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_map(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temp_path.replace(path)


def find_pid(local_port: int, remote_host: str, remote_port: int) -> int | None:
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, psutil.Error):
        return None

    for connection in connections:
        if not connection.laddr or not connection.raddr:
            continue
        if connection.laddr.port != local_port:
            continue
        if connection.raddr.port != remote_port:
            continue
        if connection.raddr.ip != remote_host:
            continue
        return connection.pid
    return None


def is_target_pid(config: Config, pid: int | None) -> bool:
    if pid is None:
        return False
    if config.route_name_for_pid(pid) is not None:
        return True
    try:
        name = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    return bool(config.target_process_name) and name.lower() == config.target_process_name.lower()


def is_ipv6_address(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        return False
    return True


def resolve_tracked_login_hosts(config: Config) -> dict[str, str]:
    tracked: dict[str, str] = {}
    for host in config.tracked_login_hosts:
        try:
            addresses = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            log("warn", f"login tracker could not resolve {host}: {exc}", config)
            continue
        for family, _socktype, _proto, _canonname, sockaddr in addresses:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            tracked[str(sockaddr[0])] = host
    return tracked


def log_tracked_login_target(
    config: Config,
    logged_targets: set[tuple[int | None, int, str]],
    pid: int | None,
    source_port: int,
    destination_host: str,
    destination_port: int,
    tracked_host: str | None,
    action: str,
) -> None:
    if tracked_host is None:
        return
    key = (pid, source_port, destination_host)
    if key in logged_targets:
        return
    logged_targets.add(key)
    log(
        "track",
        f"pid={pid or '?'} {source_port} login-host={tracked_host} "
        f"ip={destination_host}:{destination_port} action={action} "
        "endpoint=hidden-by-https",
        config,
    )


def should_redirect_packet(
    config: Config,
    pid: int | None,
    target_port: int,
    redirect_unknown_pid: bool,
) -> bool:
    if is_target_pid(config, pid):
        return True
    if target_port == config.target_remote_port:
        return redirect_unknown_pid
    return False


def remember_mapping(
    config: Config,
    source_port: int,
    destination_host: str,
    destination_port: int,
    pid: int | None,
) -> None:
    remember_redirect_target(source_port, destination_host, destination_port, pid)
    data = load_map(config.redirect_map_path)
    data[str(source_port)] = {
        "pid": pid,
        "destination_host": destination_host,
        "destination_port": destination_port,
        "updated_at": time.time(),
    }

    cutoff = time.time() - 300
    data = {
        key: value
        for key, value in data.items()
        if float(value.get("updated_at", 0)) >= cutoff
    }
    save_map(config.redirect_map_path, data)


def run(config: Config, redirect_unknown_pid: bool) -> None:
    try:
        import pydivert
        from pydivert.consts import Direction
    except ImportError:
        print("pydivert is not installed. Run: python -m pip install -r requirements.txt")
        raise

    if not is_admin():
        log("error", "redirect backend must be run as Administrator")
        sys.exit(1)

    global COLOR_LOGS
    COLOR_LOGS = config.color_logs
    colorama_init()

    target_ports = set(config.target_remote_ports)
    tracked_ports = {443} if config.tracked_login_hosts else set()
    filter_ports = target_ports | tracked_ports
    target_filter = " or ".join(f"tcp.DstPort == {port}" for port in sorted(filter_ports))
    transparent_port = config.transparent_listen_port
    nat_table: dict[int, tuple[str, int]] = {}
    mapped_pids: dict[int, int | None] = {}
    last_seen: dict[int, float] = {}
    last_cleanup_at = time.time()
    route_pids = {route.pid for route in config.routes if route.pid is not None}
    logged_redirects: set[int] = set()
    logged_loopback_targets: set[int | str] = set()
    logged_ipv6_targets: set[int | str] = set()
    logged_tracked_targets: set[tuple[int | None, int, str]] = set()
    tracked_login_ips = resolve_tracked_login_hosts(config)
    last_track_dns_at = time.time()
    clear_redirect_targets()
    save_map(config.redirect_map_path, {})

    packet_filter = (
        f"tcp and ({target_filter} or "
        f"tcp.SrcPort == {transparent_port})"
    )

    log(
        "redirect-ready",
        f"targets={','.join(str(port) for port in sorted(target_ports))} "
        f"transparent=adapter:{transparent_port} "
        f"unknown-pid={'on' if redirect_unknown_pid else 'off'}",
        config,
    )
    if config.tracked_login_hosts:
        log(
            "track",
            f"login tracker hosts={','.join(config.tracked_login_hosts)} "
            f"resolved-ips={len(tracked_login_ips)}",
            config,
        )
    if config.verbose:
        log("redirect-ready", f"filter: {packet_filter}", config)

    with pydivert.WinDivert(packet_filter) as divert:
        for packet in divert:
            try:
                if packet.tcp is None:
                    divert.send(packet)
                    continue

                if packet.is_outbound and packet.tcp.dst_port in filter_ports:
                    source_port = packet.tcp.src_port
                    target_port = packet.tcp.dst_port
                    destination_host = packet.dst_addr
                    now = time.time()
                    last_seen[source_port] = now
                    is_new_connection = bool(packet.tcp.syn and not packet.tcp.ack)
                    is_new_mapping = False

                    can_redirect_port = target_port in target_ports
                    if can_redirect_port and source_port in nat_table and not is_new_connection:
                        pid = mapped_pids.get(source_port)
                        should_redirect = True
                    else:
                        pid = find_pid(source_port, destination_host, target_port)
                        should_redirect = can_redirect_port and should_redirect_packet(
                            config,
                            pid,
                            target_port,
                            redirect_unknown_pid,
                        )

                    if now - last_track_dns_at >= TRACK_DNS_REFRESH_SECONDS:
                        tracked_login_ips = resolve_tracked_login_hosts(config)
                        last_track_dns_at = now

                    tracked_host = tracked_login_ips.get(destination_host)
                    if tracked_host is not None and (is_target_pid(config, pid) or should_redirect):
                        track_action = "proxy" if should_redirect else "local"
                        if is_ipv6_address(destination_host) and should_redirect and config.ipv6_target_action != "proxy":
                            track_action = config.ipv6_target_action
                        log_tracked_login_target(
                            config,
                            logged_tracked_targets,
                            pid,
                            source_port,
                            destination_host,
                            target_port,
                            tracked_host,
                            track_action,
                        )

                    if is_new_connection:
                        old_mapping = nat_table.pop(source_port, None)
                        mapped_pids.pop(source_port, None)
                        forget_redirect_target(source_port)
                        if old_mapping is not None and old_mapping != (destination_host, target_port):
                            logged_redirects.discard(source_port)
                            log(
                                "redirect",
                                f"pid={pid or '?'} {source_port} remapped "
                                f"{old_mapping[0]}:{old_mapping[1]} -> "
                                f"{destination_host}:{target_port}",
                            )

                    if should_redirect and is_ipv6_address(destination_host) and config.ipv6_target_action != "proxy":
                        ipv6_log_key: int | str = pid if pid is not None else f"{destination_host}:{target_port}"
                        if ipv6_log_key not in logged_ipv6_targets:
                            action_text = (
                                "blocked so the game retries IPv4 through the proxy"
                                if config.ipv6_target_action == "block"
                                else "bypassed because the upstream proxy may reject IPv6"
                            )
                            log(
                                "warn",
                                f"pid={pid or '?'} {source_port} IPv6 target "
                                f"{destination_host}:{target_port}; {action_text}",
                                config,
                            )
                            logged_ipv6_targets.add(ipv6_log_key)
                        if config.ipv6_target_action == "bypass":
                            divert.send(packet)
                        continue

                    if destination_host in LOOPBACK_HOSTS:
                        loopback_log_key: int | str = pid if pid is not None else f"port:{source_port}"
                        if loopback_log_key not in logged_loopback_targets:
                            log(
                                "error",
                                f"pid={pid or '?'} {source_port} target is local "
                                f"{destination_host}:{target_port}; cannot proxy because the real "
                                "game server IP is already hidden by another local redirect",
                                config,
                            )
                            logged_loopback_targets.add(loopback_log_key)
                        if pid is not None:
                            ignore_pid(config, pid, "local target already redirected")
                        divert.send(packet)
                        continue

                    if should_redirect:
                        if source_port not in nat_table or is_new_connection:
                            is_new_mapping = True
                            nat_table[source_port] = (destination_host, target_port)
                            mapped_pids[source_port] = pid
                        if is_new_mapping:
                            remember_mapping(config, source_port, destination_host, target_port, pid)
                        redirect_host = packet.src_addr
                        packet.direction = Direction.INBOUND
                        packet.dst_addr = redirect_host
                        packet.tcp.dst_port = transparent_port
                        packet.recalculate_checksums()
                        if source_port not in logged_redirects:
                            log(
                                "redirect",
                                f"pid={pid or '?'} {source_port} -> "
                                f"{destination_host}:{target_port} via {packet.dst_addr}:{transparent_port}",
                            )
                            logged_redirects.add(source_port)

                elif packet.tcp.src_port == transparent_port:
                    original = nat_table.get(packet.tcp.dst_port)
                    if original is not None:
                        original_host, original_port = original
                        packet.src_addr = original_host
                        packet.tcp.src_port = original_port
                        packet.direction = Direction.INBOUND
                        packet.recalculate_checksums()

                divert.send(packet)
                if packet.tcp and (packet.tcp.fin or packet.tcp.rst):
                    cleanup_port = packet.tcp.src_port if packet.tcp.dst_port in target_ports else packet.tcp.dst_port
                    last_seen[cleanup_port] = time.time() - MAPPING_TTL_SECONDS - 1
                now = time.time()
                if now - last_cleanup_at >= CLEANUP_INTERVAL_SECONDS:
                    cleanup_mappings(config, nat_table, mapped_pids, last_seen)
                    last_cleanup_at = now
            except Exception as exc:
                if config.verbose:
                    log("error", f"packet recovered from error: {exc}", config)
                try:
                    divert.send(packet)
                except Exception:
                    pass


def cleanup_mappings(
    config: Config,
    nat_table: dict[int, tuple[str, int]],
    mapped_pids: dict[int, int | None],
    last_seen: dict[int, float],
) -> None:
    cutoff = time.time() - MAPPING_TTL_SECONDS
    stale_ports = [
        source_port
        for source_port, updated_at in last_seen.items()
        if updated_at < cutoff
    ]
    if not stale_ports:
        return

    for source_port in stale_ports:
        nat_table.pop(source_port, None)
        mapped_pids.pop(source_port, None)
        last_seen.pop(source_port, None)
        forget_redirect_target(source_port)

    data = load_map(config.redirect_map_path)
    for source_port in stale_ports:
        data.pop(str(source_port), None)
    save_map(config.redirect_map_path, data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Experimental WinDivert redirect backend")
    parser.add_argument("--config", default="config.json")
    parser.add_argument(
        "--redirect-unknown-pid",
        action="store_true",
        help="Redirect all TCP target-port traffic when PID is not visible yet",
    )
    args = parser.parse_args()
    run(Config.load(Path(args.config)), args.redirect_unknown_pid)


def log(level: str, message: str, config: Config | None = None) -> None:
    prefix = f"[{level}]"
    if COLOR_LOGS:
        color = LOG_COLORS.get(level, "")
        print(f"{color}{prefix} {message}{Style.RESET_ALL}", flush=True)
    else:
        print(f"{prefix} {message}", flush=True)
    if level in ("warn", "error", "track"):
        append_debug_log(config.debug_log_path if config is not None else None, level, message)


if __name__ == "__main__":
    main()
