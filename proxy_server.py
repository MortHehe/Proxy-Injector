from __future__ import annotations

import argparse
import ctypes
import json
import os
import selectors
import socket
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import psutil
from colorama import Fore, Style, init as colorama_init

from upstream_servers import Upstream, configure_socket, connect_via_upstream


AF_INET = 2
TCP_TABLE_OWNER_PID_CONNECTIONS = 4
NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122
CONFIG_WRITE_LOCK = threading.Lock()
STATUS_LOG_LOCK = threading.Lock()
STATUS_LOG_LAST: dict[tuple[int | None, str, str, int, str], float] = {}
STATUS_LOG_INTERVAL_SECONDS = 10.0
LIVE_STATUS_INTERVAL_SECONDS = 0.5
PROCESS_SCAN_INTERVAL_SECONDS = 0.5
REDIRECT_MAP_RETRY_COUNT = 100
REDIRECT_MAP_RETRY_DELAY_SECONDS = 0.01
PID_ROUTE_RETRY_COUNT = 20
PID_ROUTE_RETRY_DELAY_SECONDS = 0.05
PID_STATUS_LOCK = threading.Lock()
PID_PROXY_STATUS: dict[int, dict[str, Any]] = {}
PID_STARTED_AT: dict[int, float] = {}
DETECTED_PIDS: set[int] = set()
PID_TRAFFIC: dict[int, dict[str, float]] = {}
PID_LATENCY: dict[int, dict[str, float]] = {}
PID_IGNORED_UNTIL: dict[int, float] = {}
TOTAL_TRAFFIC = {"up_total": 0.0, "down_total": 0.0}
PID_SOCKETS: dict[int, dict[socket.socket, int]] = {}
TABLE_RENDER_LOCK = threading.Lock()
REDIRECT_TARGET_LOCK = threading.Lock()
REDIRECT_TARGETS: dict[int, dict[str, Any]] = {}
SUMMARY_INTERVAL_SECONDS = 1.0
COLOR_LOGS = True
READY_LOGGED = False
DEFAULT_TARGET_PROCESS_NAME = "PixelWorlds.exe"
DEFAULT_TARGET_REMOTE_PORT = 10001
DEFAULT_TARGET_REMOTE_PORTS = (10001,)
DEFAULT_MAX_PIDS_PER_PROXY = 3
DEFAULT_PROXY_PROTOCOL = "socks5"
DEFAULT_IPV6_TARGET_ACTION = "bypass"
DEFAULT_NO_REPLY_WARN_SECONDS = 8.0
DEFAULT_NO_REPLY_CLOSE_SECONDS = 30.0
DEFAULT_DEBUG_LOG_PATH = "network_debug.log"
DEFAULT_TRACKED_LOGIN_HOSTS = (
    "11ef5c.playfabapi.com",
    "pw-auth.pw.sclfrst.com",
)
DEBUG_LOG_LOCK = threading.Lock()
DEBUG_LOG_PATH: Path | None = None


LOG_COLORS = {
    "ready": Fore.CYAN,
    "route": Fore.MAGENTA,
    "game": Fore.YELLOW,
    "summary": Fore.CYAN,
    "status": Fore.GREEN,
    "live": Fore.CYAN,
    "track": Fore.MAGENTA,
    "warn": Fore.YELLOW,
    "error": Fore.RED,
    "proxy-attempt": Fore.BLUE,
    "conn": Fore.BLUE,
}


@dataclass(frozen=True)
class Route:
    pid: int | None
    process_name: str | None
    upstream: str


@dataclass(frozen=True)
class RelayResult:
    reason: str
    down_bytes: int
    up_bytes: int
    first_down_after: float | None
    first_up_after: float | None


@dataclass(frozen=True)
class Config:
    config_path: Path
    listen_host: str
    listen_port: int
    transparent_bind_host: str
    transparent_listen_port: int
    redirect_map_path: Path
    target_process_name: str
    target_remote_port: int
    target_remote_ports: tuple[int, ...]
    default_route: str
    max_pids_per_proxy: int
    proxy_pid_limits: dict[str, int]
    auto_assign_routes: bool
    verbose: bool
    color_logs: bool
    hide_proxy_in_list: bool
    tcp_nodelay: bool
    socket_keepalive: bool
    socket_buffer_size: int
    relay_buffer_size: int
    connect_timeout_seconds: float
    summary_interval_seconds: float
    ipv6_target_action: str
    no_reply_warn_seconds: float
    no_reply_close_seconds: float
    debug_log_path: Path
    tracked_login_hosts: tuple[str, ...]
    upstreams: dict[str, Upstream]
    routes: list[Route]

    @classmethod
    def load(cls, path: Path) -> "Config":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        proxy_protocol = str(data.get("proxy_protocol", DEFAULT_PROXY_PROTOCOL)).lower()
        if proxy_protocol not in ("socks5", "http"):
            raise ValueError("proxy_protocol must be socks5 or http")
        upstreams: dict[str, Upstream] = {}
        for index, item in enumerate(data.get("upstreams", []), start=1):
            upstream = Upstream.from_config(item, index, proxy_protocol)
            upstreams[upstream.name] = upstream

        if "direct" not in upstreams:
            upstreams["direct"] = Upstream(name="direct", type="direct")
        proxy_names = [
            name
            for name, upstream in upstreams.items()
            if upstream.type != "direct"
        ]
        default_route = data.get("default_route") or (proxy_names[0] if proxy_names else "direct")
        if default_route not in upstreams:
            default_route = proxy_names[0] if proxy_names else "direct"
        routes = [
            Route(
                pid=item.get("pid"),
                process_name=item.get("process_name"),
                upstream=item["upstream"],
            )
            for item in data.get("routes", [])
        ]
        max_pids_per_proxy = int(data.get("max_pids_per_proxy", DEFAULT_MAX_PIDS_PER_PROXY))
        if max_pids_per_proxy < 1:
            raise ValueError("max_pids_per_proxy must be 1 or higher")

        proxy_pid_limits = {
            str(name): int(limit)
            for name, limit in data.get("proxy_pid_limits", {}).items()
        }
        for upstream in upstreams.values():
            if upstream.pid_limit is not None:
                proxy_pid_limits[upstream.name] = int(upstream.pid_limit)
        for name, limit in proxy_pid_limits.items():
            if limit < 1:
                raise ValueError(f"proxy_pid_limits[{name!r}] must be 1 or higher")

        target_remote_port = int(data.get("target_remote_port", DEFAULT_TARGET_REMOTE_PORT))
        target_remote_ports = parse_target_remote_ports(data, target_remote_port)
        ipv6_target_action = str(data.get("ipv6_target_action", DEFAULT_IPV6_TARGET_ACTION)).lower()
        if ipv6_target_action not in ("bypass", "block", "proxy"):
            ipv6_target_action = DEFAULT_IPV6_TARGET_ACTION
        tracked_login_hosts = parse_tracked_login_hosts(data)

        return cls(
            config_path=path,
            listen_host=data.get("listen_host", "127.0.0.1"),
            listen_port=int(data.get("listen_port", 15000)),
            transparent_bind_host=data.get("transparent_bind_host", "0.0.0.0"),
            transparent_listen_port=int(data.get("transparent_listen_port", 15001)),
            redirect_map_path=Path(data.get("redirect_map_path", "redirect_map.json")),
            target_process_name=data.get("target_process_name", DEFAULT_TARGET_PROCESS_NAME),
            target_remote_port=target_remote_port,
            target_remote_ports=target_remote_ports,
            default_route=default_route,
            max_pids_per_proxy=max_pids_per_proxy,
            proxy_pid_limits=proxy_pid_limits,
            auto_assign_routes=bool(data.get("auto_assign_routes", True)),
            verbose=bool(data.get("verbose", False)),
            color_logs=bool(data.get("color_logs", True)),
            hide_proxy_in_list=bool(data.get("hide_proxy_in_list", False)),
            tcp_nodelay=bool(data.get("tcp_nodelay", True)),
            socket_keepalive=bool(data.get("socket_keepalive", True)),
            socket_buffer_size=int(data.get("socket_buffer_size", 131072)),
            relay_buffer_size=int(data.get("relay_buffer_size", 131072)),
            connect_timeout_seconds=float(data.get("connect_timeout_seconds", 10)),
            summary_interval_seconds=float(data.get("summary_interval_seconds", SUMMARY_INTERVAL_SECONDS)),
            ipv6_target_action=ipv6_target_action,
            no_reply_warn_seconds=float(data.get("no_reply_warn_seconds", DEFAULT_NO_REPLY_WARN_SECONDS)),
            no_reply_close_seconds=float(data.get("no_reply_close_seconds", DEFAULT_NO_REPLY_CLOSE_SECONDS)),
            debug_log_path=Path(data.get("debug_log_path", DEFAULT_DEBUG_LOG_PATH)),
            tracked_login_hosts=tracked_login_hosts,
            upstreams=upstreams,
            routes=routes,
        )

    def upstream_for_pid(self, pid: int | None) -> Upstream:
        if pid is not None:
            for route in self.routes:
                if route.pid == pid:
                    return self.upstreams[route.upstream]
        return self.upstreams[self.default_route]

    def upstream_for_route(self, route_name: str) -> Upstream:
        return self.upstreams[route_name]

    def route_name_for_pid(self, pid: int) -> str | None:
        for route in self.routes:
            if route.pid == pid:
                return route.upstream
        return None

    def proxy_route_names(self) -> list[str]:
        return [
            name
            for name, upstream in self.upstreams.items()
            if upstream.type != "direct"
        ]

    def pid_limit_for_proxy(self, proxy_name: str) -> int:
        return self.proxy_pid_limits.get(proxy_name, self.max_pids_per_proxy)

    def auto_assign_pid(self, pid: int, process_name: str) -> str | None:
        existing = self.route_name_for_pid(pid)
        if existing:
            return existing

        proxy_names = self.proxy_route_names()
        if not proxy_names:
            return None

        counts = {name: 0 for name in proxy_names}
        for route in self.routes:
            if route.upstream in counts:
                counts[route.upstream] += 1

        selected = next(
            (name for name in proxy_names if counts[name] < self.pid_limit_for_proxy(name)),
            None,
        )
        if selected is None:
            return None

        route = Route(pid=pid, process_name=process_name, upstream=selected)
        self.routes.append(route)
        return selected

    def upstream_label_for_route(self, route_name: str | None) -> str:
        if route_name is None:
            return "-"
        upstream = self.upstreams.get(route_name)
        if upstream is None:
            return route_name
        return upstream_label(upstream)

    def remove_runtime_route(self, pid: int) -> None:
        self.routes[:] = [route for route in self.routes if route.pid != pid]

    def _save_route(self, route: Route) -> None:
        with CONFIG_WRITE_LOCK:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            routes = data.setdefault("routes", [])
            if not any(item.get("pid") == route.pid for item in routes):
                routes.append(
                    {
                        "pid": route.pid,
                        "process_name": route.process_name,
                        "upstream": route.upstream,
                    }
                )
            data["target_process_name"] = self.target_process_name
            data["max_pids_per_proxy"] = self.max_pids_per_proxy
            if self.proxy_pid_limits:
                data["proxy_pid_limits"] = self.proxy_pid_limits
            data["auto_assign_routes"] = self.auto_assign_routes
            data["hide_proxy_in_list"] = self.hide_proxy_in_list
            self.config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def parse_target_remote_ports(data: dict[str, Any], target_remote_port: int) -> tuple[int, ...]:
    raw_ports = data.get("target_remote_ports")
    if raw_ports is None:
        ports = [target_remote_port]
    elif isinstance(raw_ports, int):
        ports = [raw_ports]
    else:
        ports = list(raw_ports)

    cleaned = []
    for port in ports:
        value = int(port)
        if value < 1 or value > 65535:
            raise ValueError(f"target_remote_ports contains invalid port: {value}")
        if value not in cleaned:
            cleaned.append(value)
    if target_remote_port not in cleaned:
        cleaned.append(target_remote_port)
    return tuple(cleaned)


def parse_tracked_login_hosts(data: dict[str, Any]) -> tuple[str, ...]:
    raw_hosts = data.get("tracked_login_hosts", DEFAULT_TRACKED_LOGIN_HOSTS)
    if isinstance(raw_hosts, str):
        items = [raw_hosts]
    else:
        items = list(raw_hosts)

    hosts = []
    for item in items:
        value = str(item).strip()
        if not value:
            continue
        if "://" in value:
            parsed = urlsplit(value)
            value = parsed.hostname or ""
        else:
            value = value.split("/", 1)[0]
        value = value.strip().lower()
        if value and value not in hosts:
            hosts.append(value)
    return tuple(hosts)


class MibTcpRowOwnerPid(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_ulong),
        ("dwLocalAddr", ctypes.c_ulong),
        ("dwLocalPort", ctypes.c_ulong),
        ("dwRemoteAddr", ctypes.c_ulong),
        ("dwRemotePort", ctypes.c_ulong),
        ("dwOwningPid", ctypes.c_ulong),
    ]


def find_pid_for_tcp_connection(local_port: int, remote_port: int) -> int | None:
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi.dll")
    except OSError:
        return None
    size = ctypes.c_ulong(0)
    result = iphlpapi.GetExtendedTcpTable(
        None,
        ctypes.byref(size),
        False,
        AF_INET,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        0,
    )
    if result != ERROR_INSUFFICIENT_BUFFER:
        return None

    buffer = ctypes.create_string_buffer(size.value)
    result = iphlpapi.GetExtendedTcpTable(
        buffer,
        ctypes.byref(size),
        False,
        AF_INET,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        0,
    )
    if result != NO_ERROR:
        return None

    count = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ulong)).contents.value
    row_size = ctypes.sizeof(MibTcpRowOwnerPid)
    base = ctypes.addressof(buffer) + ctypes.sizeof(ctypes.c_ulong)

    for index in range(count):
        row = MibTcpRowOwnerPid.from_address(base + index * row_size)
        row_local_port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        row_remote_port = socket.ntohs(row.dwRemotePort & 0xFFFF)
        if row_local_port == local_port and row_remote_port == remote_port:
            return int(row.dwOwningPid)

    return None


def monitor_game_processes(config: Config) -> None:
    seen_processes: set[int] = set()
    known_process_names: dict[int, str] = {}
    seen_connections: set[tuple[int, str, int, int]] = set()
    last_summary_at = 0.0

    while True:
        try:
            _monitor_game_processes_once(config, seen_processes, known_process_names, seen_connections, last_summary_at)
            now = time.time()
            if now - last_summary_at >= config.summary_interval_seconds:
                last_summary_at = now
        except Exception as exc:
            log("error", f"monitor recovered from error: {exc}")
            time.sleep(2.0)


def _monitor_game_processes_once(
    config: Config,
    seen_processes: set[int],
    known_process_names: dict[int, str],
    seen_connections: set[tuple[int, str, int, int]],
    last_summary_at: float,
) -> None:
        changed = False
        target_pids = {
            route.pid
            for route in config.routes
            if route.pid is not None
        }

        for process in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = int(process.info["pid"])
                if is_pid_ignored(pid):
                    continue
                name = process.info.get("name") or ""
                if _is_target_process(config, pid, name):
                    target_pids.add(pid)
                    if pid not in seen_processes:
                        route_name = config.route_name_for_pid(pid)
                        if route_name is None and config.auto_assign_routes:
                            route_name = config.auto_assign_pid(pid, name)
                            if route_name is not None:
                                log("route", f"auto-assigned {name} pid={pid} -> {route_name}")

                        route_name = route_name or "unassigned"
                        if route_name != "unassigned":
                            set_pid_status(
                                pid,
                                "assigned",
                                config.upstream_label_for_route(route_name),
                                hide_proxy=config.hide_proxy_in_list,
                            )
                        log("game", f"detected {name} pid={pid} route={route_name}")
                        seen_processes.add(pid)
                        DETECTED_PIDS.add(pid)
                        known_process_names[pid] = name
                        PID_STARTED_AT[pid] = time.time()
                        changed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        live_process_names: dict[int, str] = {}
        for process in psutil.process_iter(["pid", "name"]):
            try:
                live_process_names[process.pid] = process.info.get("name") or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        for pid in list(seen_processes):
            live_name = live_process_names.get(pid)
            expected_name = known_process_names.get(pid, config.target_process_name or "")
            if is_pid_ignored(pid):
                name = known_process_names.get(pid, config.target_process_name or "app")
                log("warn", f"closed ignored {name} pid={pid}")
                seen_processes.remove(pid)
                DETECTED_PIDS.discard(pid)
                config.remove_runtime_route(pid)
                known_process_names.pop(pid, None)
                PID_STARTED_AT.pop(pid, None)
                clear_pid_state(pid)
                close_pid_connections(pid)
                changed = True
            elif live_name is None or live_name.lower() != expected_name.lower():
                name = known_process_names.get(pid, config.target_process_name or "app")
                log("warn", f"closed {name} pid={pid}")
                seen_processes.remove(pid)
                DETECTED_PIDS.discard(pid)
                config.remove_runtime_route(pid)
                known_process_names.pop(pid, None)
                PID_STARTED_AT.pop(pid, None)
                clear_pid_state(pid)
                close_pid_connections(pid)
                changed = True

        connections = []
        if config.verbose:
            try:
                connections = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, psutil.Error) as exc:
                log("warn", f"could not read TCP connections: {exc}")

        for connection in connections:
            if connection.pid not in target_pids or not connection.raddr:
                continue

            remote_host = connection.raddr.ip
            remote_port = connection.raddr.port
            local_port = connection.laddr.port if connection.laddr else 0
            key = (connection.pid, remote_host, remote_port, local_port)
            if key in seen_connections:
                continue

            if remote_host in ("127.0.0.1", "::1") and remote_port == config.listen_port:
                if config.verbose:
                    log(
                        "proxy-attempt",
                        f"game pid={connection.pid} is trying to connect "
                        f"through local proxy {config.listen_host}:{config.listen_port}",
                    )
                seen_connections.add(key)
            elif remote_port in config.target_remote_ports:
                if config.verbose:
                    log("game", f"game pid={connection.pid} connected to {remote_host}:{remote_port}")
                seen_connections.add(key)

        now = time.time()
        if changed or now - last_summary_at >= config.summary_interval_seconds:
            log_process_summary(seen_processes)

        time.sleep(PROCESS_SCAN_INTERVAL_SECONDS)


def _is_target_process(config: Config, pid: int, name: str) -> bool:
    if is_pid_ignored(pid):
        return False
    if any(route.pid == pid for route in config.routes):
        return True
    return bool(config.target_process_name) and name.lower() == config.target_process_name.lower()


def read_socks5_destination(client: socket.socket) -> tuple[str, int]:
    header = _recv_exact(client, 2)
    if header[0] != 5:
        raise ValueError("Only SOCKS5 clients are supported in this MVP")

    methods = _recv_exact(client, header[1])
    if 0 not in methods:
        client.sendall(b"\x05\xff")
        raise ValueError("SOCKS5 client did not offer no-auth mode")
    client.sendall(b"\x05\x00")

    request = _recv_exact(client, 4)
    version, command, _reserved, atyp = request
    if version != 5 or command != 1:
        client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        raise ValueError("Only SOCKS5 CONNECT is supported")

    if atyp == 1:
        host = socket.inet_ntoa(_recv_exact(client, 4))
    elif atyp == 3:
        length = _recv_exact(client, 1)[0]
        host = _recv_exact(client, length).decode("idna")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
    else:
        client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
        raise ValueError(f"Unsupported SOCKS5 address type: {atyp}")

    port = struct.unpack("!H", _recv_exact(client, 2))[0]
    return host, port


def send_socks5_success(client: socket.socket) -> None:
    client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")


def parse_tls_client_hello(data: bytes) -> tuple[bool, dict[str, Any] | None]:
    if len(data) < 5:
        return False, None
    if data[0] != 22:
        return True, None

    record_version = tls_version_name(data[1], data[2])
    record_length = int.from_bytes(data[3:5], "big")
    record_end = 5 + record_length
    if len(data) < record_end:
        return False, None

    if len(data) < 9 or data[5] != 1:
        return True, None

    handshake_length = int.from_bytes(data[6:9], "big")
    body_start = 9
    body_end = body_start + handshake_length
    if len(data) < body_end:
        return False, None

    body = data[body_start:body_end]
    if len(body) < 35:
        return True, None

    details: dict[str, Any] = {
        "record_version": record_version,
        "client_version": tls_version_name(body[0], body[1]),
        "sni": "",
        "alpn": [],
        "supported_versions": [],
    }

    offset = 34
    if offset >= len(body):
        return True, details
    session_id_length = body[offset]
    offset += 1 + session_id_length
    if offset + 2 > len(body):
        return True, details
    cipher_suites_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2 + cipher_suites_length
    if offset >= len(body):
        return True, details
    compression_methods_length = body[offset]
    offset += 1 + compression_methods_length
    if offset + 2 > len(body):
        return True, details

    extensions_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    extensions_end = min(len(body), offset + extensions_length)
    while offset + 4 <= extensions_end:
        extension_type = int.from_bytes(body[offset:offset + 2], "big")
        extension_length = int.from_bytes(body[offset + 2:offset + 4], "big")
        extension = body[offset + 4:offset + 4 + extension_length]
        offset += 4 + extension_length

        if extension_type == 0:
            details["sni"] = parse_sni_extension(extension)
        elif extension_type == 16:
            details["alpn"] = parse_alpn_extension(extension)
        elif extension_type == 43:
            details["supported_versions"] = parse_supported_versions_extension(extension)

    return True, details


def parse_sni_extension(extension: bytes) -> str:
    if len(extension) < 5:
        return ""
    list_length = int.from_bytes(extension[0:2], "big")
    offset = 2
    end = min(len(extension), offset + list_length)
    while offset + 3 <= end:
        name_type = extension[offset]
        name_length = int.from_bytes(extension[offset + 1:offset + 3], "big")
        offset += 3
        name = extension[offset:offset + name_length]
        offset += name_length
        if name_type == 0:
            try:
                return name.decode("idna")
            except UnicodeError:
                return name.decode("ascii", errors="replace")
    return ""


def parse_alpn_extension(extension: bytes) -> list[str]:
    if len(extension) < 2:
        return []
    offset = 2
    end = min(len(extension), 2 + int.from_bytes(extension[0:2], "big"))
    protocols = []
    while offset < end:
        length = extension[offset]
        offset += 1
        value = extension[offset:offset + length]
        offset += length
        if value:
            protocols.append(value.decode("ascii", errors="replace"))
    return protocols


def parse_supported_versions_extension(extension: bytes) -> list[str]:
    if not extension:
        return []
    length = extension[0]
    versions = []
    offset = 1
    end = min(len(extension), offset + length)
    while offset + 2 <= end:
        versions.append(tls_version_name(extension[offset], extension[offset + 1]))
        offset += 2
    return versions


def tls_version_name(major: int, minor: int) -> str:
    names = {
        (3, 0): "SSL3.0",
        (3, 1): "TLS1.0",
        (3, 2): "TLS1.1",
        (3, 3): "TLS1.2",
        (3, 4): "TLS1.3",
    }
    return names.get((major, minor), f"0x{major:02x}{minor:02x}")


def relay(
    left: socket.socket,
    right: socket.socket,
    buffer_size: int,
    pid: int | None,
    destination_host: str,
    destination_port: int,
    no_reply_warn_seconds: float,
    no_reply_close_seconds: float,
) -> RelayResult:
    register_pid_sockets(pid, destination_port, left, right)
    selector = selectors.DefaultSelector()
    left.setblocking(False)
    right.setblocking(False)
    selector.register(left, selectors.EVENT_READ, ("up", "game", right))
    selector.register(right, selectors.EVENT_READ, ("down", "proxy", left))
    started_at = time.time()
    up_bytes = 0
    down_bytes = 0
    first_up_after = None
    first_down_after = None
    first_down_warned = False
    tls_probe = bytearray()
    tls_probe_done = destination_port != 443

    def result(reason: str) -> RelayResult:
        return RelayResult(reason, down_bytes, up_bytes, first_down_after, first_up_after)

    try:
        while True:
            events = selector.select(timeout=1.0)
            if (
                not events
                and first_up_after is not None
                and first_down_after is None
                and not first_down_warned
                and no_reply_warn_seconds > 0
                and time.time() - started_at >= no_reply_warn_seconds
            ):
                log(
                    "warn",
                    f"pid={pid or '?'} dst={destination_host}:{destination_port} "
                    "has upload traffic but no server reply yet",
                )
                first_down_warned = True
                continue
            if (
                not events
                and first_up_after is not None
                and first_down_after is None
                and no_reply_close_seconds > 0
                and time.time() - started_at >= no_reply_close_seconds
            ):
                return result(
                    f"no_server_reply_timeout:{int(no_reply_close_seconds)}s"
                )

            for key, _events in events:
                source = key.fileobj
                direction, side, target = key.data
                try:
                    data = source.recv(buffer_size)
                except OSError as exc:
                    return result(f"{side}_recv_failed: {exc}")
                if not data:
                    reason = f"{side}_closed"
                    if side == "game" and first_down_after is None:
                        reason = "game_closed_before_server_reply"
                    return result(reason)
                record_traffic(pid, direction, len(data))
                if direction == "up":
                    up_bytes += len(data)
                    if not tls_probe_done:
                        tls_probe.extend(data)
                        try:
                            done, tls_details = parse_tls_client_hello(bytes(tls_probe))
                        except Exception as exc:
                            done, tls_details = True, None
                            log(
                                "warn",
                                f"pid={pid or '?'} tls-clienthello parse failed "
                                f"dst={destination_host}:{destination_port}: {exc}",
                            )
                        if done or len(tls_probe) >= 8192:
                            tls_probe_done = True
                            if tls_details is not None:
                                log(
                                    "track",
                                    f"pid={pid or '?'} tls-clienthello "
                                    f"dst={destination_host}:{destination_port} "
                                    f"sni={tls_details.get('sni') or '-'} "
                                    f"record={tls_details.get('record_version', '-')} "
                                    f"client={tls_details.get('client_version', '-')} "
                                    f"versions={','.join(tls_details.get('supported_versions', [])) or '-'} "
                                    f"alpn={','.join(tls_details.get('alpn', [])) or '-'}",
                                )
                            tls_probe.clear()
                    if first_up_after is None:
                        first_up_after = time.time() - started_at
                        record_latency(pid, first_up_after=first_up_after)
                else:
                    down_bytes += len(data)
                    if first_down_after is None:
                        first_down_after = time.time() - started_at
                        record_latency(pid, first_down_after=first_down_after)
                try:
                    target.sendall(data)
                except OSError as exc:
                    return result(f"{side}_send_failed: {exc}")
    finally:
        selector.close()
        unregister_pid_sockets(pid, left, right)


def handle_client(client: socket.socket, address: tuple[str, int], config: Config) -> None:
    pid = None
    upstream = None
    remote = None
    try:
        source_port = address[1]
        configure_socket(client, config.tcp_nodelay, config.socket_keepalive, config.socket_buffer_size)
        pid = find_pid_for_tcp_connection(source_port, config.listen_port)
        route_name = config.route_name_for_pid(pid) if pid is not None else None
        if config.verbose:
            log(
                "proxy-attempt",
                f"pid={pid or '?'} route={route_name or 'default'} "
                f"connected to local proxy from {address[0]}:{source_port}",
            )
        destination_host, destination_port = read_socks5_destination(client)
        if destination_port in config.target_remote_ports:
            pid, route_name = ensure_assigned_route(config, pid, source_port, config.listen_port)
            upstream = config.upstream_for_route(route_name)
        else:
            upstream = config.upstream_for_pid(pid)

        if destination_port not in config.target_remote_ports:
            log(
                "warn",
                f"PID {pid or '?'} requested port {destination_port}; "
                f"configured targets are {format_ports(config.target_remote_ports)}",
            )

        connect_started_at = time.time()
        remote = connect_via_upstream(
            upstream,
            destination_host,
            destination_port,
            timeout=config.connect_timeout_seconds,
            tcp_nodelay=config.tcp_nodelay,
            keepalive=config.socket_keepalive,
            buffer_size=config.socket_buffer_size,
        )
        record_latency(pid, proxy_connect_after=time.time() - connect_started_at)
        print_status(
            pid,
            upstream,
            destination_host,
            destination_port,
            "connected",
            hide_proxy=config.hide_proxy_in_list,
        )
        send_socks5_success(client)
        log(
            "conn",
            f"pid={pid or '?'} proxy={upstream_label(upstream)} "
            f"dst={destination_host}:{destination_port} started src_port={source_port}",
        )
        conn_started_at = time.time()
        result = relay(
            client,
            remote,
            config.relay_buffer_size,
            pid,
            destination_host,
            destination_port,
            config.no_reply_warn_seconds,
            config.no_reply_close_seconds,
        )
        log(
            "conn",
            f"pid={pid or '?'} ended after {format_runtime(time.time() - conn_started_at)} "
            f"down={format_bytes(result.down_bytes)} up={format_bytes(result.up_bytes)} "
            f"first_down={format_first_byte_time(result.first_down_after)} "
            f"first_up={format_first_byte_time(result.first_up_after)} "
            f"reason={result.reason}",
        )
    except Exception as exc:
        if upstream is not None:
            log("error", f"pid={pid or '?'} via {upstream_label(upstream)} failed: {exc}")
            print_status(pid, upstream, "?", 0, "failed", str(exc), config.hide_proxy_in_list)
        else:
            log("status", f"pid={pid or '?'} -> bypassed via unknown -> failed ({exc})")
    finally:
        client.close()
        if remote is not None:
            remote.close()


def handle_transparent_client(client: socket.socket, address: tuple[str, int], config: Config) -> None:
    pid = None
    upstream = None
    remote = None
    try:
        source_port = address[1]
        configure_socket(client, config.tcp_nodelay, config.socket_keepalive, config.socket_buffer_size)
        target = find_redirect_target(config.redirect_map_path, source_port)
        if target is None:
            raise ValueError(f"No redirect mapping found for local source port {source_port}")

        destination_host = target["destination_host"]
        destination_port = int(target["destination_port"])
        pid = target.get("pid")
        pid, route_name = ensure_assigned_route(
            config,
            pid,
            source_port,
            config.transparent_listen_port,
        )
        upstream = config.upstream_for_route(route_name)

        connect_started_at = time.time()
        remote = connect_via_upstream(
            upstream,
            destination_host,
            destination_port,
            timeout=config.connect_timeout_seconds,
            tcp_nodelay=config.tcp_nodelay,
            keepalive=config.socket_keepalive,
            buffer_size=config.socket_buffer_size,
        )
        record_latency(pid, proxy_connect_after=time.time() - connect_started_at)
        print_status(
            pid,
            upstream,
            destination_host,
            destination_port,
            "connected",
            hide_proxy=config.hide_proxy_in_list,
        )
        log(
            "conn",
            f"pid={pid or '?'} proxy={upstream_label(upstream)} "
            f"dst={destination_host}:{destination_port} started src_port={source_port}",
        )
        conn_started_at = time.time()
        result = relay(
            client,
            remote,
            config.relay_buffer_size,
            pid,
            destination_host,
            destination_port,
            config.no_reply_warn_seconds,
            config.no_reply_close_seconds,
        )
        log(
            "conn",
            f"pid={pid or '?'} ended after {format_runtime(time.time() - conn_started_at)} "
            f"down={format_bytes(result.down_bytes)} up={format_bytes(result.up_bytes)} "
            f"first_down={format_first_byte_time(result.first_down_after)} "
            f"first_up={format_first_byte_time(result.first_up_after)} "
            f"reason={result.reason}",
        )
    except Exception as exc:
        if upstream is not None:
            log("error", f"pid={pid or '?'} via {upstream_label(upstream)} failed: {exc}")
            print_status(
                pid,
                upstream,
                destination_host if "destination_host" in locals() else "?",
                int(destination_port) if "destination_port" in locals() else 0,
                "failed",
                str(exc),
                config.hide_proxy_in_list,
            )
        else:
            log("status", f"pid={pid or '?'} -> bypassed via unknown -> failed ({exc})")
    finally:
        client.close()
        if remote is not None:
            remote.close()


def ensure_assigned_route(
    config: Config,
    pid: int | None,
    source_port: int,
    local_proxy_port: int,
) -> tuple[int, str]:
    for _attempt in range(PID_ROUTE_RETRY_COUNT):
        if pid is None:
            pid = find_pid_for_tcp_connection(source_port, local_proxy_port)

        if pid is not None:
            route_name = config.route_name_for_pid(pid)
            if route_name is not None:
                return pid, route_name

            if config.auto_assign_routes:
                try:
                    process_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = config.target_process_name
                route_name = config.auto_assign_pid(pid, process_name)
                if route_name is not None:
                    set_pid_status(
                        pid,
                        "assigned",
                        config.upstream_label_for_route(route_name),
                        hide_proxy=config.hide_proxy_in_list,
                    )
                    log("route", f"auto-assigned {process_name} pid={pid} -> {route_name}")
                    return pid, route_name

        time.sleep(PID_ROUTE_RETRY_DELAY_SECONDS)

    raise ValueError("PID route was not ready; dropped connection instead of using a fallback proxy")


def find_redirect_target(path: Path, source_port: int) -> dict[str, Any] | None:
    key = str(source_port)
    for _attempt in range(REDIRECT_MAP_RETRY_COUNT):
        target = get_redirect_target(source_port)
        if target is not None:
            return target
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        target = data.get(key)
        if target is not None:
            return target
        time.sleep(REDIRECT_MAP_RETRY_DELAY_SECONDS)
    return None


def remember_redirect_target(
    source_port: int,
    destination_host: str,
    destination_port: int,
    pid: int | None,
) -> None:
    with REDIRECT_TARGET_LOCK:
        REDIRECT_TARGETS[source_port] = {
            "pid": pid,
            "destination_host": destination_host,
            "destination_port": destination_port,
            "updated_at": time.time(),
        }


def get_redirect_target(source_port: int) -> dict[str, Any] | None:
    with REDIRECT_TARGET_LOCK:
        target = REDIRECT_TARGETS.get(source_port)
        if target is None:
            return None
        return dict(target)


def forget_redirect_target(source_port: int) -> None:
    with REDIRECT_TARGET_LOCK:
        REDIRECT_TARGETS.pop(source_port, None)


def clear_redirect_targets() -> None:
    with REDIRECT_TARGET_LOCK:
        REDIRECT_TARGETS.clear()


def print_status(
    pid: int | None,
    upstream: Upstream,
    destination_host: str,
    destination_port: int,
    status: str,
    detail: str | None = None,
    hide_proxy: bool = False,
) -> None:
    key = (pid, upstream.name, destination_host, destination_port, status)
    now = time.time()
    with STATUS_LOG_LOCK:
        last_seen = STATUS_LOG_LAST.get(key, 0)
        if now - last_seen < STATUS_LOG_INTERVAL_SECONDS:
            return
        STATUS_LOG_LAST[key] = now

    suffix = f" ({destination_host}:{destination_port})" if destination_port else ""
    if detail:
        suffix = f" ({detail})"
    if pid is not None:
        set_pid_status(
            pid,
            status,
            upstream_label(upstream),
            destination_host,
            destination_port,
            hide_proxy,
        )
    table_pids = set(DETECTED_PIDS)
    if pid is not None:
        table_pids.add(pid)
    if table_pids:
        log_process_summary(table_pids)
    else:
        log("status", f"pid={pid or '?'} -> bypassed via {upstream_label(upstream)} -> {status}{suffix}")


def upstream_label(upstream: Upstream) -> str:
    if upstream.type == "direct":
        return "direct"
    if upstream.host and upstream.port:
        return f"{upstream.host}:{upstream.port}"
    return upstream.name


def set_pid_status(
    pid: int,
    status: str,
    upstream: str,
    destination_host: str = "",
    destination_port: int = 0,
    hide_proxy: bool = False,
) -> None:
    with PID_STATUS_LOCK:
        PID_PROXY_STATUS[pid] = {
            "status": status,
            "upstream": upstream,
            "hide_proxy": hide_proxy,
            "destination_host": destination_host,
            "destination_port": destination_port,
            "updated_at": time.time(),
        }


def clear_pid_state(pid: int) -> None:
    with PID_STATUS_LOCK:
        PID_PROXY_STATUS.pop(pid, None)
        PID_TRAFFIC.pop(pid, None)
        PID_LATENCY.pop(pid, None)


def ignore_pid(config: Config, pid: int, reason: str, seconds: float = 120.0) -> None:
    if is_pid_ignored(pid):
        PID_IGNORED_UNTIL[pid] = time.time() + seconds
        return

    PID_IGNORED_UNTIL[pid] = time.time() + seconds
    DETECTED_PIDS.discard(pid)
    PID_STARTED_AT.pop(pid, None)
    config.remove_runtime_route(pid)
    clear_pid_state(pid)
    close_pid_connections(pid)
    log("warn", f"closed ignored process pid={pid} reason={reason}")


def is_pid_ignored(pid: int) -> bool:
    expires_at = PID_IGNORED_UNTIL.get(pid)
    if expires_at is None:
        return False
    if time.time() >= expires_at:
        PID_IGNORED_UNTIL.pop(pid, None)
        return False
    return True


def log_process_summary(seen_processes: set[int]) -> None:
    with PID_STATUS_LOCK:
        rows = []
        for pid in sorted(seen_processes):
            status_info = PID_PROXY_STATUS.get(pid, {})
            status = status_info.get("status", "detected")
            real_upstream = status_info.get("upstream", "-")
            upstream = real_upstream
            if status_info.get("hide_proxy"):
                upstream = "hidden"
            started_at = PID_STARTED_AT.get(pid)
            runtime_seconds = time.time() - started_at if started_at else 0.0
            runtime = format_runtime(runtime_seconds) if started_at else "-"
            traffic = current_traffic_speed(pid)
            latency_seconds = latency_for_pid(pid)
            latency = format_latency_seconds(latency_seconds)
            rows.append((
                str(pid),
                status,
                upstream,
                runtime,
                format_speed(traffic["down_bps"]),
                format_speed(traffic["up_bps"]),
                format_megabytes(traffic["down_total"] + traffic["up_total"]),
                latency,
            ))
        total_used = TOTAL_TRAFFIC["down_total"] + TOTAL_TRAFFIC["up_total"]

    print_status_table(rows, total_used)


def print_status_table(rows: list[tuple[str, str, str, str, str, str, str, str]], total_used: float) -> None:
    headers = ("pid", "status", "proxy ip", "runtime", "down/s", "up/s", "used", "latency")
    widths = []
    for index in range(len(headers)):
        values = [len(headers[index])]
        values.extend(len(row[index]) for row in rows)
        widths.append(max(values))
    lines = [
        "  ".join(headers[index].ljust(widths[index]) for index in range(len(headers))),
        "  ".join("-" * widths[index] for index in range(len(headers))),
    ]
    for row in rows:
        lines.append("  ".join(row[index].ljust(widths[index]) for index in range(len(row))))
    if not rows:
        lines.append("no active processes")
    lines.append(f"total active instances: {len(rows)}")
    lines.append(f"total bandwidth used: {format_megabytes(total_used)}")

    with TABLE_RENDER_LOCK:
        print("\x1b[2J\x1b[H", end="")
        for line in lines:
            log("summary", line)


def record_traffic(pid: int | None, direction: str, size: int) -> None:
    if pid is None:
        return

    now = time.time()
    live_line: str | None = None
    with PID_STATUS_LOCK:
        stats = PID_TRAFFIC.setdefault(
            pid,
            {
                "up_total": 0.0,
                "down_total": 0.0,
                "last_up_total": 0.0,
                "last_down_total": 0.0,
                "last_check": now,
                "up_bps": 0.0,
                "down_bps": 0.0,
                "live_last_up_total": 0.0,
                "live_last_down_total": 0.0,
                "live_last_check": now,
                "live_last_emit": 0.0,
            },
        )
        key = "up_total" if direction == "up" else "down_total"
        stats[key] += size
        TOTAL_TRAFFIC[key] += size

        if now - stats.get("live_last_emit", 0.0) >= LIVE_STATUS_INTERVAL_SECONDS:
            elapsed = max(0.001, now - stats.get("live_last_check", now))
            up_bps = (stats["up_total"] - stats.get("live_last_up_total", 0.0)) / elapsed
            down_bps = (stats["down_total"] - stats.get("live_last_down_total", 0.0)) / elapsed
            stats["live_last_up_total"] = stats["up_total"]
            stats["live_last_down_total"] = stats["down_total"]
            stats["live_last_check"] = now
            stats["live_last_emit"] = now
            status_info = PID_PROXY_STATUS.get(pid, {})
            upstream = status_info.get("upstream", "-")
            latency = format_latency_seconds(latency_for_pid(pid))
            started_at = PID_STARTED_AT.get(pid)
            runtime = format_runtime(now - started_at) if started_at else "-"
            live_line = (
                f"pid={pid} status={status_info.get('status', 'connected')} "
                f"proxy={upstream} runtime={runtime} "
                f"down={format_speed(down_bps)} up={format_speed(up_bps)} "
                f"used={format_megabytes(stats['down_total'] + stats['up_total'])} "
                f"latency={latency}"
            )
    if live_line is not None:
        log("live", live_line)


def record_latency(
    pid: int | None,
    proxy_connect_after: float | None = None,
    first_down_after: float | None = None,
    first_up_after: float | None = None,
) -> None:
    if pid is None:
        return

    with PID_STATUS_LOCK:
        latency = PID_LATENCY.setdefault(pid, {})
        if proxy_connect_after is not None:
            latency["proxy_connect_after"] = proxy_connect_after
        if first_down_after is not None:
            latency["first_down_after"] = first_down_after
        if first_up_after is not None:
            latency["first_up_after"] = first_up_after
        latency["updated_at"] = time.time()


def traffic_totals(pid: int | None) -> tuple[float, float]:
    if pid is None:
        return 0.0, 0.0
    with PID_STATUS_LOCK:
        stats = PID_TRAFFIC.get(pid)
        if not stats:
            return 0.0, 0.0
        return float(stats["down_total"]), float(stats["up_total"])


def register_pid_sockets(pid: int | None, destination_port: int, *sockets: socket.socket) -> None:
    if pid is None:
        return
    with PID_STATUS_LOCK:
        bucket = PID_SOCKETS.setdefault(pid, {})
        for item in sockets:
            bucket[item] = destination_port


def unregister_pid_sockets(pid: int | None, *sockets: socket.socket) -> None:
    if pid is None:
        return
    with PID_STATUS_LOCK:
        bucket = PID_SOCKETS.get(pid)
        if not bucket:
            return
        for item in sockets:
            bucket.pop(item, None)
        if not bucket:
            PID_SOCKETS.pop(pid, None)


def close_pid_connections(pid: int | None, destination_port: int | None = None) -> int:
    if pid is None:
        return 0
    with PID_STATUS_LOCK:
        bucket = PID_SOCKETS.get(pid, {})
        if destination_port is None:
            sockets = list(bucket)
            PID_SOCKETS.pop(pid, None)
        else:
            sockets = [
                item
                for item, socket_destination_port in bucket.items()
                if socket_destination_port == destination_port
            ]
            for item in sockets:
                bucket.pop(item, None)
            if not bucket:
                PID_SOCKETS.pop(pid, None)
    for item in sockets:
        try:
            item.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            item.close()
        except OSError:
            pass
    return len(sockets)


def current_traffic_speed(pid: int) -> dict[str, float]:
    now = time.time()
    stats = PID_TRAFFIC.setdefault(
        pid,
        {
            "up_total": 0.0,
            "down_total": 0.0,
            "last_up_total": 0.0,
            "last_down_total": 0.0,
            "last_check": now,
            "up_bps": 0.0,
            "down_bps": 0.0,
        },
    )

    elapsed = max(0.001, now - stats["last_check"])
    stats["up_bps"] = (stats["up_total"] - stats["last_up_total"]) / elapsed
    stats["down_bps"] = (stats["down_total"] - stats["last_down_total"]) / elapsed
    stats["last_up_total"] = stats["up_total"]
    stats["last_down_total"] = stats["down_total"]
    stats["last_check"] = now
    return stats


def format_speed(bytes_per_second: float) -> str:
    if bytes_per_second >= 1024 * 1024:
        return f"{bytes_per_second / (1024 * 1024):.1f}MB"
    if bytes_per_second >= 1024:
        return f"{bytes_per_second / 1024:.1f}KB"
    return f"{bytes_per_second:.0f}B"


def format_bytes(byte_count: float) -> str:
    if byte_count >= 1024 * 1024:
        return f"{byte_count / (1024 * 1024):.2f}MB"
    if byte_count >= 1024:
        return f"{byte_count / 1024:.1f}KB"
    return f"{byte_count:.0f}B"


def format_megabytes(byte_count: float) -> str:
    return f"{byte_count / (1024 * 1024):.2f}MB"


def format_ports(ports: tuple[int, ...]) -> str:
    return ", ".join(str(port) for port in ports)


def format_first_byte_time(seconds: float | None) -> str:
    if seconds is None:
        return "none"
    return f"{seconds:.2f}s"


def latency_for_pid(pid: int) -> float | None:
    latency = PID_LATENCY.get(pid, {})
    seconds = latency.get("first_down_after")
    if seconds is None:
        seconds = latency.get("proxy_connect_after")
    return seconds


def format_latency(pid: int) -> str:
    return format_latency_seconds(latency_for_pid(pid))


def format_latency_seconds(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    milliseconds = max(0, int(seconds * 1000))
    return f"{milliseconds}ms"


def format_runtime(seconds: float) -> str:
    total_seconds = max(0, int(seconds))
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    if days:
        return f"{days}d{hours:02d}h{minutes:02d}m"
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def serve_listener(
    config: Config,
    host: str,
    port: int,
    handler: Any,
    label: str,
    family: int = socket.AF_INET,
) -> None:
    with socket.socket(family, socket.SOCK_STREAM) as server:
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(200)
        if config.verbose:
            log("ready", f"{label} listening on {host}:{port}")
        while True:
            client, address = server.accept()
            thread = threading.Thread(target=handler, args=(client, address, config), daemon=True)
            thread.start()


def serve(config: Config) -> None:
    global COLOR_LOGS, DEBUG_LOG_PATH, READY_LOGGED
    COLOR_LOGS = config.color_logs
    DEBUG_LOG_PATH = config.debug_log_path
    colorama_init()
    if not READY_LOGGED:
        append_debug_log(config.debug_log_path, "ready", "debug log started")
        log("ready", "all system ready")
        READY_LOGGED = True

    if config.verbose:
        log("ready", f"target process: {config.target_process_name or '<not set>'}")
        log("ready", f"target remote TCP ports: {format_ports(config.target_remote_ports)}")
        log("ready", f"auto route assignment: {'on' if config.auto_assign_routes else 'off'}")
        log("ready", f"verbose logging: {'on' if config.verbose else 'off'}")
        log("ready", f"color logs: {'on' if config.color_logs else 'off'}")
        log("ready", f"redirect map: {config.redirect_map_path}")

    monitor = threading.Thread(target=monitor_game_processes, args=(config,), daemon=True)
    monitor.start()

    transparent = threading.Thread(
        target=serve_listener,
        args=(
            config,
            config.transparent_bind_host,
            config.transparent_listen_port,
            handle_transparent_client,
            "transparent TCP proxy",
        ),
        daemon=True,
    )
    transparent.start()
    transparent_ipv6 = threading.Thread(
        target=serve_optional_listener,
        args=(
            config,
            "::",
            config.transparent_listen_port,
            handle_transparent_client,
            "transparent TCP proxy IPv6",
            socket.AF_INET6,
        ),
        daemon=True,
    )
    transparent_ipv6.start()

    serve_listener(
        config,
        config.listen_host,
        config.listen_port,
        handle_client,
        "SOCKS5 PID proxy",
    )


def serve_optional_listener(
    config: Config,
    host: str,
    port: int,
    handler: Any,
    label: str,
    family: int,
) -> None:
    try:
        serve_listener(config, host, port, handler, label, family)
    except OSError as exc:
        log("warn", f"{label} not available on {host}:{port}: {exc}")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("Connection closed while reading from socket")
        chunks.extend(chunk)
    return bytes(chunks)


def log(level: str, message: str) -> None:
    prefix = f"[{level}]"
    if COLOR_LOGS:
        color = LOG_COLORS.get(level, "")
        print(f"{color}{prefix} {message}{Style.RESET_ALL}", flush=True)
    else:
        print(f"{prefix} {message}", flush=True)
    if level in ("warn", "error", "track"):
        append_debug_log(DEBUG_LOG_PATH, level, message)


def append_debug_log(path: Path | None, level: str, message: str) -> None:
    if path is None:
        return
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with DEBUG_LOG_LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as file:
                file.write(f"[{timestamp}] [{level}] {message}\n")
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="PID-aware local SOCKS5 proxy MVP")
    parser.add_argument("--config", default="config.json", help="Path to config JSON")
    args = parser.parse_args()
    serve(Config.load(Path(args.config)))


if __name__ == "__main__":
    main()
