from __future__ import annotations

import argparse
import json
from pathlib import Path

import psutil


def find_processes(process_name: str) -> list[psutil.Process]:
    matches: list[psutil.Process] = []
    for process in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            if (process.info.get("name") or "").lower() == process_name.lower():
                matches.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(matches, key=lambda item: item.info.get("create_time") or 0)


def search_processes(text: str) -> list[psutil.Process]:
    matches: list[psutil.Process] = []
    needle = text.lower()
    for process in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time"]):
        try:
            values = [
                process.info.get("name") or "",
                process.info.get("exe") or "",
                " ".join(process.info.get("cmdline") or []),
            ]
            if any(needle in value.lower() for value in values):
                matches.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(matches, key=lambda item: item.info.get("create_time") or 0)


def get_upstream_names(data: dict) -> list[str]:
    names: list[str] = []
    for index, item in enumerate(data.get("upstreams", []), start=1):
        if isinstance(item, str):
            names.append(f"proxy-{index}")
            continue

        name = item.get("name")
        if name and item.get("type", "direct").lower() != "direct":
            names.append(name)
    return names


def load_proxy_limits(data: dict, overrides: list[str] | None = None) -> dict[str, int]:
    limits = {
        str(name): int(limit)
        for name, limit in data.get("proxy_pid_limits", {}).items()
    }
    for index, item in enumerate(data.get("upstreams", []), start=1):
        if not isinstance(item, dict):
            continue

        name = str(item.get("name") or f"proxy-{index}")
        limit = item.get("pid_limit", item.get("max_pids"))
        if limit is not None:
            limits[name] = int(limit)

    for override in overrides or []:
        if "=" not in override:
            raise ValueError("--proxy-limit must look like proxy-1=2")
        name, limit_text = override.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError("--proxy-limit proxy name cannot be empty")
        limits[name] = int(limit_text)

    for name, limit in limits.items():
        if limit < 1:
            raise ValueError(f"proxy_pid_limits[{name!r}] must be 1 or higher")
    return limits


def set_limits(
    config_path: Path,
    max_pids_per_proxy: int | None = None,
    proxy_limit_overrides: list[str] | None = None,
) -> None:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    if max_pids_per_proxy is not None:
        if max_pids_per_proxy < 1:
            raise ValueError("max_pids_per_proxy must be 1 or higher")
        data["max_pids_per_proxy"] = max_pids_per_proxy

    proxy_limits = load_proxy_limits(data, proxy_limit_overrides)
    if proxy_limits:
        data["proxy_pid_limits"] = proxy_limits

    config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Updated limits in {config_path}:")
    print(f"  Default max PIDs per proxy: {data.get('max_pids_per_proxy', 1)}")
    for name, limit in sorted(proxy_limits.items()):
        print(f"  {name}: {limit}")


def assign_routes(
    config_path: Path,
    process_name: str,
    max_pids_per_proxy: int | None = None,
    proxy_limit_overrides: list[str] | None = None,
) -> None:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    max_pids = max_pids_per_proxy or int(data.get("max_pids_per_proxy", 1))
    if max_pids < 1:
        raise ValueError("max_pids_per_proxy must be 1 or higher")
    proxy_limits = load_proxy_limits(data, proxy_limit_overrides)

    upstream_names = get_upstream_names(data)
    if not upstream_names:
        upstream_names = [data.get("default_route", "direct")]

    processes = find_processes(process_name)
    routes = []
    counts = {name: 0 for name in upstream_names}
    upstream_index = 0
    for process in processes:
        for offset in range(len(upstream_names)):
            candidate_index = (upstream_index + offset) % len(upstream_names)
            candidate = upstream_names[candidate_index]
            if counts[candidate] < proxy_limits.get(candidate, max_pids):
                upstream_name = candidate
                upstream_index = candidate_index
                break
        else:
            break

        counts[upstream_name] += 1
        if counts[upstream_name] >= proxy_limits.get(upstream_name, max_pids):
            upstream_index = (upstream_index + 1) % len(upstream_names)
        routes.append(
            {
                "pid": process.pid,
                "process_name": process_name,
                "upstream": upstream_name,
            }
        )

    data["target_process_name"] = process_name
    data["max_pids_per_proxy"] = max_pids
    if proxy_limits:
        data["proxy_pid_limits"] = proxy_limits
    data["routes"] = routes
    config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    print(f"Assigned {len(routes)} process(es) in {config_path}:")
    print(f"  Default max PIDs per proxy: {max_pids}")
    for name, limit in sorted(proxy_limits.items()):
        print(f"  {name} limit: {limit}")
    for route in routes:
        print(f"  PID {route['pid']} -> {route['upstream']}")


def clear_routes(config_path: Path) -> None:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    count = len(data.get("routes", []))
    data["routes"] = []
    config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Cleared {count} route(s) from {config_path}")


def list_processes(process_name: str) -> None:
    processes = find_processes(process_name)
    if not processes:
        print(f"No running processes named {process_name!r}")
        return

    for process in processes:
        try:
            print(f"{process.pid}\t{process.name()}\t{process.exe()}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print(f"{process.pid}\t{process_name}\t<access denied>")


def print_processes(processes: list[psutil.Process], empty_message: str) -> None:
    if not processes:
        print(empty_message)
        return

    for process in processes:
        try:
            print(f"{process.pid}\t{process.name()}\t{process.exe()}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print(f"{process.pid}\t<access denied>\t<access denied>")


def main() -> None:
    parser = argparse.ArgumentParser(description="List and assign per-PID proxy routes")
    parser.add_argument("process_name", nargs="?", help="Example: game.exe")
    parser.add_argument("--config", default="config.json", help="Path to config JSON")
    parser.add_argument("--assign", action="store_true", help="Rewrite config routes for matching PIDs")
    parser.add_argument("--clear-routes", action="store_true", help="Clear saved routes from config")
    parser.add_argument("--search", action="store_true", help="Fuzzy search process name/path/cmdline")
    parser.add_argument(
        "--set-limits",
        action="store_true",
        help="Update proxy PID limits in config without assigning routes",
    )
    parser.add_argument(
        "--max-pids-per-proxy",
        type=int,
        help="Set the default PID limit for every proxy",
    )
    parser.add_argument(
        "--proxy-limit",
        action="append",
        default=[],
        metavar="NAME=LIMIT",
        help="Set a per-proxy PID limit, for example proxy-1=2. Can be repeated.",
    )
    args = parser.parse_args()

    if args.clear_routes:
        clear_routes(Path(args.config))
    elif args.set_limits:
        set_limits(Path(args.config), args.max_pids_per_proxy, args.proxy_limit)
    elif args.search:
        if not args.process_name:
            parser.error("process_name is required with --search")
        print_processes(
            search_processes(args.process_name),
            f"No running processes matching {args.process_name!r}",
        )
    elif args.assign:
        if not args.process_name:
            parser.error("process_name is required with --assign")
        assign_routes(Path(args.config), args.process_name, args.max_pids_per_proxy, args.proxy_limit)
    else:
        if not args.process_name:
            parser.error("process_name is required unless --set-limits or --clear-routes is used")
        list_processes(args.process_name)


if __name__ == "__main__":
    main()
