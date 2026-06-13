from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText


APP_TITLE = "Dunia Pixel Proxy Injector"
APP_VERSION = "1.0.36"
APP_WATERMARK = "Creator: morthehe    DuniaPixel.co"
LOG_FILE = "ui_runtime.log"
WORKER_CONFIG_FILE = "ui_worker_config.json"
PROXY_CHECK_HOST = "1.1.1.1"
PROXY_CHECK_PORT = 80
PROXY_CHECK_TIMEOUT_SECONDS = 5.0
DEFAULT_HIDE_PROXY_IN_LIST = False
DEFAULT_MAX_PIDS_PER_PROXY = 3
DEFAULT_SUMMARY_INTERVAL_SECONDS = 1.0
DEFAULT_PROXY_PROTOCOL = "socks5"
DEFAULT_IPV6_TARGET_ACTION = "bypass"
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def config_path() -> Path:
    return app_dir() / "config.json"


def log_path() -> Path:
    return app_dir() / LOG_FILE


def worker_config_path() -> Path:
    return app_dir() / WORKER_CONFIG_FILE


def app_executable_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return Path(__file__).resolve()


def is_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def machine_label() -> str:
    computer = os.environ.get("COMPUTERNAME") or socket.gethostname()
    username = os.environ.get("USERNAME") or ""
    session = os.environ.get("SESSIONNAME") or ""
    parts = [computer]
    if username:
        parts.append(username)
    if session:
        parts.append(session)
    return " / ".join(parts)


def worker_main(config: str) -> None:
    import run_all

    log_file = log_path().open("a", encoding="utf-8", buffering=1)
    sys.stdout = log_file
    sys.stderr = log_file
    sys.argv = [sys.argv[0], "--config", config]
    print("[ready] UI worker starting")
    run_all.main()


class PixelProxyUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"{APP_TITLE} v{APP_VERSION}")
        self.root.geometry("1080x640")
        self.root.minsize(980, 520)
        self.process: subprocess.Popen[str] | None = None
        self.log_position = 0
        self.rows: dict[str, tuple[str, str, str, str, str, str, str, str]] = {}
        self.summary_pids: set[str] = set()
        self.status_var = tk.StringVar(value="Stopped")
        self.admin_var = tk.StringVar(value="Administrator" if is_admin() else "Not Administrator")
        self.machine_var = tk.StringVar(value=machine_label())
        self.total_bandwidth_var = tk.StringVar(value="0.00MB")
        self.process_count_var = tk.StringVar(value="0")
        self.hide_proxy_var = tk.BooleanVar(value=DEFAULT_HIDE_PROXY_IN_LIST)
        self.proxy_protocol_var = tk.StringVar(value=DEFAULT_PROXY_PROTOCOL)
        self.ipv6_target_action_var = tk.StringVar(value=DEFAULT_IPV6_TARGET_ACTION)
        self.proxy_web_var = tk.BooleanVar(value=False)
        self.max_pids_var = tk.IntVar(value=DEFAULT_MAX_PIDS_PER_PROXY)
        self.summary_interval_var = tk.DoubleVar(value=DEFAULT_SUMMARY_INTERVAL_SECONDS)

        self.build_ui()
        self.load_config()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(500, self.poll)

    def build_ui(self) -> None:
        self.configure_style()
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

        header = ttk.Frame(self.root, padding=(14, 12, 14, 8), style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        title_box = ttk.Frame(header, style="App.TFrame")
        title_box.grid(row=0, column=0, sticky="w")
        ttk.Label(title_box, text=f"{APP_TITLE} v{APP_VERSION}", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(title_box, textvariable=self.admin_var, style="Subtle.TLabel").grid(row=1, column=0, sticky="w")
        ttk.Label(title_box, textvariable=self.machine_var, style="Subtle.TLabel").grid(row=2, column=0, sticky="w")

        metrics = ttk.Frame(header, style="App.TFrame")
        metrics.grid(row=0, column=1, sticky="e")
        self.status_label = ttk.Label(metrics, textvariable=self.status_var, style="Status.TLabel")
        self.status_label.grid(row=0, column=0, sticky="e", padx=(0, 10))
        ttk.Label(metrics, text="instances active", style="MetricName.TLabel").grid(row=0, column=1, sticky="e")
        ttk.Label(metrics, textvariable=self.process_count_var, style="MetricValue.TLabel").grid(row=1, column=1, sticky="e", padx=(0, 18))
        ttk.Label(metrics, text="total used", style="MetricName.TLabel").grid(row=0, column=2, sticky="e")
        ttk.Label(metrics, textvariable=self.total_bandwidth_var, style="MetricValue.TLabel").grid(row=1, column=2, sticky="e")

        controls = ttk.Frame(self.root, padding=(14, 0, 14, 10), style="App.TFrame")
        controls.grid(row=1, column=0, sticky="ew")
        controls.columnconfigure(10, weight=1)

        self.start_button = ttk.Button(controls, text="Start", command=self.start)
        self.start_button.grid(row=0, column=0, padx=(0, 8))
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=(0, 16))

        ttk.Checkbutton(
            controls,
            text="Hide proxy in list",
            variable=self.hide_proxy_var,
            command=self.on_hide_proxy_changed,
        ).grid(row=0, column=2, padx=(0, 16))

        ttk.Label(controls, text="Protocol").grid(row=0, column=3, padx=(0, 6))
        protocol_box = ttk.Combobox(
            controls,
            width=7,
            textvariable=self.proxy_protocol_var,
            values=("socks5", "http"),
            state="readonly",
        )
        protocol_box.grid(row=0, column=4, padx=(0, 16))
        protocol_box.bind("<<ComboboxSelected>>", lambda _event: self.save_config())

        ttk.Label(controls, text="IPv6").grid(row=0, column=5, padx=(0, 6))
        ipv6_box = ttk.Combobox(
            controls,
            width=7,
            textvariable=self.ipv6_target_action_var,
            values=("bypass", "block", "proxy"),
            state="readonly",
        )
        ipv6_box.grid(row=0, column=6, padx=(0, 16))
        ipv6_box.bind("<<ComboboxSelected>>", lambda _event: self.save_config())

        ttk.Checkbutton(
            controls,
            text="Proxy web",
            variable=self.proxy_web_var,
            command=self.save_config,
        ).grid(row=0, column=7, padx=(0, 16))

        ttk.Label(controls, text="PIDs/proxy").grid(row=0, column=8, padx=(0, 6))
        ttk.Spinbox(
            controls,
            from_=1,
            to=100,
            width=5,
            textvariable=self.max_pids_var,
            command=self.save_config,
        ).grid(row=0, column=9, padx=(0, 16))

        ttk.Label(controls, text="Refresh").grid(row=0, column=10, padx=(0, 6))
        ttk.Spinbox(
            controls,
            from_=0.5,
            to=60.0,
            increment=0.5,
            width=6,
            textvariable=self.summary_interval_var,
            command=self.save_config,
        ).grid(row=0, column=11, padx=(0, 6))
        ttk.Label(controls, text="sec").grid(row=0, column=12, padx=(0, 16))

        ttk.Button(controls, text="Save Config", command=self.save_config).grid(row=0, column=13, padx=(0, 8))
        ttk.Button(controls, text="Open Config", command=self.open_config).grid(row=0, column=14, padx=(0, 8))
        self.check_button = ttk.Button(controls, text="Check Proxies", command=self.check_proxies)
        self.check_button.grid(row=0, column=15, padx=(0, 8))
        ttk.Button(controls, text="Clear Logs", command=self.clear_logs).grid(row=0, column=16)

        body = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        body.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.root.update_idletasks()

        table_frame = ttk.Frame(body, style="Panel.TFrame", padding=1)
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.table = ttk.Treeview(
            table_frame,
            columns=("pid", "status", "proxy", "runtime", "down", "up", "used", "latency"),
            show="headings",
            height=12,
            selectmode="browse",
        )
        for key, text, width, minwidth, stretch in (
            ("pid", "PID", 62, 52, False),
            ("status", "Status", 82, 70, False),
            ("proxy", "Proxy", 190, 150, True),
            ("runtime", "Runtime", 74, 64, False),
            ("down", "Down/s", 72, 62, False),
            ("up", "Up/s", 66, 56, False),
            ("used", "Used", 76, 64, False),
            ("latency", "Latency", 72, 62, False),
        ):
            self.table.heading(key, text=text)
            self.table.column(key, width=width, minwidth=minwidth, anchor="w", stretch=stretch)
        self.table.tag_configure("connected", background="#ecf8f1")
        self.table.tag_configure("assigned", background="#eef5ff")
        self.table.tag_configure("failed", background="#fff0f2")
        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=y_scroll.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        body.add(table_frame, weight=8)

        log_frame = ttk.Frame(body, style="Panel.TFrame", padding=1)
        log_frame.rowconfigure(1, weight=1)
        log_frame.columnconfigure(0, weight=1)
        ttk.Label(log_frame, text="Logs", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="ew")
        self.log_view = ScrolledText(
            log_frame,
            wrap="word",
            height=5,
            font=("Consolas", 8),
            bg="#0f141a",
            fg="#d8e1e8",
            insertbackground="#d8e1e8",
            relief="flat",
            padx=8,
            pady=8,
        )
        self.log_view.grid(row=1, column=0, sticky="nsew")
        self.configure_log_tags()
        body.add(log_frame, weight=1)

        footer = ttk.Frame(self.root, padding=(14, 0, 14, 8), style="App.TFrame")
        footer.grid(row=3, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)
        ttk.Label(footer, text=APP_WATERMARK, style="Watermark.TLabel").grid(row=0, column=0, sticky="e")

    def configure_style(self) -> None:
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
        self.root.configure(bg="#eef1f4")
        style.configure("App.TFrame", background="#eef1f4")
        style.configure("Panel.TFrame", background="#d6dde5")
        style.configure("Title.TLabel", background="#eef1f4", foreground="#111827", font=("Segoe UI", 16, "bold"))
        style.configure("Subtle.TLabel", background="#eef1f4", foreground="#667085")
        style.configure("MetricName.TLabel", background="#eef1f4", foreground="#667085", font=("Segoe UI", 8))
        style.configure("MetricValue.TLabel", background="#eef1f4", foreground="#111827", font=("Segoe UI", 11, "bold"))
        style.configure("Watermark.TLabel", background="#eef1f4", foreground="#667085", font=("Segoe UI", 8))
        style.configure("Status.TLabel", background="#dff6e7", foreground="#0f6b35", padding=(10, 4), font=("Segoe UI", 9, "bold"))
        style.configure("PanelTitle.TLabel", background="#f7f9fb", foreground="#344054", padding=(8, 6), font=("Segoe UI", 9, "bold"))
        style.configure("Treeview", rowheight=22, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def configure_log_tags(self) -> None:
        self.log_view.tag_configure("error", foreground="#ff7b8a")
        self.log_view.tag_configure("warn", foreground="#f4c76b")
        self.log_view.tag_configure("ok", foreground="#80d99b")
        self.log_view.tag_configure("route", foreground="#d7a4ff")
        self.log_view.tag_configure("game", foreground="#ffd479")
        self.log_view.tag_configure("status", foreground="#8dd4e8")
        self.log_view.tag_configure("conn", foreground="#80c7ff")
        self.log_view.tag_configure("redirect", foreground="#7dd3fc")
        self.log_view.tag_configure("track", foreground="#d7a4ff")
        self.log_view.tag_configure("ui", foreground="#8fd6c2")

    def load_config(self) -> None:
        try:
            data = json.loads(config_path().read_text(encoding="utf-8-sig"))
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not read config.json:\n{exc}")
            return

        self.hide_proxy_var.set(bool(data.get("hide_proxy_in_list", DEFAULT_HIDE_PROXY_IN_LIST)))
        protocol = str(data.get("proxy_protocol", DEFAULT_PROXY_PROTOCOL)).lower()
        if protocol not in ("socks5", "http"):
            protocol = DEFAULT_PROXY_PROTOCOL
        self.proxy_protocol_var.set(protocol)
        ipv6_action = str(data.get("ipv6_target_action", DEFAULT_IPV6_TARGET_ACTION)).lower()
        if ipv6_action not in ("bypass", "block", "proxy"):
            ipv6_action = DEFAULT_IPV6_TARGET_ACTION
        self.ipv6_target_action_var.set(ipv6_action)
        raw_target_ports = data.get("target_remote_ports", data.get("target_remote_port", 10001))
        if isinstance(raw_target_ports, (list, tuple)):
            target_ports = {int(port) for port in raw_target_ports}
        else:
            target_ports = {int(raw_target_ports)}
        self.proxy_web_var.set(80 in target_ports or 443 in target_ports)
        self.max_pids_var.set(int(data.get("max_pids_per_proxy", DEFAULT_MAX_PIDS_PER_PROXY)))
        self.summary_interval_var.set(float(data.get("summary_interval_seconds", DEFAULT_SUMMARY_INTERVAL_SECONDS)))

    def update_process_count(self) -> None:
        count = len(self.rows)
        self.process_count_var.set(str(count))

    def save_config(self) -> None:
        try:
            path = config_path()
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            protocol = self.proxy_protocol_var.get().lower()
            if protocol not in ("socks5", "http"):
                protocol = DEFAULT_PROXY_PROTOCOL
                self.proxy_protocol_var.set(protocol)
            ipv6_action = self.ipv6_target_action_var.get().lower()
            if ipv6_action not in ("bypass", "block", "proxy"):
                ipv6_action = DEFAULT_IPV6_TARGET_ACTION
                self.ipv6_target_action_var.set(ipv6_action)
            data["proxy_protocol"] = protocol
            data["ipv6_target_action"] = ipv6_action
            data["target_remote_ports"] = [80, 443, 10001] if self.proxy_web_var.get() else [10001]
            data["max_pids_per_proxy"] = max(1, int(self.max_pids_var.get()))
            data["summary_interval_seconds"] = max(0.5, float(self.summary_interval_var.get()))
            data["hide_proxy_in_list"] = bool(self.hide_proxy_var.get())
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.append_log("[ui] config saved")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not save config.json:\n{exc}")

    def clear_logs(self) -> None:
        self.log_view.configure(state="normal")
        self.log_view.delete("1.0", "end")
        self.log_view.configure(state="disabled")

    def on_hide_proxy_changed(self) -> None:
        self.render_table()

    def create_worker_config(self) -> Path:
        data = json.loads(config_path().read_text(encoding="utf-8-sig"))
        data["proxy_protocol"] = self.proxy_protocol_var.get().lower()
        data["ipv6_target_action"] = self.ipv6_target_action_var.get().lower()
        data["target_remote_ports"] = [80, 443, 10001] if self.proxy_web_var.get() else [10001]
        data["max_pids_per_proxy"] = max(1, int(self.max_pids_var.get()))
        data["summary_interval_seconds"] = max(0.5, float(self.summary_interval_var.get()))
        data["hide_proxy_in_list"] = False
        path = worker_config_path()
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def ensure_firewall_rules(self, worker_config: Path) -> None:
        if os.name != "nt":
            return
        if not is_admin():
            self.append_log("[warn] firewall rules skipped; app is not running as Administrator")
            return

        try:
            from proxy_server import Config

            config = Config.load(worker_config)
            ports = sorted({config.transparent_listen_port, config.listen_port})
            exe_path = str(app_executable_path())
            for port in ports:
                self.ensure_firewall_rule(
                    f"PixelProxyInjector TCP {port} In",
                    [
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=PixelProxyInjector TCP {port} In",
                        "dir=in",
                        "action=allow",
                        "protocol=TCP",
                        f"localport={port}",
                    ],
                )
                self.ensure_firewall_rule(
                    f"PixelProxyInjector TCP {port} Out",
                    [
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        f"name=PixelProxyInjector TCP {port} Out",
                        "dir=out",
                        "action=allow",
                        "protocol=TCP",
                        f"localport={port}",
                    ],
                )

            self.ensure_firewall_rule(
                "PixelProxyInjector App In",
                [
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=PixelProxyInjector App In",
                    "dir=in",
                    "action=allow",
                    f"program={exe_path}",
                    "enable=yes",
                ],
            )
            self.ensure_firewall_rule(
                "PixelProxyInjector App Out",
                [
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=PixelProxyInjector App Out",
                    "dir=out",
                    "action=allow",
                    f"program={exe_path}",
                    "enable=yes",
                ],
            )
            self.append_log("[ui] firewall rules ready")
        except Exception as exc:
            self.append_log(f"[warn] firewall rule setup failed: {exc}")

    def ensure_firewall_rule(self, rule_name: str, add_args: list[str]) -> None:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            cwd=app_dir(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        completed = subprocess.run(
            ["netsh", *add_args],
            cwd=app_dir(),
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "netsh failed").strip()
            raise RuntimeError(f"{rule_name}: {message}")

    def open_config(self) -> None:
        path = config_path()
        if os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", str(path)])

    def check_proxies(self) -> None:
        self.check_button.configure(state="disabled")
        self.append_log("[ui] checking proxies")
        thread = threading.Thread(target=self.check_proxies_worker, daemon=True)
        thread.start()

    def check_proxies_worker(self) -> None:
        from proxy_server import Config, upstream_label
        from upstream_servers import connect_via_upstream

        try:
            config = Config.load(config_path())
            proxies = [
                upstream
                for upstream in config.upstreams.values()
                if upstream.type != "direct"
            ]
            if not proxies:
                self.root.after(0, self.append_log, "[proxy-check] no proxies configured")
                return

            for upstream in proxies:
                label = upstream_label(upstream)
                self.root.after(0, self.append_log, f"[proxy-check] checking {upstream.name} {label}")
                sock = None
                try:
                    sock = connect_via_upstream(
                        upstream,
                        PROXY_CHECK_HOST,
                        PROXY_CHECK_PORT,
                        timeout=PROXY_CHECK_TIMEOUT_SECONDS,
                        tcp_nodelay=True,
                        keepalive=True,
                        buffer_size=32768,
                    )
                    sock.settimeout(2.0)
                    sock.sendall(b"HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")
                    sock.recv(1)
                    self.root.after(0, self.append_log, f"[proxy-check] OK {upstream.name} {label}")
                except Exception as exc:
                    self.root.after(0, self.append_log, f"[proxy-check] FAILED {upstream.name} {label}: {exc}")
                finally:
                    if sock is not None:
                        sock.close()
            self.root.after(0, self.append_log, "[proxy-check] done")
        finally:
            self.root.after(0, lambda: self.check_button.configure(state="normal"))

    def start(self) -> None:
        if self.process and self.process.poll() is None:
            return
        if not is_admin():
            messagebox.showwarning(APP_TITLE, "Run this app as Administrator so WinDivert can start.")

        self.save_config()
        worker_config = self.create_worker_config()
        log_path().write_text("", encoding="utf-8")
        self.log_position = 0
        self.clear_table()
        self.ensure_firewall_rules(worker_config)

        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "--worker", "--config", str(worker_config)]
        else:
            cmd = [sys.executable, str(Path(__file__).resolve()), "--worker", "--config", str(worker_config)]

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW
        self.process = subprocess.Popen(cmd, cwd=app_dir(), creationflags=creationflags)
        self.status_var.set("Running")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.append_log("[ui] worker started")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.append_log("[ui] stopping worker")
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None
        self.status_var.set("Stopped")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.clear_table()

    def poll(self) -> None:
        if self.process and self.process.poll() is not None:
            self.status_var.set(f"Stopped ({self.process.returncode})")
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.process = None
            self.clear_table()

        self.read_log()
        self.root.after(500, self.poll)

    def read_log(self) -> None:
        path = log_path()
        if not path.exists():
            return
        with path.open("r", encoding="utf-8", errors="replace") as file:
            file.seek(self.log_position)
            chunk = file.read()
            self.log_position = file.tell()
        if not chunk:
            return

        clean = ANSI_ESCAPE_RE.sub("", chunk.replace("\x1b[2J\x1b[H", ""))
        log_lines = []
        for line in clean.splitlines():
            self.parse_summary_line(line)
            self.parse_log_line(line)
            if line.startswith("[live]"):
                self.parse_live_line(line)
                continue
            if not line.startswith("[summary]"):
                log_lines.append(line)
        if log_lines:
            self.append_log("\n".join(log_lines), add_newline=True)

    def parse_summary_line(self, line: str) -> None:
        if not line.startswith("[summary]"):
            return
        text = line.replace("[summary]", "", 1).strip()
        if not text or text.startswith("---"):
            return
        if text.startswith("pid "):
            self.summary_pids.clear()
            return
        if text == "no active processes":
            self.summary_pids.clear()
            self.clear_table()
            return
        if text.startswith("total active instances:"):
            self.process_count_var.set(text.replace("total active instances:", "", 1).strip())
            self.reconcile_summary_rows()
            return
        if text.startswith("total bandwidth used:"):
            self.total_bandwidth_var.set(text.replace("total bandwidth used:", "", 1).strip())
            return
        parts = text.split()
        if len(parts) < 8 or not parts[0].isdigit():
            return

        pid = parts[0]
        values = (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7])
        self.summary_pids.add(pid)
        self.rows[pid] = values
        self.render_row(pid, values)
        self.update_process_count()

    def parse_live_line(self, line: str) -> None:
        text = line.replace("[live]", "", 1).strip()
        values: dict[str, str] = {}
        for part in text.split():
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            values[key] = value

        pid = values.get("pid", "")
        if not pid.isdigit():
            return

        row = (
            pid,
            values.get("status", "connected"),
            values.get("proxy", "-"),
            values.get("runtime", "-"),
            values.get("down", "0B"),
            values.get("up", "0B"),
            values.get("used", "0.00MB"),
            values.get("latency", "-"),
        )
        self.rows[pid] = row
        self.render_row(pid, row)
        self.update_process_count()

    def parse_log_line(self, line: str) -> None:
        if "[warn] closed " not in line:
            return
        marker = " pid="
        if marker not in line:
            return
        pid = line.rsplit(marker, 1)[1].split(maxsplit=1)[0]
        if not pid.isdigit():
            return
        self.rows.pop(pid, None)
        if self.table.exists(pid):
            self.table.delete(pid)
        self.update_process_count()

    def reconcile_summary_rows(self) -> None:
        if not self.summary_pids:
            return
        stale_pids = [pid for pid in self.rows if pid not in self.summary_pids]
        for pid in stale_pids:
            self.rows.pop(pid, None)
            if self.table.exists(pid):
                self.table.delete(pid)
        self.update_process_count()
        self.summary_pids.clear()

    def render_table(self) -> None:
        for pid, values in self.rows.items():
            self.render_row(pid, values)

    def render_row(self, pid: str, values: tuple[str, str, str, str, str, str, str, str]) -> None:
        display_values = values
        if self.hide_proxy_var.get():
            display_values = (
                values[0],
                values[1],
                "hidden" if values[2] not in ("-", "direct") else values[2],
                values[3],
                values[4],
                values[5],
                values[6],
                values[7],
            )
        if self.table.exists(pid):
            self.table.item(pid, values=display_values, tags=(values[1],))
        else:
            self.table.insert("", "end", iid=pid, values=display_values, tags=(values[1],))

    def append_log(self, text: str, add_newline: bool = True) -> None:
        self.log_view.configure(state="normal")
        lines = text.splitlines()
        if not lines:
            lines = [text]
        for index, line in enumerate(lines):
            if index:
                self.log_view.insert("end", "\n")
            self.log_view.insert("end", line, self.log_tag_for_line(line))
        if add_newline:
            self.log_view.insert("end", "\n")
        self.log_view.see("end")
        self.log_view.configure(state="disabled")

    def log_tag_for_line(self, line: str) -> str:
        if line.startswith("[error]") or " FAILED " in line:
            return "error"
        if line.startswith("[warn]"):
            return "warn"
        if line.startswith("[proxy-check] OK"):
            return "ok"
        if line.startswith("[route]"):
            return "route"
        if line.startswith("[redirect]") or line.startswith("[redirect-ready]"):
            return "redirect"
        if line.startswith("[track]"):
            return "track"
        if line.startswith("[game]"):
            return "game"
        if line.startswith("[status]"):
            return "status"
        if line.startswith("[conn]"):
            return "conn"
        if line.startswith("[ui]") or line.startswith("[ready]"):
            return "ui"
        return ""

    def clear_table(self) -> None:
        self.rows.clear()
        for item in self.table.get_children():
            self.table.delete(item)
        self.update_process_count()

    def on_close(self) -> None:
        self.stop()
        self.root.destroy()


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_TITLE)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--config", default=str(config_path()))
    args = parser.parse_args()

    if args.worker:
        worker_main(args.config)
        return

    root = tk.Tk()
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    PixelProxyUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
