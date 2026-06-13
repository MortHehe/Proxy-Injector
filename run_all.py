from __future__ import annotations

import argparse
import ctypes
import os
import signal
import traceback
import threading
import time
from datetime import datetime
from pathlib import Path

from proxy_server import Config, serve
from redirect_backend import run as run_redirect_backend


CRASH_LOG = Path("crash.log")
RESTART_DELAY_SECONDS = 5.0
CTRL_C_EVENT = 0
CTRL_BREAK_EVENT = 1
CTRL_CLOSE_EVENT = 2
CTRL_LOGOFF_EVENT = 5
CTRL_SHUTDOWN_EVENT = 6


def main() -> None:
    install_shutdown_handlers()

    parser = argparse.ArgumentParser(description="Run proxy server and redirect backend together")
    parser.add_argument("--config", default="config.json")
    parser.add_argument(
        "--redirect-unknown-pid",
        action="store_true",
        default=True,
        help="Redirect target-port traffic even if PID is not visible yet",
    )
    parser.add_argument(
        "--no-redirect-unknown-pid",
        dest="redirect_unknown_pid",
        action="store_false",
        help="Only redirect traffic when PID is already assigned in config",
    )
    args = parser.parse_args()

    config_path = Path(args.config)

    proxy_thread = threading.Thread(
        target=supervise,
        args=("proxy", lambda: serve(Config.load(config_path))),
        daemon=True,
    )
    redirect_thread = threading.Thread(
        target=supervise,
        args=(
            "redirect",
            lambda: run_redirect_backend(Config.load(config_path), args.redirect_unknown_pid),
        ),
        daemon=True,
    )

    proxy_thread.start()
    time.sleep(0.5)
    redirect_thread.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[stop] shutting down")
        hard_exit(0)


def install_shutdown_handlers() -> None:
    signal.signal(signal.SIGINT, lambda _signum, _frame: hard_exit(0))
    signal.signal(signal.SIGTERM, lambda _signum, _frame: hard_exit(0))

    if os.name != "nt":
        return

    handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

    def console_handler(event: int) -> bool:
        if event in (
            CTRL_C_EVENT,
            CTRL_BREAK_EVENT,
            CTRL_CLOSE_EVENT,
            CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT,
        ):
            hard_exit(0)
            return True
        return False

    # Keep a reference so Windows can call the handler later.
    install_shutdown_handlers.console_handler = handler_type(console_handler)  # type: ignore[attr-defined]
    ctypes.windll.kernel32.SetConsoleCtrlHandler(
        install_shutdown_handlers.console_handler,  # type: ignore[attr-defined]
        True,
    )


def hard_exit(code: int) -> None:
    print("\n[stop] terminating proxy services")
    os._exit(code)


def supervise(name: str, target: object) -> None:
    while True:
        try:
            target()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            write_crash(name, f"stopped with SystemExit({code})", None)
            if code != 0:
                print(f"[error] {name} stopped. Fix the error and restart the app.")
            return
        except KeyboardInterrupt:
            return
        except Exception as exc:
            write_crash(name, str(exc), traceback.format_exc())
            print(f"[error] {name} crashed: {exc}")
            print(f"[warn] restarting {name} in {RESTART_DELAY_SECONDS:.0f}s")
            time.sleep(RESTART_DELAY_SECONDS)


def write_crash(name: str, message: str, stack: str | None) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with CRASH_LOG.open("a", encoding="utf-8") as file:
        file.write(f"[{timestamp}] {name}: {message}\n")
        if stack:
            file.write(stack)
        file.write("\n")


if __name__ == "__main__":
    main()
