# PID Proxy MVP

This is the first layer of a Proxifier-like tool that can route traffic by process ID.

Current MVP:

- Runs a local SOCKS5 proxy on `127.0.0.1:15000`
- Detects the Windows PID that opened the local TCP connection
- Selects an upstream route from `config.json`
- Supports direct connections and SOCKS5 upstream proxies
- Includes a process scanner/route assigner

Important limitation:

This MVP does not yet force non-proxy-aware apps through the proxy. A game that does not support proxy settings still needs a native redirect backend such as WinDivert or Windows Filtering Platform. That backend should capture selected PID traffic to remote TCP port `10001` and redirect it into this local proxy.

## Install

```powershell
python -m pip install -r requirements.txt
```

## Run Proxy

```powershell
python proxy_server.py
```

The default local proxy is:

```text
127.0.0.1:15000
```

The target game/server port is configured as:

```text
10001
```

## List Game PIDs

```powershell
python pid_manager.py game.exe
```

## Assign Routes By PID

First add your upstream proxies to `config.json`, then run:

```powershell
python pid_manager.py game.exe --assign
```

Simple upstream config:

```json
"max_pids_per_proxy": 1,
"auto_assign_routes": true,
"verbose": false,
"color_logs": true,
"upstreams": [
  "socks5://1.2.3.4:1080:user:pass",
  "http://5.6.7.8:8080:user:pass",
  "9.10.11.12:1080:user:pass"
]
```

These are auto-named as `proxy-1`, `proxy-2`, `proxy-3`.

For proxies without login, use `socks5://host:port`, `http://host:port`, or plain `host:port`.

Plain `host:port:user:pass` means SOCKS5. Use `http://host:port:user:pass` for HTTP proxies.

`max_pids_per_proxy` controls how many game instances are assigned to each proxy:

```text
1 = PID 1 -> proxy-1, PID 2 -> proxy-2, PID 3 -> proxy-3
2 = PID 1 -> proxy-1, PID 2 -> proxy-1, PID 3 -> proxy-2
```

You can also update the default limit for every proxy:

```powershell
python pid_manager.py --set-limits --max-pids-per-proxy 2
```

For different limits per proxy, set `proxy_pid_limits` in `config.json`:

```json
"max_pids_per_proxy": 1,
"proxy_pid_limits": {
  "proxy-1": 2,
  "proxy-2": 4
}
```

Or write those limits from the CLI:

```powershell
python pid_manager.py --set-limits --proxy-limit proxy-1=2 --proxy-limit proxy-2=4
```

When using object-style upstreams, you can also put the limit directly on that proxy:

```json
{
  "name": "proxy-1",
  "type": "socks5",
  "host": "1.2.3.4",
  "port": 1080,
  "pid_limit": 2
}
```

You can override limits while assigning:

```powershell
python pid_manager.py game.exe --assign --max-pids-per-proxy 2 --proxy-limit proxy-1=3
```

When `auto_assign_routes` is `true`, `proxy_server.py` assigns detected game PIDs in memory. It does not write temporary PIDs into `config.json`.

With `verbose` set to `false`, the console prints compact status lines like:

```text
[status] pid=25768 -> bypassed via growtechcentral.com:10000 -> connected (63.176.210.142:10001)
```

Stability settings:

```json
"tcp_nodelay": true,
"socket_keepalive": true,
"socket_buffer_size": 131072,
"relay_buffer_size": 131072,
"connect_timeout_seconds": 10,
"summary_interval_seconds": 10
```

`tcp_nodelay` reduces TCP buffering delay. Larger socket/relay buffers help under bursty traffic. Keepalive helps Windows detect dead tunnels more cleanly.

To clear manually saved routes:

```powershell
python pid_manager.py PixelWorlds.exe --clear-routes
```

## Test

```powershell
python tools\run_demo.py
```

Or manually:

```powershell
python proxy_server.py
python tools\test_client.py --dest-host example.com --dest-port 80
```

## Next Backend Step

For real Proxifier-style behavior:

```text
game.exe PID 4100 -> proxy-1 -> game server :10001
game.exe PID 4224 -> proxy-2 -> game server :10001
game.exe PID 4392 -> proxy-3 -> game server :10001
```

Add a native redirect backend that:

- runs as Administrator
- filters selected PIDs only
- filters TCP destination port `10001`
- redirects matching connections to `127.0.0.1:15000`
- preserves or reports the original destination to the proxy layer

## Experimental Redirect Backend

## Build EXE

On your build machine:

```powershell
.\build_app.ps1
```

Output:

```text
dist\PixelProxyInjector\PixelProxyInjector.exe
```

Copy the whole `dist\PixelProxyInjector` folder to the target device/RDP. Keep `config.json` beside the exe so you can edit proxies without rebuilding.

Run `PixelProxyInjector.exe` as Administrator.

One-command mode, from Administrator PowerShell:

```powershell
python run_all.py
```

Manual mode:

Run the proxy server first:

```powershell
python proxy_server.py
```

Then open a second Administrator PowerShell and run:

```powershell
python redirect_backend.py --redirect-unknown-pid
```

This uses WinDivert through `pydivert`, so it needs Administrator rights. The backend redirects TCP connections to the configured game port into the transparent proxy port:

```text
PixelWorlds.exe -> game server :10001
redirect_backend.py -> transparent port 15001
proxy_server.py -> assigned upstream proxy
```
