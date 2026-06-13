from __future__ import annotations

import socket
import struct
import time
from base64 import b64encode
from dataclasses import dataclass
from urllib.parse import urlsplit
from typing import Any


SOCKS5_REPLY_MESSAGES = {
    1: "general SOCKS server failure",
    2: "connection not allowed by ruleset",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused by destination",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}
PROXY_DNS_CACHE_TTL_SECONDS = 3600.0
PROXY_DNS_RETRY_COUNT = 3
PROXY_DNS_RETRY_DELAY_SECONDS = 0.25
PROXY_ADDRESS_CACHE: dict[tuple[str, int], tuple[float, list[tuple[Any, ...]]]] = {}


@dataclass(frozen=True)
class Upstream:
    name: str
    type: str
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    pid_limit: int | None = None

    @classmethod
    def from_config(
        cls,
        data: dict[str, Any] | str,
        index: int | None = None,
        default_type: str = "socks5",
    ) -> "Upstream":
        if isinstance(data, str):
            return cls.from_proxy_string(data, index, default_type)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Upstream":
        pid_limit = data.get("pid_limit")
        if pid_limit is None:
            pid_limit = data.get("max_pids")
        return cls(
            name=str(data["name"]),
            type=str(data.get("type", "direct")).lower(),
            host=data.get("host"),
            port=data.get("port"),
            username=data.get("username"),
            password=data.get("password"),
            pid_limit=pid_limit,
        )

    @classmethod
    def from_proxy_string(
        cls,
        value: str,
        index: int | None = None,
        default_type: str = "socks5",
    ) -> "Upstream":
        proxy_type = default_type.lower()
        if proxy_type not in ("socks5", "http"):
            raise ValueError("Default proxy protocol must be socks5 or http")
        proxy_value = value.strip()
        if "://" in proxy_value:
            scheme, remainder = proxy_value.split("://", 1)
            proxy_type = scheme.lower()
            if proxy_type not in ("socks5", "http"):
                raise ValueError("Proxy URL scheme must be socks5:// or http://")

            if "@" in remainder:
                parsed = urlsplit(proxy_value)
                host = parsed.hostname
                port = parsed.port
                username = parsed.username
                password = parsed.password
                if not host or not port:
                    raise ValueError("Proxy URL must include host and port")
                name = f"proxy-{index}" if index is not None else f"{proxy_type}://{host}:{port}"
                return cls(
                    name=name,
                    type=proxy_type,
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                )

            proxy_value = remainder

        parts = proxy_value.split(":")
        if len(parts) not in (2, 4):
            raise ValueError(
                "Proxy string must be host:port, host:port:user:pass, "
                "socks5://host:port:user:pass, or http://host:port:user:pass"
            )

        host, port_text = parts[0], parts[1]
        username = parts[2] if len(parts) == 4 else None
        password = parts[3] if len(parts) == 4 else None
        name = f"proxy-{index}" if index is not None else f"{host}:{port_text}"

        return cls(
            name=name,
            type=proxy_type,
            host=host,
            port=int(port_text),
            username=username,
            password=password,
        )


def connect_via_upstream(
    upstream: Upstream,
    destination_host: str,
    destination_port: int,
    timeout: float = 15.0,
    tcp_nodelay: bool = True,
    keepalive: bool = True,
    buffer_size: int = 131072,
) -> socket.socket:
    if upstream.type == "direct":
        sock = socket.create_connection((destination_host, destination_port), timeout=timeout)
        configure_socket(sock, tcp_nodelay, keepalive, buffer_size)
        return sock

    if upstream.type == "socks5":
        return _connect_socks5(upstream, destination_host, destination_port, timeout, tcp_nodelay, keepalive, buffer_size)

    if upstream.type == "http":
        return _connect_http(upstream, destination_host, destination_port, timeout, tcp_nodelay, keepalive, buffer_size)

    raise ValueError(f"Unsupported upstream type: {upstream.type}")


def _connect_socks5(
    upstream: Upstream,
    destination_host: str,
    destination_port: int,
    timeout: float,
    tcp_nodelay: bool,
    keepalive: bool,
    buffer_size: int,
) -> socket.socket:
    if not upstream.host or not upstream.port:
        raise ValueError(f"SOCKS5 upstream {upstream.name!r} requires host and port")

    sock = create_proxy_connection(upstream.host, upstream.port, timeout)
    configure_socket(sock, tcp_nodelay, keepalive, buffer_size)

    try:
        if upstream.username is not None and upstream.password is not None:
            sock.sendall(b"\x05\x01\x02")
            _expect(sock.recv(2), b"\x05\x02", "SOCKS5 username/password auth was rejected")
            username = upstream.username.encode("utf-8")
            password = upstream.password.encode("utf-8")
            if len(username) > 255 or len(password) > 255:
                raise ValueError("SOCKS5 username/password must be 255 bytes or less")
            sock.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
            _expect(sock.recv(2), b"\x01\x00", "SOCKS5 username/password auth failed")
        else:
            sock.sendall(b"\x05\x01\x00")
            _expect(sock.recv(2), b"\x05\x00", "SOCKS5 no-auth method was rejected")

        address_request = _socks5_address_request(destination_host)
        request = b"\x05\x01\x00" + address_request + struct.pack("!H", destination_port)
        sock.sendall(request)
        response = _recv_exact(sock, 4)
        if response[0] != 5 or response[1] != 0:
            reply_code = response[1]
            reply_message = SOCKS5_REPLY_MESSAGES.get(reply_code, "unknown reply")
            raise OSError(f"SOCKS5 connect failed: {reply_message} (reply code {reply_code})")

        atyp = response[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 3:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length)
        elif atyp == 4:
            _recv_exact(sock, 16)
        else:
            raise OSError(f"SOCKS5 returned unknown address type {atyp}")
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def _connect_http(
    upstream: Upstream,
    destination_host: str,
    destination_port: int,
    timeout: float,
    tcp_nodelay: bool,
    keepalive: bool,
    buffer_size: int,
) -> socket.socket:
    if not upstream.host or not upstream.port:
        raise ValueError(f"HTTP upstream {upstream.name!r} requires host and port")

    sock = create_proxy_connection(upstream.host, upstream.port, timeout)
    configure_socket(sock, tcp_nodelay, keepalive, buffer_size)
    try:
        destination = format_connect_destination(destination_host, destination_port)
        headers = [
            f"CONNECT {destination} HTTP/1.1",
            f"Host: {destination}",
            "Proxy-Connection: Keep-Alive",
        ]
        if upstream.username is not None and upstream.password is not None:
            token = f"{upstream.username}:{upstream.password}".encode("utf-8")
            encoded = b64encode(token).decode("ascii")
            headers.append(f"Proxy-Authorization: Basic {encoded}")

        request = "\r\n".join(headers) + "\r\n\r\n"
        sock.sendall(request.encode("ascii"))

        response = _recv_http_headers(sock)
        status_line = response.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise OSError(f"HTTP proxy returned invalid response: {status_line}")
        status_code = int(parts[1])
        if status_code < 200 or status_code >= 300:
            raise OSError(f"HTTP proxy CONNECT failed: {status_line}")
        return sock
    except Exception:
        sock.close()
        raise


def _recv_http_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("HTTP proxy closed before sending response headers")
        data.extend(chunk)
        if len(data) > 65536:
            raise OSError("HTTP proxy response headers are too large")
    return bytes(data)


def create_proxy_connection(host: str, port: int, timeout: float) -> socket.socket:
    last_error: OSError | None = None
    literal_host = proxy_literal_connect_host(host)
    if literal_host is not None:
        try:
            return socket.create_connection((literal_host, port), timeout=timeout)
        except OSError as exc:
            last_error = exc

    for attempt in range(PROXY_DNS_RETRY_COUNT):
        try:
            return create_connection_from_addrinfo(host, port, timeout, refresh=attempt > 0)
        except socket.gaierror as exc:
            last_error = exc
            if attempt + 1 < PROXY_DNS_RETRY_COUNT:
                time.sleep(PROXY_DNS_RETRY_DELAY_SECONDS)
        except OSError as exc:
            last_error = exc
            break

    try:
        return create_connection_from_cache(host, port, timeout)
    except OSError:
        if last_error is not None:
            raise OSError(f"proxy connect failed for {host}:{port}: {last_error}") from last_error
        raise


def create_connection_from_addrinfo(
    host: str,
    port: int,
    timeout: float,
    refresh: bool = False,
) -> socket.socket:
    addresses = resolve_proxy_addrinfo(host, port, refresh)
    last_error: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in addresses:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is not None:
        raise last_error
    raise OSError(f"proxy DNS returned no usable addresses for {host}:{port}")


def create_connection_from_cache(host: str, port: int, timeout: float) -> socket.socket:
    key = (host, port)
    cached = PROXY_ADDRESS_CACHE.get(key)
    if cached is None:
        raise OSError(f"no cached proxy address for {host}:{port}")
    _resolved_at, addresses = cached
    last_error: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in addresses:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is not None:
        raise last_error
    raise OSError(f"cached proxy address list is empty for {host}:{port}")


def resolve_proxy_addrinfo(host: str, port: int, refresh: bool = False) -> list[tuple[Any, ...]]:
    key = (host, port)
    now = time.time()
    cached = PROXY_ADDRESS_CACHE.get(key)
    if not refresh and cached is not None:
        resolved_at, addresses = cached
        if now - resolved_at <= PROXY_DNS_CACHE_TTL_SECONDS:
            return addresses

    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    PROXY_ADDRESS_CACHE[key] = (now, addresses)
    return addresses


def proxy_literal_connect_host(host: str) -> str | None:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass

    labels = host.split(".")
    if len(labels) >= 4 and all(label.isdigit() for label in labels[:4]):
        candidate = ".".join(labels[:4])
        try:
            socket.inet_pton(socket.AF_INET, candidate)
            return candidate
        except OSError:
            pass
    return None


def _socks5_address_request(destination_host: str) -> bytes:
    try:
        return b"\x01" + socket.inet_pton(socket.AF_INET, destination_host)
    except OSError:
        pass

    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, destination_host)
    except OSError:
        pass

    host_bytes = destination_host.encode("idna")
    if len(host_bytes) > 255:
        raise ValueError("Destination hostname is too long for SOCKS5")
    return b"\x03" + bytes([len(host_bytes)]) + host_bytes


def format_connect_destination(destination_host: str, destination_port: int) -> str:
    try:
        socket.inet_pton(socket.AF_INET6, destination_host)
        return f"[{destination_host}]:{destination_port}"
    except OSError:
        return f"{destination_host}:{destination_port}"


def configure_socket(
    sock: socket.socket,
    tcp_nodelay: bool = True,
    keepalive: bool = True,
    buffer_size: int = 131072,
) -> None:
    if tcp_nodelay:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if keepalive:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if buffer_size > 0:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)


def _expect(actual: bytes, expected: bytes, message: str) -> None:
    if actual != expected:
        raise OSError(message)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("Connection closed while reading from socket")
        chunks.extend(chunk)
    return bytes(chunks)
