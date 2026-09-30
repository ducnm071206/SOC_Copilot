"""B9: chặn và ghi lại mọi kết nối ra ngoài localhost trong tiến trình Python."""
import ipaddress
import socket

_LOCAL_NAMES = {"localhost", "localhost.localdomain", ""}


def is_local_host(host) -> bool:
    if isinstance(host, bytes):
        host = host.decode(errors="ignore")
    if host is None:
        return True
    try:
        ip = ipaddress.ip_address(str(host).strip("[]"))
        return ip.is_loopback or ip.is_unspecified
    except ValueError:
        return str(host).lower() in _LOCAL_NAMES


class EgressGuard:
    def __init__(self, block: bool = True):
        self.block = block
        self.attempts = []          # [(kind, host)]
        self._orig = {}

    def _record(self, kind, host):
        self.attempts.append((kind, str(host)))

    def hosts(self):
        return sorted({h for _, h in self.attempts})

    def __enter__(self):
        g = self
        orig_connect, orig_connect_ex = socket.socket.connect, socket.socket.connect_ex
        orig_gai = socket.getaddrinfo
        self._orig = {"connect": orig_connect, "connect_ex": orig_connect_ex, "gai": orig_gai}

        def host_of(address):
            return address[0] if isinstance(address, tuple) else None   # AF_UNIX => local

        def connect(sock, address):
            h = host_of(address)
            if h is not None and not is_local_host(h):
                g._record("connect", h)
                if g.block:
                    raise ConnectionRefusedError(f"egress blocked: {h}")
            return orig_connect(sock, address)

        def connect_ex(sock, address):
            h = host_of(address)
            if h is not None and not is_local_host(h):
                g._record("connect", h)
                if g.block:
                    return 111
            return orig_connect_ex(sock, address)

        def gai(host, *a, **k):
            if host is not None and not is_local_host(host):
                g._record("dns", host)
                if g.block:
                    raise socket.gaierror(f"egress blocked: {host}")
            return orig_gai(host, *a, **k)

        socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = connect, connect_ex, gai
        return self

    def __exit__(self, *exc):
        socket.socket.connect = self._orig["connect"]
        socket.socket.connect_ex = self._orig["connect_ex"]
        socket.getaddrinfo = self._orig["gai"]
        return False
