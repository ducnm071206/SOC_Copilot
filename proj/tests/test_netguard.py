import socket
import pytest
from soc_copilot.netguard import EgressGuard, is_local_host


def test_is_local():
    assert is_local_host("127.0.0.1") and is_local_host("localhost") and is_local_host("::1")
    assert not is_local_host("8.8.8.8") and not is_local_host("huggingface.co")


def test_blocks_external_allows_loopback():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    with EgressGuard() as g:
        socket.create_connection(("127.0.0.1", port)).close()
        with pytest.raises(OSError):
            socket.create_connection(("8.8.8.8", 53), timeout=1)
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("example.com", 443)
    srv.close()
    assert g.hosts() == ["8.8.8.8", "example.com"]
