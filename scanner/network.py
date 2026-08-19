import asyncio
import socket
from typing import Optional
from scanner.models import PortResult

# Mapping of well-known ports to default service names
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
}


async def check_port(host: str, port: int, timeout: float = 1.5) -> Optional[PortResult]:
    """
    Asynchronously checks if a single TCP port is open on the target host.
    
    Returns:
        PortResult if the connection succeeds (port is open), otherwise None.
    """
    try:
        # Attempt TCP three-way handshake with a non-blocking timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )

        # Infer service name based on standard assignments
        service_name = COMMON_SERVICES.get(port)
        if not service_name:
            try:
                service_name = socket.getservbyport(port, "tcp")
            except OSError:
                service_name = "unknown"

        # Gracefully shut down the socket
        writer.close()
        await writer.wait_closed()

        return PortResult(
            port=port,
            state="open",
            service=service_name,
            banner=None
        )

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        # Port is closed, filtered, or host is unreachable
        return None
