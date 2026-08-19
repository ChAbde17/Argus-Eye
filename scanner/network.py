import asyncio
import socket
from typing import Optional
from scanner.models import PortResult
from typing import List

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

async def _bounded_check_port(sem: asyncio.Semaphore, host: str, port: int, timeout: float) -> Optional[PortResult]:
    """
    A wrapper around check_port that enforces concurrency limits.
    It waits for the semaphore to grant permission before executing.
    """
    async with sem:
        return await check_port(host, port, timeout)


async def scan_ports_concurrently(host: str, ports: List[int], concurrency_limit: int = 200, timeout: float = 1.5) -> List[PortResult]:
    """
    Scans a list of ports concurrently, bounded by a semaphore.
    
    Returns:
        A list of PortResult objects ONLY for ports that are open.
    """
    # Create the concurrency toll booth
    sem = asyncio.Semaphore(concurrency_limit)
    
    # Prepare all the tasks
    tasks = [
        _bounded_check_port(sem, host, port, timeout)
        for port in ports
    ]
    
    # Execute all tasks concurrently and wait for them to finish
    results = await asyncio.gather(*tasks)
    
    # Filter out None values (which represent closed/filtered ports)
    open_ports = [res for res in results if res is not None]
    
    return open_ports
