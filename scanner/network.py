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


def parse_ports(port_str: str) -> List[int]:
    """
    Parses a string of ports into a deduplicated, sorted list of integers.
    Supports single ports ('80'), comma-separated ('80,443'), and ranges ('1-1024').
    """
    ports = set()
    
    # Split by comma first
    parts = port_str.split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
            
        # Check if it's a range (e.g., '1-100')
        if '-' in part:
            try:
                start_str, end_str = part.split('-')
                start = int(start_str)
                end = int(end_str)
                
                # Ensure valid port boundaries
                if start <= end and 1 <= start <= 65535 and 1 <= end <= 65535:
                    ports.update(range(start, end + 1))
            except ValueError:
                pass  # Ignore malformed ranges gracefully
        else:
            # Handle single ports
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                pass  # Ignore invalid strings gracefully
                
    return sorted(list(ports))
    
    
async def check_port(host: str, port: int, timeout: float = 1.5) -> Optional[PortResult]:
    """
    Asynchronously checks if a TCP port is open and attempts to grab the service banner.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )

        service_name = COMMON_SERVICES.get(port)
        if not service_name:
            try:
                service_name = socket.getservbyport(port, "tcp")
            except OSError:
                service_name = "unknown"

        banner = None
        try:
            # 1. Attempt to read a "server-speaks-first" banner (e.g., SSH, FTP, SMTP)
            # We use a shorter timeout here so it doesn't hang if the server is waiting for us
            data = await asyncio.wait_for(reader.read(1024), timeout=0.75)
            if data:
                banner = data.decode("utf-8", errors="ignore").strip()
        except asyncio.TimeoutError:
            # 2. If it times out, it might be a "client-speaks-first" protocol (e.g., HTTP)
            # Send a generic HTTP payload to provoke a response
            try:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                
                data = await asyncio.wait_for(reader.read(1024), timeout=0.75)
                if data:
                    # Clean up the HTTP response to just grab the first line (e.g., "HTTP/1.1 200 OK")
                    raw_banner = data.decode("utf-8", errors="ignore").strip()
                    banner = raw_banner.split("\n")[0].strip() if raw_banner else None
            except Exception:
                pass
        except Exception:
            pass

        writer.close()
        await writer.wait_closed()

        return PortResult(
            port=port,
            state="open",
            service=service_name,
            banner=banner
        )

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
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
