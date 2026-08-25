import asyncio
import socket
from typing import Optional, List
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
    
    
async def _grab_banner(host: str, port: int, timeout: float = 0.8) -> Optional[str]:
    """Dedicated banner grabber run ONLY on confirmed open ports."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = None
        try:
            # 1. Server-speaks-first protocols (SSH/FTP)
            data = await asyncio.wait_for(reader.read(512), timeout=0.4)
            if data:
                banner = data.decode("utf-8", errors="ignore").strip()
        except asyncio.TimeoutError:
            # 2. HTTP probe fallback
            try:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(512), timeout=0.4)
                if data:
                    raw_banner = data.decode("utf-8", errors="ignore").strip()
                    banner = raw_banner.split("\n")[0].strip() if raw_banner else None
            except Exception:
                pass

        writer.close()
        await writer.wait_closed()
        return banner
    except Exception:
        return None


async def check_port_fast(host: str, port: int, timeout: float = 0.6) -> Optional[int]:
    """Lightweight TCP handshake check with short timeout."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


async def _bounded_check_port(sem: asyncio.Semaphore, host: str, port: int, timeout: float) -> Optional[PortResult]:
    """
    A wrapper around check_port that enforces concurrency limits.
    It waits for the semaphore to grant permission before executing.
    """
    async with sem:
        return await check_port(host, port, timeout)


async def scan_ports_concurrently(
    host: str,
    ports: List[int],
    concurrency_limit: int = 250,
    timeout: float = 0.6
) -> List[PortResult]:
    """
    High-speed two-phase port scanner:
    Phase 1: Rapid async TCP sweep.
    Phase 2: Targeted banner extraction on open ports only.
    """
    sem = asyncio.Semaphore(concurrency_limit)

    async def _bounded_check(p: int):
        async with sem:
            return await check_port_fast(host, p, timeout)

    # Phase 1: Fast TCP sweep
    check_tasks = [_bounded_check(p) for p in ports]
    open_port_nums = [p for p in await asyncio.gather(*check_tasks) if p is not None]

    # Phase 2: Grab banners concurrently ONLY for open ports
    results: List[PortResult] = []
    for port in open_port_nums:
        service_name = COMMON_SERVICES.get(port)
        if not service_name:
            try:
                service_name = socket.getservbyport(port, "tcp")
            except OSError:
                service_name = "unknown"

        banner = await _grab_banner(host, port)
        results.append(
            PortResult(
                port=port,
                state="open",
                service=service_name,
                banner=banner
            )
        )

    return sorted(results, key=lambda r: r.port)
