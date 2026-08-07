from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict, Any

@dataclass
class PortResult:
    """Represents the state and metadata of a single scanned port."""
    port: int
    state: str = "open" # open, closed, filtered
    service: str = "unknown"
    banner: Optional[str] = None

@dataclass
class WebFinding:
    """Represents HTTP security header gaps and exposed paths found on an endpoint."""
    url: str
    missing_headers: List[str] = field(default_factory=list)
    exposed_paths: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)

@dataclass
class Host:
    """Represents a discovered host or subdomain and its associated scan results."""
    ip: str
    hostname: Optional[str] = None
    open_ports: List[PortResult] = field(default_factory=list)
    web_findings: List[WebFinding] = field(default_factory=list)

@dataclass
class ScanReport:
    """The master report containing all target results and execution metadata."""
    target: str
    scan_date: str = field(
        default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    subdomains: List[str] = field(default_factory=list)
    hosts: List[Host] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the entire object hierarchy to a python dictionary."""
        return asdict(self)