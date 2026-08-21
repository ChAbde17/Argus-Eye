import asyncio
import httpx
from typing import Optional, List, Dict
from scanner.models import WebFinding
from urllib.parse import urljoin

# Recommended baseline security headers
SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Content-Security-Policy": "Restricts unauthorized script and resource execution (CSP)",
    "X-Frame-Options": "Prevents framing and Clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (nosniff)",
    "Referrer-Policy": "Controls information sent in the Referer header",
    "Permissions-Policy": "Restricts browser feature access (camera, microphone, geolocation)",
}

# High-risk paths paired with text signatures to validate true positives
SENSITIVE_TARGETS: Dict[str, List[str]] = {
    "/.git/HEAD": ["ref: refs/", "ref:"],
    "/.env": ["DB_", "APP_", "SECRET", "KEY", "TOKEN", "PASSWORD="],
    "/robots.txt": ["User-agent", "Disallow", "Allow"],
    "/sitemap.xml": ["<urlset", "<?xml", "<sitemapindex"],
    "/.dockerignore": ["node_modules", ".git", "Dockerfile"],
}

async def audit_headers(url: str, client: Optional[httpx.AsyncClient] = None, timeout: float = 8.0) -> Optional[WebFinding]:
    """
    Sends an HTTP request to evaluate the presence of defensive security headers.
    
    Args:
        url: The web URL to audit (e.g., 'https://example.com').
        client: Optional shared httpx.AsyncClient instance.
        timeout: Request timeout in seconds.
        
    Returns:
        A WebFinding instance containing missing headers, or None if the host is unreachable.
    """
    # Ensure scheme is prepended
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    headers_to_send = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Argus-Eye/1.0"
    }

    own_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True)
        own_client = True

    try:
        response = await client.get(url, headers=headers_to_send)
        
        # Convert response headers to lowercase keys for case-insensitive lookup
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        
        missing = []
        for header_name in SECURITY_HEADERS:
            if header_name.lower() not in resp_headers:
                missing.append(header_name)

        return WebFinding(
            url=str(response.url),
            missing_headers=missing,
            exposed_paths=[],
            technologies=[]
        )

    except (httpx.RequestError, httpx.TimeoutException, Exception):
        return None

    finally:
        if own_client:
            await client.aclose()

async def _probe_single_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    signatures: List[str]
) -> Optional[str]:
    """
    Probes a specific sensitive path and validates content against signature markers.
    """
    target_url = urljoin(base_url, path)
    try:
        response = await client.get(target_url)
        
        # Verify status 200 OK and non-empty response
        if response.status_code == 200 and response.text:
            content = response.text
            
            # Prevent false positives: Ensure SPA/HTML templates returning 200 for 404s are ignored
            if path in ["/.git/HEAD", "/.env"] and "<html" in content.lower():
                return None
                
            # Verify body contains expected signature strings
            if any(sig in content for sig in signatures):
                return path

    except (httpx.RequestError, httpx.TimeoutException):
        pass

    return None


async def scan_exposed_paths(
    base_url: str,
    client: httpx.AsyncClient,
    concurrency_limit: int = 10
) -> List[str]:
    """
    Concurrently probes base_url for exposed sensitive and configuration files.
    """
    sem = asyncio.Semaphore(concurrency_limit)

    async def _bounded_probe(path: str, sigs: List[str]):
        async with sem:
            return await _probe_single_path(client, base_url, path, sigs)

    tasks = [
        _bounded_probe(path, sigs)
        for path, sigs in SENSITIVE_TARGETS.items()
    ]

    results = await asyncio.gather(*tasks)
    return [p for p in results if p is not None]


async def audit_web_target(
    url: str,
    timeout: float = 8.0
) -> Optional[WebFinding]:
    """
    Performs full web audit: header review and sensitive file discovery.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    headers_to_send = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Argus-Eye/1.0"
    }

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            headers=headers_to_send
        ) as client:
            
            # 1. Base response for security headers
            response = await client.get(url)
            final_url = str(response.url)
            
            resp_headers = {k.lower(): v for k, v in response.headers.items()}
            missing_headers = [
                h for h in SECURITY_HEADERS if h.lower() not in resp_headers
            ]

            # 2. Concurrently check sensitive paths
            exposed = await scan_exposed_paths(final_url, client)

            return WebFinding(
                url=final_url,
                missing_headers=missing_headers,
                exposed_paths=exposed,
                technologies=[]
            )

    except Exception:
        return None
