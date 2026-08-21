import httpx
from typing import Optional, List, Dict
from scanner.models import WebFinding

# Recommended baseline security headers
SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Content-Security-Policy": "Restricts unauthorized script and resource execution (CSP)",
    "X-Frame-Options": "Prevents framing and Clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (nosniff)",
    "Referrer-Policy": "Controls information sent in the Referer header",
    "Permissions-Policy": "Restricts browser feature access (camera, microphone, geolocation)",
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
