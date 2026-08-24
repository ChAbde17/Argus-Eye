import asyncio
import httpx
from typing import Optional, List, Dict, Set
from urllib.parse import urljoin
from scanner.models import WebFinding

# Recommended baseline security headers
SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Content-Security-Policy": "Restricts unauthorized script execution (CSP)",
    "X-Frame-Options": "Prevents framing and Clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (nosniff)",
    "Referrer-Policy": "Controls information sent in the Referer header",
    "Permissions-Policy": "Restricts browser feature access",
}

# High-risk paths paired with text signatures
SENSITIVE_TARGETS: Dict[str, List[str]] = {
    "/.git/HEAD": ["ref: refs/", "ref:"],
    "/.env": ["DB_", "APP_", "SECRET", "KEY", "TOKEN", "PASSWORD="],
    "/robots.txt": ["User-agent", "Disallow", "Allow"],
    "/sitemap.xml": ["<urlset", "<?xml", "<sitemapindex"],
    "/.dockerignore": ["node_modules", ".git", "Dockerfile"],
}

# Cookie signatures mapped to technology frameworks
COOKIE_SIGNATURES: Dict[str, str] = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (Servlet/Tomcat)",
    "csrftoken": "Django",
    "laravel_session": "Laravel (PHP)",
    "connect.sid": "Node.js (Express)",
    "ASP.NET_SessionId": "ASP.NET",
    "_rails_session": "Ruby on Rails",
}


def extract_technologies(response: httpx.Response) -> List[str]:
    """Inspects response headers and cookies to identify technologies."""
    techs: Set[str] = set()
    resp_headers = {k.lower(): v for k, v in response.headers.items()}

    # 1. Inspect Server header
    if "server" in resp_headers and resp_headers["server"].strip():
        techs.add(f"Server: {resp_headers['server'].strip()}")

    # 2. Inspect X-Powered-By header
    if "x-powered-by" in resp_headers and resp_headers["x-powered-by"].strip():
        techs.add(f"Framework: {resp_headers['x-powered-by'].strip()}")

    # 3. Inspect other informative headers
    if "x-aspnet-version" in resp_headers:
        techs.add(f"ASP.NET: {resp_headers['x-aspnet-version'].strip()}")
    if "x-generator" in resp_headers:
        techs.add(f"Generator: {resp_headers['x-generator'].strip()}")
    if "via" in resp_headers:
        techs.add(f"Proxy/CDN: {resp_headers['via'].strip()}")

    # 4. Inspect cookies for backend frameworks
    for cookie_name in response.cookies.keys():
        if cookie_name in COOKIE_SIGNATURES:
            techs.add(COOKIE_SIGNATURES[cookie_name])

    return sorted(list(techs))


async def _probe_single_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    signatures: List[str]
) -> Optional[str]:
    """Probes a specific sensitive path and validates content against signatures."""
    target_url = urljoin(base_url, path)
    try:
        response = await client.get(target_url)
        if response.status_code == 200 and response.text:
            content = response.text
            # Filter SPA false positives returning 200 for 404
            if path in ["/.git/HEAD", "/.env"] and "<html" in content.lower():
                return None
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
    """Concurrently probes base_url for exposed sensitive files."""
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
    Performs a full web audit: header check, sensitive file probe, and tech fingerprinting.
    Automatically handles HTTPS to HTTP fallbacks.
    """
    headers_to_send = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Argus-Eye/1.0"
    }

    candidates = []
    if url.startswith("http://") or url.startswith("https://"):
        candidates.append(url)
    else:
        candidates.append(f"https://{url}")
        candidates.append(f"http://{url}")

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
        headers=headers_to_send
    ) as client:
        
        response = None
        for target_url in candidates:
            try:
                response = await client.get(target_url)
                if response:
                    break
            except Exception:
                continue

        if response is None:
            return None

        final_url = str(response.url)

        # 1. Security header evaluation
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        missing_headers = [
            h for h in SECURITY_HEADERS if h.lower() not in resp_headers
        ]

        # 2. Technology fingerprinting
        technologies = extract_technologies(response)

        # 3. Sensitive file discovery
        exposed = await scan_exposed_paths(final_url, client)

        return WebFinding(
            url=final_url,
            missing_headers=missing_headers,
            exposed_paths=exposed,
            technologies=technologies
        )
