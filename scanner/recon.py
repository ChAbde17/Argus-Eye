import asyncio
import httpx
import os
import dns.asyncresolver
import dns.resolver
import dns.exception
from typing import Set, List, Optional


async def _query_alienvault(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Queries AlienVault OTX passive DNS database."""
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Argus-Eye/1.0"}

    try:
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subdomains.add(hostname)
    except Exception:
        pass
    return subdomains


async def _query_hackertarget(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Queries HackerTarget's passive hostsearch database."""
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Argus-Eye/1.0"}

    try:
        response = await client.get(url, headers=headers)
        if response.status_code == 200 and "error" not in response.text.lower():
            for line in response.text.splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains


async def _query_crt_sh(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Queries crt.sh Certificate Transparency logs."""
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Argus-Eye/1.0"}

    try:
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if sub.startswith("*."):
                        sub = sub[2:]
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains


async def get_passive_subdomains(domain: str, timeout: float = 12.0) -> List[str]:
    """
    Asynchronously queries multiple passive reconnaissance feeds in parallel.
    """
    subdomains: Set[str] = set()

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # Launch AlienVault, HackerTarget, and crt.sh concurrently
        results = await asyncio.gather(
            _query_alienvault(domain, client),
            _query_hackertarget(domain, client),
            _query_crt_sh(domain, client),
            return_exceptions=True
        )

        for res in results:
            if isinstance(res, set):
                subdomains.update(res)

    return sorted(list(subdomains))


async def _resolve_candidate(
    resolver: dns.asyncresolver.Resolver,
    sem: asyncio.Semaphore,
    fqdn: str
) -> Optional[str]:
    """
    Attempts to resolve an A record for a single fully qualified domain name (FQDN).
    """
    async with sem:
        try:
            # Query standard IPv4 address record
            answers = await resolver.resolve(fqdn, "A")
            if answers:
                return fqdn
        except (
            dns.resolver.NXDOMAIN,       # Domain does not exist
            dns.resolver.NoAnswer,       # Domain exists but no A record
            dns.resolver.LifetimeTimeout, # Query timed out
            dns.resolver.NoNameservers,
            dns.exception.DNSException
        ):
            return None
        except Exception:
            return None
    return None


async def brute_force_subdomains(
    domain: str,
    wordlist_path: str = "wordlists/subdomains.txt",
    concurrency_limit: int = 50,
    timeout: float = 2.0
) -> List[str]:
    """
    Asynchronously brute-forces subdomains for a target domain using a local wordlist.
    """
    if not os.path.exists(wordlist_path):
        return []

    # Read wordlist prefixes
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

    if not words:
        return []

    # Configure fast, reliable upstream nameservers (Cloudflare & Google)
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]
    resolver.lifetime = timeout
    resolver.timeout = timeout

    sem = asyncio.Semaphore(concurrency_limit)

    # Construct FQDN list and spawn async resolution tasks
    tasks = [
        _resolve_candidate(resolver, sem, f"{word}.{domain}")
        for word in words
    ]

    results = await asyncio.gather(*tasks)

    # Filter out unresolved domains
    active_subdomains = [fqdn for fqdn in results if fqdn is not None]
    return sorted(list(set(active_subdomains)))
