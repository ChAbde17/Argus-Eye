import asyncio
import argparse
import sys
import time
from scanner.models import ScanReport, Host
from scanner.network import parse_ports, scan_ports_concurrently
from scanner.recon import discover_hosts
from scanner.web_audit import audit_web_target
from scanner.utils import sanitize_target, is_valid_target
from scanner.reporter import (
    console,
    print_banner,
    display_results_tables,
    display_summary_card,
    export_to_json,
    export_to_html
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Argus-Eye - High-Performance Recon & Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        type=str,
        help="Target domain or IP address (e.g. example.com)"
    )
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default="80,443,21,22,8080,8443",
        help="Ports to scan (e.g. '80,443' or '1-1024'). Default: 80,443,21,22,8080,8443"
    )
    parser.add_argument(
        "-w", "--wordlist",
        type=str,
        default="wordlists/subdomains.txt",
        help="Path to subdomain wordlist file. Default: wordlists/subdomains.txt"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="json",
        choices=["json", "html", "both"],
        help="Output format: json, html, or both. Default: json"
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=250,
        help="Max concurrent network workers. Default: 250"
    )

    return parser.parse_args()


async def run_scanner():
    print_banner()
    args = parse_arguments()

    # 1. Target Sanitization & Validation
    target = sanitize_target(args.target)
    if not is_valid_target(target):
        console.print(f"[bold red][!] Error:[/bold red] '{args.target}' is not a valid domain or IPv4 address.")
        sys.exit(1)

    start_time = time.perf_counter()
    target_ports = parse_ports(args.ports)
    report = ScanReport(target=target)

    console.print(f"[bold cyan][*][/bold cyan] Target locked: [bold white]{target}[/bold white]")
    console.print(f"[bold cyan][*][/bold cyan] Port count: [bold white]{len(target_ports)}[/bold white] | Concurrency: [bold white]{args.concurrency}[/bold white]\n")

    # 2. Host & Subdomain Discovery
    with console.status("[bold green]Discovering active hosts and subdomains...", spinner="dots"):
        hosts = await discover_hosts(
            domain=target,
            wordlist_path=args.wordlist,
            concurrency_limit=args.concurrency
        )
        report.hosts = hosts
        report.subdomains = [h.hostname for h in hosts if h.hostname]

    console.print(f"[bold green][+][/bold green] Recon complete: Discovered [bold green]{len(report.hosts)}[/bold green] active host(s).")

    # 3. Concurrent Multi-Host Port Sweeps
    with console.status("[bold green]Scanning TCP ports and extracting banners across all hosts...", spinner="dots"):
        async def _scan_host(host: Host):
            host.open_ports = await scan_ports_concurrently(
                host=host.ip,
                ports=target_ports,
                concurrency_limit=args.concurrency,
                timeout=0.6
            )

        await asyncio.gather(*[_scan_host(h) for h in report.hosts])

    # 4. Asynchronous Web Auditing
    with console.status("[bold green]Auditing HTTP security headers and sensitive paths...", spinner="dots"):
        async def _audit_host(host: Host):
            web_ports = [p.port for p in host.open_ports if p.port in [80, 443, 8080, 8443]]
            target_domain = host.hostname or host.ip
            if web_ports or 80 in target_ports or 443 in target_ports:
                finding = await audit_web_target(target_domain)
                if finding:
                    host.web_findings.append(finding)

        await asyncio.gather(*[_audit_host(h) for h in report.hosts])

    # 5. UI Render & Exports
    display_results_tables(report)

    console.print("\n[bold cyan][*] Generating reports...[/bold cyan]")
    if args.output in ["json", "both"]:
        json_file = export_to_json(report, "results.json")
        console.print(f"  [bold green]✔[/bold green] JSON report saved to: [bold white]{json_file}[/bold white]")

    if args.output in ["html", "both"]:
        html_file = export_to_html(report, "results.html")
        console.print(f"  [bold green]✔[/bold green] HTML report saved to: [bold white]{html_file}[/bold white]")

    elapsed = time.perf_counter() - start_time
    display_summary_card(report, elapsed)


def main():
    try:
        asyncio.run(run_scanner())
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan aborted by user.[/bold red]")
        sys.exit(0)


if __name__ == "__main__":
    main()
