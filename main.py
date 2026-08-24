import asyncio
import argparse
import sys
from scanner.models import ScanReport, Host
from scanner.network import parse_ports, scan_ports_concurrently
from scanner.recon import discover_hosts
from scanner.web_audit import audit_web_target
from scanner.reporter import console, print_banner, display_results_tables
from scanner.reporter import (
    console,
    print_banner,
    display_results_tables,
    export_to_json,
    export_to_html
)

def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments."""
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
        default=50,
        help="Max concurrent network workers. Default: 50"
    )

    return parser.parse_args()


async def run_scanner():
    # Print banner before parsing arguments so it appears in --help output
    print_banner()
    args = parse_arguments()

    target_ports = parse_ports(args.ports)
    report = ScanReport(target=args.target)

    console.print(f"[bold cyan][*][/bold cyan] Initiating target recon on: [bold white]{args.target}[/bold white]")
    console.print(f"[bold cyan][*][/bold cyan] Scanning {len(target_ports)} target port(s) with concurrency limit {args.concurrency}\n")

    # Step 1: Subdomain Reconnaissance & DNS Resolution
    with console.status("[bold green]Discovering active hosts and subdomains...", spinner="dots"):
        hosts = await discover_hosts(
            domain=args.target,
            wordlist_path=args.wordlist,
            concurrency_limit=args.concurrency
        )
        report.hosts = hosts
        report.subdomains = [h.hostname for h in hosts if h.hostname]

    console.print(f"[bold green][+][/bold green] Recon complete: Found [bold green]{len(report.hosts)}[/bold green] active host(s).")

    # Step 2: Port Scanning & Banner Grabbing
    with console.status("[bold green]Scanning TCP ports and extracting banners...", spinner="dots"):
        for host in report.hosts:
            open_ports = await scan_ports_concurrently(
                host=host.ip,
                ports=target_ports,
                concurrency_limit=args.concurrency
            )
            host.open_ports = open_ports

    # Step 3: Web Security Auditing
    with console.status("[bold green]Auditing HTTP security headers and sensitive paths...", spinner="dots"):
        for host in report.hosts:
            web_ports = [p.port for p in host.open_ports if p.port in [80, 443, 8080, 8443]]
            target_domain = host.hostname or host.ip

            if web_ports or 80 in target_ports or 443 in target_ports:
                finding = await audit_web_target(target_domain)
                if finding:
                    host.web_findings.append(finding)

    # Step 4: Render UI Tables
    display_results_tables(report)

    # Step 5: Export Reports
    console.print("\n[bold cyan][*] Generating reports...[/bold cyan]")
    if args.output in ["json", "both"]:
        json_file = export_to_json(report, "results.json")
        console.print(f"  [bold green]✔[/bold green] JSON report saved to: [bold white]{json_file}[/bold white]")

    if args.output in ["html", "both"]:
        html_file = export_to_html(report, "results.html")
        console.print(f"  [bold green]✔[/bold green] HTML report saved to: [bold white]{html_file}[/bold white]")


def main():
    try:
        asyncio.run(run_scanner())
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan aborted by user.[/bold red]")
        sys.exit(0)


if __name__ == "__main__":
    main()
