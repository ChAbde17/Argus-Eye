from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from scanner.models import ScanReport

console = Console()


def print_banner():
    """Prints the custom Argus-Eye CLI ASCII banner."""
    raw_banner = r"""
 █████   ██████   ██████  ██   ██  ██████        ███████ ██   ██ ███████
██   ██  ██   ██ ██       ██   ██ ██             ██       ██ ██  ██     
███████  ██████  ██  ████ ██   ██  █████  ██████ █████     ███   █████  
██   ██  ██   ██ ██    ██ ██   ██      ██        ██        ███   ██     
██   ██  ██   ██  ██████   █████  ██████         ███████   ███   ███████
"""
    banner_text = Text(raw_banner, style="bold cyan", no_wrap=True)
    banner_text.append("\n  [+] Asynchronous Vulnerability & Attack Surface Recon Scanner", style="italic white")

    console.print(Panel(banner_text, border_style="bold blue", expand=False))


def display_results_tables(report: ScanReport):
    """Renders scan findings into formatted Rich tables."""
    console.print("\n")

    # 1. Discovered Hosts & Open Ports Table
    host_table = Table(
        title="[bold green]Network Discovery & Port Scan Results[/bold green]",
        header_style="bold magenta",
        show_lines=True
    )
    host_table.add_column("Hostname / Subdomain", style="cyan", no_wrap=True)
    host_table.add_column("IP Address", style="bright_blue")
    host_table.add_column("Port", style="yellow", justify="center")
    host_table.add_column("Service", style="green")
    host_table.add_column("Service Banner", style="white")

    has_port_results = False
    for host in report.hosts:
        if host.open_ports:
            for p in host.open_ports:
                has_port_results = True
                banner_preview = (p.banner[:45] + "...") if p.banner and len(p.banner) > 45 else (p.banner or "-")
                host_table.add_row(
                    host.hostname or host.ip,
                    host.ip,
                    str(p.port),
                    p.service,
                    banner_preview
                )
        else:
            host_table.add_row(
                host.hostname or host.ip,
                host.ip,
                "[dim]None[/dim]",
                "[dim]-[/dim]",
                "[dim]-[/dim]"
            )

    if report.hosts:
        console.print(host_table)

    # 2. Web Security & Misconfiguration Table
    web_table = Table(
        title="\n[bold red]Web Security & Vulnerability Audit Results[/bold red]",
        header_style="bold red",
        show_lines=True
    )
    web_table.add_column("Target URL", style="cyan")
    web_table.add_column("Missing Security Headers", style="yellow")
    web_table.add_column("Exposed Files / Paths", style="bold red")
    web_table.add_column("Detected Technologies", style="blue")

    has_web_findings = False
    for host in report.hosts:
        for finding in host.web_findings:
            has_web_findings = True
            missing_hdrs_str = "\n".join([f"• {h}" for h in finding.missing_headers]) if finding.missing_headers else "[green]None (All Present)[/green]"
            exposed_str = "\n".join([f"⚠ {p}" for p in finding.exposed_paths]) if finding.exposed_paths else "[dim]None Detected[/dim]"
            techs_str = "\n".join(finding.technologies) if finding.technologies else "[dim]Unknown[/dim]"

            web_table.add_row(
                finding.url,
                missing_hdrs_str,
                exposed_str,
                techs_str
            )

    if has_web_findings:
        console.print(web_table)
    else:
        console.print("[dim]No HTTP/HTTPS web services audited.[/dim]")
