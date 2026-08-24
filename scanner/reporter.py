import json
import os
from scanner.models import ScanReport
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from scanner.models import ScanReport

console = Console()


def print_banner():
    """Prints the compact Argus-Eye CLI ASCII banner."""
    raw_banner = r"""
   ___                         ______          
  /   |  _________ ___  _______/ ____/_  _____ 
 / /| | / ___/ __ `/ / / / ___/ __/ / / / / _ \
/ ___ |/ /  / /_/ / /_/ (__  ) /___/ /_/ /  __/
/_/  |_/_/   \__, /\__,_/____/_____/\__, /\___/ 
            /____/                 /____/      """

    banner_text = Text(raw_banner, style="bold cyan")
    banner_text.append("\n\n  ⚡ Async Recon & Attack Surface Scanner", style="bold white")
    banner_text.append("\n  🛠  Made by CH ABDE", style="italic magenta")

    console.print(Panel(banner_text, border_style="bold blue", expand=False))


def display_results_tables(report: ScanReport):
    """Renders condensed scan findings to the terminal."""
    console.print("\n")

    # 1. Discovered Hosts & Open Ports Table (Filter for hosts with open ports)
    active_hosts_with_ports = [h for h in report.hosts if h.open_ports]

    if active_hosts_with_ports:
        host_table = Table(
            title="[bold green]Open Ports & Identified Services[/bold green]",
            header_style="bold magenta",
            show_lines=True
        )
        host_table.add_column("Hostname / Subdomain", style="cyan")
        host_table.add_column("IP Address", style="bright_blue")
        host_table.add_column("Port", style="yellow", justify="center")
        host_table.add_column("Service", style="green")
        host_table.add_column("Service Banner", style="white")

        for host in active_hosts_with_ports:
            for p in host.open_ports:
                banner_preview = (p.banner[:45] + "...") if p.banner and len(p.banner) > 45 else (p.banner or "-")
                host_table.add_row(
                    host.hostname or host.ip,
                    host.ip,
                    str(p.port),
                    p.service,
                    banner_preview
                )
        console.print(host_table)
    else:
        console.print(f"[yellow][!] Scanned {len(report.hosts)} host(s), but no open ports were discovered.[/yellow]")

    # 2. Web Security Table
    has_web_findings = any(len(h.web_findings) > 0 for h in report.hosts)
    if has_web_findings:
        web_table = Table(
            title="\n[bold red]Web Security & Vulnerability Audit Results[/bold red]",
            header_style="bold red",
            show_lines=True
        )
        web_table.add_column("Target URL", style="cyan")
        web_table.add_column("Missing Security Headers", style="yellow")
        web_table.add_column("Exposed Files / Paths", style="bold red")
        web_table.add_column("Detected Technologies", style="blue")

        for host in report.hosts:
            for finding in host.web_findings:
                missing_hdrs_str = "\n".join([f"• {h}" for h in finding.missing_headers]) if finding.missing_headers else "[green]None[/green]"
                exposed_str = "\n".join([f"⚠ {p}" for p in finding.exposed_paths]) if finding.exposed_paths else "[dim]None[/dim]"
                techs_str = "\n".join(finding.technologies) if finding.technologies else "[dim]Unknown[/dim]"

                web_table.add_row(
                    finding.url,
                    missing_hdrs_str,
                    exposed_str,
                    techs_str
                )
        console.print(web_table)

def export_to_json(report: ScanReport, filepath: str = "results.json") -> str:
    """Exports scan results to a formatted JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)
    return filepath


def export_to_html(report: ScanReport, filepath: str = "results.html") -> str:
    """Generates a standalone dark-themed HTML report."""
    total_ports = sum(len(h.open_ports) for h in report.hosts)
    total_web = sum(len(h.web_findings) for h in report.hosts)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Argus-Eye Scan Report - {report.target}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-cyan: #38bdf8;
            --accent-green: #4ade80;
            --accent-red: #f87171;
            --accent-yellow: #facc15;
            --border: #334155;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background-color: var(--bg); color: var(--text-main); padding: 2rem; line-height: 1.5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        .header h1 {{ font-size: 2rem; color: var(--accent-cyan); margin-bottom: 0.5rem; }}
        .header p {{ color: var(--text-muted); font-size: 0.95rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }}
        .stat-card .value {{ font-size: 1.75rem; font-weight: bold; color: var(--accent-cyan); }}
        .stat-card .label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.25rem; }}
        .section-title {{ font-size: 1.25rem; margin: 2rem 0 1rem 0; color: var(--text-main); display: flex; align-items: center; gap: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); margin-bottom: 2rem; }}
        th, td {{ padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
        th {{ background: #111827; color: var(--accent-cyan); font-weight: 600; text-transform: uppercase; font-size: 0.8rem; letter-spacing: 0.05em; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover {{ background: #243248; }}
        .badge {{ display: inline-block; padding: 0.2rem 0.55rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
        .badge-open {{ background: rgba(74, 222, 128, 0.15); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .badge-missing {{ background: rgba(250, 204, 21, 0.15); color: var(--accent-yellow); margin-bottom: 0.25rem; display: block; width: fit-content; }}
        .badge-exposed {{ background: rgba(248, 113, 113, 0.15); color: var(--accent-red); margin-bottom: 0.25rem; display: block; width: fit-content; }}
        .code {{ font-family: monospace; font-size: 0.85rem; color: #e2e8f0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Argus-Eye Recon & Vulnerability Report</h1>
            <p>Target: <strong>{report.target}</strong> | Scan Executed: {report.scan_date}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{len(report.hosts)}</div>
                <div class="label">Discovered Hosts</div>
            </div>
            <div class="stat-card">
                <div class="value">{len(report.subdomains)}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="value">{total_ports}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="value">{total_web}</div>
                <div class="label">Web Findings</div>
            </div>
        </div>

        <h2 class="section-title">Network & Port Scan Surface</h2>
        <table>
            <thead>
                <tr>
                    <th>Host / Subdomain</th>
                    <th>IP Address</th>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
            </thead>
            <tbody>
    """

    for host in report.hosts:
        if host.open_ports:
            for p in host.open_ports:
                banner_str = p.banner or "-"
                html_content += f"""
                <tr>
                    <td class="code">{host.hostname or host.ip}</td>
                    <td class="code">{host.ip}</td>
                    <td><strong>{p.port}</strong></td>
                    <td><span class="badge badge-open">{p.state}</span></td>
                    <td>{p.service}</td>
                    <td class="code">{banner_str}</td>
                </tr>"""
        else:
            html_content += f"""
            <tr>
                <td class="code">{host.hostname or host.ip}</td>
                <td class="code">{host.ip}</td>
                <td colspan="4" style="color: var(--text-muted); font-style: italic;">No open ports identified</td>
            </tr>"""

    html_content += """
            </tbody>
        </table>

        <h2 class="section-title">Web Security & Exposure Audits</h2>
        <table>
            <thead>
                <tr>
                    <th>Target URL</th>
                    <th>Missing Security Headers</th>
                    <th>Exposed Sensitive Paths</th>
                    <th>Detected Technologies</th>
                </tr>
            </thead>
            <tbody>
    """

    has_web = False
    for host in report.hosts:
        for finding in host.web_findings:
            has_web = True
            missing_html = "".join([f'<span class="badge badge-missing">{h}</span>' for h in finding.missing_headers]) or '<span style="color: var(--accent-green);">All Present</span>'
            exposed_html = "".join([f'<span class="badge badge-exposed">⚠ {path}</span>' for path in finding.exposed_paths]) or '<span style="color: var(--text-muted);">None</span>'
            techs_html = "<br>".join(finding.technologies) or '<span style="color: var(--text-muted);">None</span>'

            html_content += f"""
            <tr>
                <td class="code"><a href="{finding.url}" target="_blank" style="color: var(--accent-cyan);">{finding.url}</a></td>
                <td>{missing_html}</td>
                <td>{exposed_html}</td>
                <td class="code">{techs_html}</td>
            </tr>"""

    if not has_web:
        html_content += """<tr><td colspan="4" style="color: var(--text-muted); text-align: center;">No web findings recorded.</td></tr>"""

    html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    return filepath
