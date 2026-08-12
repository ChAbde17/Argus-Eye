import argparse
import sys
from scanner.models import ScanReport


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments for the Recon CLI tool."""
    parser = argparse.ArgumentParser(
        description="Argus Eye - High-Performance Vulnerability & Recon CLI",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Required target argument
    parser.add_argument(
        "-t", "--target",
        required=True,
        type=str,
        help="Target domain or IP address (e.g., example.com or 192.168.1.1)"
    )

    # Optional scan configuration flags
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default="80,443,21,22,8080,8443",
        help="Ports to scan (e.g., '80', '80,443', '1-1024'). Default: 80,443,21,22,8080,8443"
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
        default=100,
        help="Max concurrent async network workers. Default: 100"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    # Initialize the master report model
    report = ScanReport(target=args.target)

    # Display test configuration confirmation
    print(f"[+] Target configured: {args.target}")
    print(f"[+] Ports set: {args.ports}")
    print(f"[+] Wordlist set: {args.wordlist}")
    print(f"[+] Output format: {args.output}")
    print(f"[+] Concurrency limit: {args.concurrency}")
    print(f"[+] Scan initialized at: {report.scan_date}")


if __name__ == "__main__":
    main()
