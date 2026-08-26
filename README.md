# 👁️ Argus-Eye: High-Performance Async Recon & Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Code-Style](https://img.shields.io/badge/Code%20Style-Black-000000.svg)](https://github.com/psf/black)

**Argus-Eye** is a modular, high-throughput asynchronous reconnaissance and attack surface audit tool built in Python. Designed for penetration testers, bug bounty hunters, and security engineers, it coordinates passive OSINT, active DNS enumeration, non-blocking TCP port scanning, and web security misconfiguration auditing into a single pipeline with dark-mode HTML and structured JSON reporting.

```text
   ___                         ______          
  /   |  _________ ___  _______/ ____/_  _____ 
 / /| | / ___/ __ `/ / / / ___/ __/ / / / / _ \
/ ___ |/ /  / /_/ / /_/ (__  ) /___/ /_/ /  __/
/_/  |_/_/   \__, /\__,_/____/_____/\__, /\___/ 
            /____/                 /____/      

 ⚡ Async Recon & Attack Surface Scanner
  🛠  Made by CH ABDE

```

---

## 🚀 Key Features

* **Multi-Source Passive OSINT:** Queries AlienVault OTX, HackerTarget, and `crt.sh` Certificate Transparency logs concurrently to map subdomains without generating direct traffic.
* **Active DNS Brute-Forcing:** Resolves wordlists asynchronously using `dnspython` over high-speed upstream nameservers (Cloudflare `1.1.1.1` & Google `8.8.8.8`) with automatic deduplication.
* **High-Speed 2-Phase Port Sweeps:** Dispatches hundreds of non-blocking TCP handshakes per second via `asyncio` streams, extracting service banners (SSH, HTTP, FTP) exclusively on confirmed open ports.
* **Automated Web Security Auditor:** Evaluates HTTP/HTTPS endpoints for missing defense-in-depth security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`), identifies exposed sensitive paths (`/.git/HEAD`, `/.env`, `/robots.txt`), and fingerprints backend technologies.
* **Interactive Terminal UI & Exporters:** Displays real-time scan progress spinners and color-coded tabular results powered by `rich`, exporting self-contained dark-mode HTML dashboards and JSON payloads.
* **Containerized Deployment:** Fully packaged Docker image based on `python:3.11-slim` with rootless execution support.

---

## 🛠️ Architecture & Pipeline

```text
                 [ Target Domain / IP ]
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
    [ Passive OSINT ]          [ Active DNS Brute-Force ]
  (AlienVault, HackerTarget,     (dnspython + Wordlist)
          crt.sh)                        │
             │                           │
             └─────────────┬─────────────┘
                           ▼
              [ DNS Deduplication & A-Records ]
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
    [ Async TCP Port Sweep ]    [ Web Security Auditing ]
  (High-concurrency handshake   (Header checks, sensitive path
     + Banner extraction)         discovery & tech fingerprinting)
             │                           │
             └─────────────┬─────────────┘
                           ▼
            [ Reporting & Visualization ]
       (Rich CLI UI ──► results.json ──► results.html)

```

---

## 📦 Installation & Setup

### Option 1: Local Virtual Environment (Recommended for Development)

1. **Clone the repository:**
```bash
git clone [https://github.com/ChAbde17/Argus-Eye.git](https://github.com/yourusername/Argus-Eye.git)
cd Argus-Eye

```


2. **Set up and activate virtual environment:**
```bash
python3 -m venv .venv
source .venv/bin/activate

```


3. **Install dependencies and CLI binary:**
```bash
pip install -r requirements.txt
pip install -e .

```



---

### Option 2: Docker Containerization

1. **Build the Docker image:**
```bash
docker build -t argus-eye .

```


2. **Run containerized scans (mounting local directory for reports):**
```bash
docker run --rm -it -v "$(pwd)":/app argus-eye -t scanme.nmap.org -p 80,443 -o both

```



---

## 💻 Command-Line Usage

```bash
argus-eye -t <TARGET> [OPTIONS]

```

### CLI Options Reference

| Flag | Full Option | Description | Default |
| --- | --- | --- | --- |
| `-t` | `--target` | **(Required)** Target domain or IPv4 address | `None` |
| `-p` | `--ports` | Comma-separated ports or port range (e.g., `80,443,8080` or `1-1024`) | `80,443,21,22,8080,8443` |
| `-w` | `--wordlist` | Custom subdomain dictionary path for active DNS brute-forcing | `wordlists/subdomains.txt` |
| `-o` | `--output` | Report output format: `json`, `html`, or `both` | `json` |
| `-r` | `--report-name` | Custom report filepath/prefix (e.g., `reports/scanme_audit`) | `results` |
| `-c` | `--concurrency` | Maximum concurrent asynchronous network workers | `250` |
| `-h` | `--help` | Show CLI help menu and exit |  |

---

## 🔍 Scan Examples

### 1. Quick Target Audit

```bash
argus-eye -t example.com -p 80,443,22

```

### 2. Full Port Sweep with HTML & JSON Reports

```bash
argus-eye -t scanme.nmap.org -p 1-1024 -c 300 -o both -r reports/scanme_full

```

### 3. Custom Subdomain Wordlist & Recon

```bash
argus-eye -t target.org -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o html

```

---

## 📂 Project Structure

```text
Argus-Eye/
├── Dockerfile                  # Container build instructions
├── .dockerignore               # Container build exclusions
├── main.py                     # CLI entrypoint and workflow coordinator
├── pyproject.toml / setup.py   # Packaging configurations
├── requirements.txt            # Project dependencies
├── scanner/
│   ├── __init__.py
│   ├── models.py               # Standard dataclasses (Host, PortResult, WebFinding)
│   ├── network.py              # Async TCP port sweeper and banner grabber
│   ├── recon.py                # Passive OSINT & active DNS brute-forcing
│   ├── reporter.py             # Rich terminal renderers & HTML/JSON exporters
│   ├── utils.py                # Target validation and sanitization helpers
│   └── web_audit.py            # Security header, sensitive path, and tech auditor
└── wordlists/
    └── subdomains.txt          # Default subdomain brute-forcing dictionary

```

---

## ⚖️ Legal & Ethical Disclaimer

```text
WARNING: This tool is developed strictly for educational purposes, authorized penetration
testing, and security auditing. Scanning targets without prior explicit written mutual
consent from the asset owner is illegal and violates local, national, and international laws.
The author assumes no liability and is not responsible for any misuse or damage caused by
this program.

```

---

## 👤 Author

* **Abderrahmane Chourak (CH ABDE)**
* **Portfolio / GitHub:** [@abderrahmane-chourak](https://github.com/ChAbde17)

```

```
