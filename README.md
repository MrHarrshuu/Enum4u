\# ENUM4U



> Unified Security Assessment Framework for automated reconnaissance, enumeration, vulnerability intelligence, risk analysis, and attack surface mapping.



ENUM4U is a modular security assessment framework designed to automate the early stages of an authorized security assessment.



It combines reconnaissance, service enumeration, web crawling, vulnerability intelligence, risk prioritization, and attack surface mapping into a single workflow.



\---



\## Features



\- Subdomain Enumeration

\- DNS Reconnaissance

\- Port \& Service Enumeration

\- HTTP Enumeration

\- Web Crawling

\- Technology Detection

\- TLS Analysis

\- Nuclei Vulnerability Assessment

\- CPE Detection

\- CVE Intelligence

\- EPSS Risk Intelligence

\- CISA KEV Detection

\- Risk Prioritization

\- Attack Surface Graph

\- JSON Reports

\- HTML Reports

\- Multiple Scan Modes



\---



\## Architecture



```text

Target

&#x20; │

&#x20; ▼

Reconnaissance

&#x20; │

&#x20; ├── DNS Enumeration

&#x20; ├── Subdomain Discovery

&#x20; ├── Certificate Information

&#x20; └── WHOIS Intelligence

&#x20; │

&#x20; ▼

Enumeration

&#x20; │

&#x20; ├── Port Scanning

&#x20; ├── Service Detection

&#x20; ├── HTTP Enumeration

&#x20; ├── Technology Detection

&#x20; └── TLS Analysis

&#x20; │

&#x20; ▼

Web Crawling

&#x20; │

&#x20; ▼

Vulnerability Assessment

&#x20; │

&#x20; ├── Nuclei

&#x20; └── Service Intelligence

&#x20; │

&#x20; ▼

Threat Intelligence

&#x20; │

&#x20; ├── CPE Detection

&#x20; ├── CVE Intelligence

&#x20; ├── EPSS Scoring

&#x20; └── CISA KEV Detection

&#x20; │

&#x20; ▼

Risk Analysis

&#x20; │

&#x20; ▼

Attack Surface Graph

&#x20; │

&#x20; ▼

Reports

&#x20; ├── JSON

&#x20; └── HTML

```



\---



\# Installation



\## Linux / Kali Linux



\### Clone the repository



```bash

git clone https://github.com/MrHarrshuu/Enum4u.git

cd Enum4u

```



\### Create a virtual environment



```bash

python3 -m venv .venv

source .venv/bin/activate

```



\### Install dependencies



```bash

pip install -r requirements.txt

pip install -e .

```



\### Verify installation



```bash

Enum4u --help

```



\---



\## Windows



\### Clone the repository



```powershell

git clone https://github.com/MrHarrshuu/Enum4u.git

cd Enum4u

```



\### Create a virtual environment



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

```



\### Install dependencies



```powershell

python -m pip install -r requirements.txt

python -m pip install -e .

```



\### Verify installation



```powershell

Enum4u --help

```



\---



\# External Tools



ENUM4U integrates with several external security tools.



| Tool | Purpose |

|---|---|

| Nmap | Port scanning and service detection |

| Subfinder | Subdomain enumeration |

| DNSx | DNS reconnaissance |

| HTTPx | HTTP probing |

| Katana | Web crawling |

| Nuclei | Vulnerability detection |



Check tool availability:



```bash

Enum4u --check

```



\---



\# Usage



\## Fast Assessment



Runs a faster security assessment with reduced enumeration and intelligence lookups.



```bash

Enum4u example.com --fast

```



\---



\## Deep Assessment



Runs a broader and more detailed assessment.



```bash

Enum4u example.com --deep

```



\---



\## Passive Reconnaissance



Performs reconnaissance with minimal active interaction.



```bash

Enum4u example.com --passive

```



\---



\## Active Enumeration



Runs active enumeration modules.



```bash

Enum4u example.com --active

```



\---



\# Individual Modules



ENUM4U also supports running individual assessment modules.



\### DNS



```bash

Enum4u example.com --dns

```



\### Subdomain Enumeration



```bash

Enum4u example.com --subdomains

```



\### Port Enumeration



```bash

Enum4u example.com --ports

```



\### Web Enumeration



```bash

Enum4u example.com --web

```



\### Web Crawling



```bash

Enum4u example.com --crawl

```



\### Vulnerability Assessment



```bash

Enum4u example.com --nuclei

```



\### Risk Analysis



```bash

Enum4u example.com --risk

```



\### Attack Surface Graph



```bash

Enum4u example.com --graph

```



\---



\# Scan Modes



| Mode | Description |

|---|---|

| `--fast` | Faster security assessment |

| `--deep` | Broader and deeper assessment |

| `--passive` | Passive reconnaissance mode |

| `--active` | Active enumeration mode |



\---



\# Output



ENUM4U generates structured assessment reports.



```text

output/

├── enum4u-report.json

└── enum4u-report.html

```



\### JSON Report



Contains structured scan results suitable for automation and further analysis.



\### HTML Report



Provides a human-readable assessment report.



\---



\# Example



```bash

Enum4u scanme.nmap.org --fast

```



Example workflow:



```bash

Enum4u --check

Enum4u example.com --fast

```



\---



\# Project Structure



```text

Enum4u/

│

├── enum4u/

│   ├── core/

│   ├── modules/

│   ├── intelligence/

│   ├── risk/

│   ├── graph/

│   ├── tools/

│   └── reporting/

│

├── configs/

├── data/

├── docs/

├── scripts/

├── tests/

├── output/

│

├── requirements.txt

├── pyproject.toml

└── README.md

```



\---



\# Disclaimer



ENUM4U is intended for authorized security testing, research, and educational purposes only.



Do not use this tool against systems, networks, or applications without explicit permission.



The developer assumes no liability for misuse or damage caused by this tool.



\---



\# Roadmap



Future development may include:



\- Continuous Attack Surface Monitoring

\- Historical Asset Tracking

\- Attack Path Analysis

\- AI-Assisted Security Analysis

\- Automated Remediation Recommendations

\- Additional Vulnerability Intelligence Sources

\- Improved Visualization

\- Docker Support

\- CI/CD Integration



\---



\# Contributing



Contributions, bug reports, and feature requests are welcome.



1\. Fork the repository

2\. Create a feature branch

3\. Commit your changes

4\. Push the branch

5\. Open a Pull Request



\---



\# Author



\*\*Harsh Kumar\*\*



Cybersecurity Researcher | Ethical Hacker | Security Tool Developer



GitHub: https://github.com/MrHarrshuu



\---



\# License



This project is intended for educational and authorized security testing purposes.



Please use responsibly.

