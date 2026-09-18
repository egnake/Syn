<div align="center">
  <img src="docs/images/1_banner.png" alt="SYN Banner" width="600">
  <h1>🚀 SYN Framework</h1>
  <p><strong>Advanced AI-Powered Autonomous Security Scanner & Pentest Framework</strong></p>

  <p align="center">
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10+-blue.svg?style=for-the-badge&logo=python" alt="Python"></a>
    <a href="https://scikit-learn.org/"><img src="https://img.shields.io/badge/AI-Scikit--Learn-orange.svg?style=for-the-badge&logo=scikitlearn" alt="AI"></a>
    <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/Docker-Supported-2496ED.svg?style=for-the-badge&logo=docker" alt="Docker"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License"></a>
  </p>
</div>

---

## 📖 Overview

**SYN** is a next-generation, autonomous port scanner and vulnerability assessment framework powered by Artificial Intelligence (Machine Learning) and real-time CVE intelligence. 

Designed for red teamers, bug bounty hunters, and penetration testers, SYN goes beyond traditional scanning mechanisms. By predicting the target's operating system, identifying network anomalies through machine learning models, and dynamically adapting its scanning behavior, SYN ensures maximum stealth and efficiency. It automatically fetches the latest high-risk CVEs from the NIST National Vulnerability Database (NVD) to provide immediate threat context.

## ✨ Core Features

*   **🤖 Autonomous AI Engine (SMART Mode)**: Utilizes trained Random Forest models to analyze target responses (TTL, Latency, Flags). It can predict the underlying OS and automatically pivot to the optimal scan method (e.g., switching to FIN scans if a stateful firewall drops initial probes).
*   **⚡ Ultra-Fast Asynchronous Scanning**: Implements high-performance TCP connection scans via `asyncio`, allowing rapid reconnaissance without requiring root privileges.
*   **🥷 Stealth Operations**: Integrates a powerful `scapy` engine supporting advanced packet manipulation (SYN, ACK, FIN, XMAS, and NULL scans) to map networks while bypassing traditional IDS/IPS systems.
*   **🌐 Real-Time CVE Integration**: Automatically queries the NIST NVD API using intelligent banner grabbing. It discovers zero-days and known vulnerabilities on the fly, utilizing a local SQLite caching system to prevent API rate limits.
*   **📊 Rich Terminal UI & Reporting**: Features a highly interactive setup wizard, color-coded terminal tables, and robust export capabilities (JSON, HTML, Markdown).
*   **🐳 Docker Ready**: Fully containerized environment for isolated, dependency-free execution with optimized caching.

---

## 📸 Screenshots & Workflow

### 1. Interactive Setup Wizard
Provides an intuitive, colorized CLI wizard to quickly configure targets, port profiles, and scan modes.
<div align="center">
  <img src="docs/images/2_setup.png" alt="Interactive Setup" width="800">
</div>

### 2. Engine Initialization & AI Analysis
Loads the machine learning models and initializes the OODA (Observe, Orient, Decide, Act) loop for target analysis.
<div align="center">
  <img src="docs/images/3_scan.png" alt="Scan Initialization" width="800">
</div>

---

## 📦 Installation

### Option 1: Docker (Recommended for Stealth Scans)
Running via Docker ensures all `scapy` dependencies (like `tcpdump` and `libpcap`) are perfectly isolated.
```bash
git clone https://github.com/egnakesec/syn.git
cd syn
docker-compose up --build
```
*Note: The `docker-compose.yml` uses `network_mode: "host"` to ensure stealth scans and proper port bindings work flawlessly.*

### Option 2: Local Installation (Requires Python 3.10+)
If you prefer running it locally on your host machine:
```bash
git clone https://github.com/egnakesec/syn.git
cd syn
pip install -e .
```

---

## 🛠️ Usage

SYN defaults to its **Interactive Wizard** if no arguments are provided. Simply type `syn` in your terminal:

```bash
syn
```

### Advanced CLI Arguments

For automated pipelines or power users, SYN supports direct execution:

```bash
# Autonomous AI Scan on a specific port range
syn 192.168.1.1 1 1000 --mode SMART

# Ultra-Fast Async Scan (No root needed) with JSON reporting
syn scanme.nmap.org 80 443 --mode ASYNC --report json

# Stealth TCP SYN Scan (Requires Root/Admin Privileges)
sudo syn 10.0.0.5 1 65535 --mode S
```

### Supported Scan Modes

| Mode | Description | Privileges Required |
|:---:|---|:---:|
| **SMART** | Autonomous AI Decision Engine. Analyzes initial state and pivots dynamically. | User / Root |
| **ASYNC** | Ultra-fast concurrent TCP connect scan. | User |
| **S** | TCP SYN Stealth Scan (Half-open scanning). | **Root** |
| **A** | TCP ACK Scan (Used for firewall mapping). | **Root** |
| **F** | TCP FIN Scan (Bypasses stateless firewalls). | **Root** |
| **X** | TCP XMAS Scan (Lights up the packet like a Christmas tree). | **Root** |
| **N** | TCP NULL Scan (No flags set). | **Root** |

### Output Formats

Generate comprehensive reports using the `--report` flag:
- `console`: Rich terminal output (Default)
- `json`: Machine-readable JSON output
- `html`: Beautifully styled HTML report
- `md`: Markdown format for easy sharing

---

## 🏗️ Architecture Under the Hood

1. **Reconnaissance & Expansion**: Resolves domains, performs subdomain enumeration via OSINT, and executes initial host discovery.
2. **AI Pre-Processing (OODA Loop)**: Initial stealth probes measure TTL and Latency.
3. **Inference**: The Scikit-Learn Random Forest and Anomaly Detection models classify the host (Windows/Linux/Custom) and score the network anomaly.
4. **Execution Pivot**: Based on the AI decision, SYN automatically switches to the optimal scan payload (e.g., Async, Stealth, FIN).
5. **Deep Fingerprinting**: Grabs banners and analyzes HTTP web surfaces dynamically.
6. **Vulnerability Assessment**: Queries the local NVD cache and live API for CVEs matching the grabbed banners.

---

## ⚠️ Disclaimer

**SYN Framework** is developed exclusively for educational purposes and authorized professional penetration testing. The author assumes no liability and is not responsible for any misuse, damage, or unauthorized access caused by this tool. **Always obtain explicit, written authorization before scanning any network or system.**

---

## 👤 Author
Developed with ❤️ by **Egnake**.
