# 🚀 SYN: AI-Powered Autonomous Pentest Framework

SYN is an advanced, autonomous port scanner and vulnerability assessment framework powered by Artificial Intelligence (Machine Learning) and real-time CVE integration.

Designed for bug bounty hunters and penetration testers, SYN goes beyond traditional scanning by predicting the target's operating system, identifying network anomalies, and automatically fetching the latest high-risk CVEs from the NIST National Vulnerability Database.

## ✨ Features
- **🤖 Autonomous AI Engine (SMART Mode)**: Analyzes target responses (TTL, Latency, Flags) using Random Forest models to predict the OS and automatically switches to the best scan method (e.g., pivoting to FIN scans if a stateful firewall is detected).
- **⚡ Ultra-Fast Asynchronous Scanning**: Capable of extremely fast TCP connection scans via `asyncio` without requiring root privileges.
- **🥷 Stealth Operations**: Integrated `scapy` engine for SYN, ACK, FIN, XMAS, and NULL scans to bypass IDS/IPS.
- **🌐 Real-Time CVE Integration**: Automatically queries the NIST NVD API using grabbed service banners to find zero-days or known vulnerabilities. Includes an intelligent local caching system to prevent API rate limits.
- **📊 Rich Terminal UI**: Interactive setup wizard, colorized tables, and JSON export capabilities.

## 📦 Installation

```bash
git clone https://github.com/egnakesec/syn.git
cd syn
pip install -e .
```

## 🛠️ Usage

SYN comes with an interactive wizard by default. Simply type `syn` in your terminal to start the TUI:

```bash
syn
```

### Advanced CLI Arguments
For script integration or power users, SYN supports direct CLI arguments:

```bash
# Autonomous AI Scan
syn 192.168.1.1 1 1000 --mode SMART

# Ultra-Fast Async Scan (No root needed)
syn scanme.nmap.org 80 443 --mode ASYNC --report json

# Stealth TCP SYN Scan
syn 10.0.0.5 1 65535 --mode S
```

### Scan Modes
*   **SMART**: Autonomous mode. Uses AI to analyze the initial state and pivot dynamically.
*   **ASYNC**: Ultra-fast concurrent TCP connect scan.
*   **S**: TCP SYN Stealth Scan.
*   **A**: TCP ACK Scan (Firewall mapping).
*   **F**: TCP FIN Scan (Bypassing stateless firewalls).
*   **X**: TCP XMAS Scan.
*   **N**: TCP NULL Scan.

## 📝 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author
Developed by **Egnake**.
