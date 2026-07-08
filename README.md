<p align="center">
  <a href="https://drive.google.com/file/d/1tTuLA0cuMH0Sm5hiHb5Pwq-xheq7D55r/view?usp=drive_link">
    <img src="https://drive.google.com/uc?export=view&id=1tTuLA0cuMH0Sm5hiHb5Pwq-xheq7D55r" alt="Repository Logo">
  </a>
</p>

# AI Automated Infrastructure Vulnerability Scanner and Patching Tool with Ethereum and SIEM Integration

## Overview
This is an advanced security scanning and vulnerability patching recommendation tool designed to help users detect vulnerabilities in their infrastructure and web applications. It integrates multiple scanning tools like **Nmap, Lynis, Naabu, Gobuster, and Bandit**, along with an AI-based recommendation engine to provide intelligent patching suggestions.

> **🛰️ ScamRecon** — the dedicated reconnaissance framework (32-tool chain,
> passive + active asset discovery for a domain and all its subdomains, validated
> HTML/PDF/JSON reports, cross-platform for Kali/Parrot/macOS) lives in
> [`recon.py`](recon.py) and is documented in **[RECON.md](RECON.md)**.
> Quick start: `python3 recon.py --install` then `python3 recon.py -d example.com`.
>
> **🛡️ ScamVapt** — a confirmation-first VAPT framework (37-tool chain) that
> consumes recon output and confirms **only tool-proven** critical/high vulns
> (SQLi, XSS, LFI, SSTI, RCE, SSRF, redirect, CRLF) with **zero false positives**,
> each finding carrying reproduction steps + PoC in a polished SVG/PDF report.
> Lives in [`vapt.py`](vapt.py), documented in **[VAPT.md](VAPT.md)**.
> Quick start: `python3 vapt.py --install` then `python3 vapt.py --from-recon recon_output`.

<p align="center">
  <img src="https://github.com/user-attachments/assets/dd4bc53a-3c42-4737-a939-bca59c1c7a5e" alt="Screenshot from 2025-03-21 00-36-00">
</p>

## Features
- **Infrastructure Scanning:** Uses Nmap, Lynis, and Naabu for network and system vulnerability detection.
- **Web Application Scanning:** Gobuster for directory enumeration.
- **Source Code Analysis:** Bandit for Python security analysis.
- **AI-Powered Patching Recommendations:** Utilizes Groq AI to analyze scan logs and suggest mitigations.
- **Detailed Reporting:** Generates log files in text and HTML formats for easy analysis.

## System Requirements
- **OS:** Linux (Tested on Kali Linux)
- **Dependencies:**
  - `python3`
  - `pandas`
  - `nmap`
  - `lynis`
  - `naabu`
  - `gobuster`
  - `bandit`
  - `requests`
- **API Key:** Groq API key for AI-based recommendations

## Installation
1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/scandroid.git
   cd scandroid
   ```
2. **Install dependencies:**
   ```sh
   sudo apt install nmap lynis naabu gobuster bandit
   pip install pandas requests
   ```
3. **Set up API Key:**
   - Open `aiRecommendation.py`
   - Replace `{API_KEY}` with your actual Groq API key.

## Usage
### 1. Running the Scanner
```sh
sudo python3 scanner.py
```
- Select options from the menu to perform scans.
- Logs are saved at `/home/kali/Downloads/finalScanner/reports/`.

### 2. Running the CSV Extractor
```sh
python3 csvExtractor.py --source /path/to/logs --output_dir /path/to/output
```
- Extracts vulnerabilities from Lynis logs and generates CSV reports.

### 3. Running AI-Based Recommendations
```sh
python3 aiRecommendation.py
```
- Reads scan logs and provides AI-driven security recommendations.

## File Structure
```
scandroid/
├── scanner.py         # Main script for scanning
├── csvExtractor.py    # Extracts vulnerabilities from logs to CSV
├── aiRecommendation.py # AI-based patch recommendations
├── README.md          # Documentation
└── reports/           # Log files generated after scanning
```

## Logging and Reports
- **Plain text logs:** `/home/kali/Downloads/finalScanner/reports/scanner_file.txt`
- **HTML reports:** `/home/kali/Downloads/finalScanner/reports/scanner_file.html`
- **AI reports:** `/home/kali/Downloads/finalScanner/aiReport/ai_report.txt`


# 🛡️ Ethereum Blockchain Log Storage System

A secure and transparent system for storing and retrieving log files using Ethereum smart contracts. This project uses Web3, Solidity, and Python to interact with a local blockchain (Ganache).

---

## 📋 Table of Contents

- [🚀 Quick Start](#-quick-start)
- [⚙️ Prerequisites](#-prerequisites)
- [💻 Installation](#-installation)
- [🛠️ Usage](#-usage)
- [📂 File Structure](#-file-structure)
- [🐞 Troubleshooting](#-troubleshooting)
- [📄 License](#-license)

---

## 🚀 Quick Start

### 1. Activate Virtual Environment

```bash
source myenv/bin/activate
```

### 2. Deploy the Smart Contract

```bash
python3 smartContract.py
```

> 📌 **Note:** Copy the deployed contract address (e.g., `0x123...`) from the output and update it inside `storage.py`.

### 3. Store Logs on the Blockchain

```bash
python3 storage.py
```

---

## ⚙️ Prerequisites

Ensure the following dependencies are installed:

- ✅ Python `3.8+`
- ✅ Node.js `v14+`
- ✅ `npm`
- ✅ Ganache CLI (for local blockchain testing)

---

## 💻 Installation

### Python Dependencies

```bash
pip install web3 py-solc-x
```

### Node.js & npm (Linux/Ubuntu)

```bash
sudo apt update
sudo apt install nodejs npm
```

### Check Installed Versions

```bash
node -v
npm -v
```

### Ganache CLI (Local Blockchain)

```bash
npm install -g ganache
```

---

## 🛠️ Usage

### Start the Local Blockchain

```bash
ganache --port=7545
```

> Open a new terminal for the next steps.

### Step-by-Step Log Storage Workflow

1. **Generate Contract Address**

   Run the following to deploy the smart contract:

   ```bash
   python3 smartContract.py
   ```

   This will output a **contract address**. Copy this address.

2. **Store Scanner Logs**

   Paste the generated contract address into the `storage.py` script and run:

   ```bash
   python3 storage.py
   ```

   This will store your scanner logs on the blockchain.

3. **Fetch Hashed Stored Logs**

   Make sure the contract address is updated in `get_hashed_logs.py` and run:

   ```bash
   python3 get_hashed_logs.py
   ```

   This will fetch and display the hashed log entries from the blockchain.

---

## 📂 File Structure

```text
.
├── smartContract.py       # Smart contract deployment logic
├── storage.py             # Logs storage to blockchain
├── fetch_logs.py          # Read logs from local files
├── fetch_stored_logs.py   # Retrieve stored logs from blockchain
├── get_hashed_logs.py     # Generate & verify log hashes
├── LogStorage.sol         # Solidity smart contract
└── README.md              # This file
```

---

## 🐞 Troubleshooting

| ❌ Error              | ✅ Solution                           |
|----------------------|----------------------------------------|
| `Connection refused` | Ensure Ganache CLI is running properly |
| `Module not found`   | Reinstall Python dependencies          |
| `Permission denied`  | Use `sudo` if accessing system logs    |
| `Empty results`      | Confirm that the contract is deployed  |

---

## 📄 License

This project is licensed under the **MIT License**.


## Future Enhancements
- Add support for more vulnerability scanning tools.
- Implement automated patching.
- Enhance AI recommendations with additional machine learning models.

## Contributors
- **Agastsya Joshi** - Co-founder
- **Karman Arora** - Co-founder
- **Nitin Dogra** - Co-founder
- **Open to Contributions**



