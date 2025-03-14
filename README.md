# ScanDroid - Vulnerability Scanner and AI-Based Patching Recommendation Tool

## Overview
ScanDroid is an advanced security scanning and vulnerability patching recommendation tool designed to help users detect vulnerabilities in their infrastructure and web applications. It integrates multiple scanning tools like **Nmap, Lynis, Naabu, Gobuster, and Bandit**, along with an AI-based recommendation engine to provide intelligent patching suggestions.

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

## Future Enhancements
- Add support for more vulnerability scanning tools.
- Implement automated patching.
- Enhance AI recommendations with additional machine learning models.

## Contributors
- **Your Name** - Developer
- **Open to Contributions**

## License
This project is licensed under the MIT License.

