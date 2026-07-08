import subprocess
import sys
import time
import os
import json
import csv
from datetime import datetime
import webbrowser
from urllib.parse import urlparse
import csvExtractor
import patchingSystem

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "reports")
AI_LOG_DIR = os.path.join(SCRIPT_DIR, "aiReport")
AI_LOG_FILE = os.path.join(AI_LOG_DIR, "ai_report.txt") 
CSV_REPORTS_DIR = os.path.join(SCRIPT_DIR, "csv_reports")
LOG_FILE = os.path.join(LOG_DIR, "scanner_file.txt")
HTML_LOG_FILE = os.path.join(LOG_DIR, "scanner_file.html")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(AI_LOG_DIR, exist_ok=True)
os.makedirs(CSV_REPORTS_DIR, exist_ok=True)

# Wordlist paths searched in order — first match wins
WORDLIST_PATHS = {
    "common": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/SecLists/Discovery/Web-Content/common.txt",
        os.path.expanduser("~/tools/SecLists/Discovery/Web-Content/common.txt"),
        os.path.expanduser("~/SecLists/Discovery/Web-Content/common.txt"),
        "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
    ],
    "big": [
        "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "/usr/share/SecLists/Discovery/Web-Content/big.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        os.path.expanduser("~/tools/SecLists/Discovery/Web-Content/big.txt"),
        os.path.expanduser("~/SecLists/Discovery/Web-Content/big.txt"),
    ],
    "subdomains": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
        os.path.expanduser("~/tools/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
        os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
    ],
    "lfi": [
        "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
        "/usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt",
        os.path.expanduser("~/tools/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"),
        os.path.expanduser("~/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"),
    ],
    "params": [
        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "/usr/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
        os.path.expanduser("~/tools/SecLists/Discovery/Web-Content/burp-parameter-names.txt"),
        os.path.expanduser("~/SecLists/Discovery/Web-Content/burp-parameter-names.txt"),
    ],
}

def find_wordlist(category):
    for path in WORDLIST_PATHS.get(category, []):
        if os.path.exists(path):
            return path
    return None

def check_tool(name):
    try:
        subprocess.run([name, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def _parse_live_urls(live_file):
    """Parse URLs from httpx output (handles JSON-per-line and plain URL formats)."""
    urls = []
    try:
        with open(live_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("{"):
                    try:
                        data = json.loads(line)
                        url = data.get("url") or data.get("input")
                        if url:
                            urls.append(url)
                    except Exception:
                        pass
                elif line.startswith("http"):
                    urls.append(line.split()[0])
    except Exception:
        pass
    return list(dict.fromkeys(urls))  # deduplicate preserving order

def display_banner():
    banner = rf"""
{Color.RED}
███████╗ ██████╗ █████╗ ███╗   ███╗██████╗ ██████╗  ██████╗ ██╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗ ████║██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗
███████╗██║     ███████║██╔████╔██║██║  ██║██████╔╝██║   ██║██║██║  ██║
╚════██║██║     ██╔══██║██║╚██╔╝██║██║  ██║██╔══██╗██║   ██║██║██║  ██║
███████║╚██████╗██║  ██║██║ ╚═╝ ██║██████╔╝██║  ██║╚██████╔╝██║██████╔╝
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ 
{Color.CYAN}                                                              v0.0.1
{Color.MAGENTA}[ETHEREUM BASED]{Color.YELLOW}[Vulnerability Scanner and AI-Based Patching and Recommendation Tool]
{Color.RESET}
"""
    # Typewriter effect
    for line in banner.split('\n'):
        print(line)
        time.sleep(0.05) if not sys.platform.startswith('win') else None

def log_result(scan_type, result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log:
        log.write(f"[{timestamp}] {scan_type} Results:\n{result}\n\n")
    
    with open(HTML_LOG_FILE, "a") as html_log:
        html_log.write(f"<h2>{scan_type} Results ({timestamp})</h2><pre>{result}</pre><hr>")


# ... (keep all previous imports and constants unchanged)

def run_nuclei_scan(target_url):
    # Validate and normalize URL
    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = f"http://{target_url}"
        parsed = urlparse(target_url)
    
    if not parsed.netloc:
        print(f"{RED}ERROR: Invalid URL format{RESET}")
        return

    print(f"\n{GREEN}Starting Nuclei scan on {target_url}{RESET}")
    
    # Configure paths
    report_path = os.path.join(LOG_DIR, f"nuclei_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    try:
        # Verify Nuclei is installed
        subprocess.run(['nuclei', '-version'], 
                      check=True,
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}ERROR: Nuclei not installed. Install with:{RESET}")
        print("go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
        return

    try:
        # Build Nuclei command
        command = [
            'nuclei',
            '-u', target_url,
            '-json',
            '-o', report_path,
            '-silent'
        ]

        # Run Nuclei with real-time output
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Capture and display output
        output = []
        print(f"{CYAN}[+] Scanning started{RESET}")
        while True:
            line = process.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line:
                print(f"  {YELLOW}{line}{RESET}")
                output.append(line)
        
        process.wait()
        
        # Log results
        log_result("Nuclei Scan", f"Target: {target_url}\nOutput:\n" + "\n".join(output))

        # Display results
        if os.path.exists(report_path):
            print(f"\n{GREEN}[+] Scan results:{RESET}")
            try:
                with open(report_path, 'r') as f:
                    findings = [json.loads(line) for line in f.readlines()]
                    
                vuln_counts = {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'unknown': 0
                }
                
                for finding in findings:
                    severity = finding.get('info', {}).get('severity', 'unknown').lower()
                    vuln_counts[severity] += 1
                    
                    print(f"{YELLOW}Found: {RESET}{finding.get('template-id')}")
                    print(f"{CYAN}Severity: {severity.upper()} | Matched: {finding.get('matched-at')}{RESET}")
                    print("-" * 50)
                
                print(f"\n{GREEN}Vulnerability Summary:{RESET}")
                print(f"Critical: {vuln_counts['critical']}")
                print(f"High: {vuln_counts['high']}")
                print(f"Medium: {vuln_counts['medium']}")
                print(f"Low: {vuln_counts['low']}")
                print(f"Unknown: {vuln_counts['unknown']}")
                
            except Exception as e:
                print(f"{RED}Error parsing results: {e}{RESET}")
        else:
            print(f"{RED}No results found{RESET}")

    except Exception as e:
        print(f"{RED}Error running Nuclei scan: {str(e)}{RESET}")

def run_backend():
    print(f"{GREEN}Running backend MongoDB upload...{RESET}")
    try:
        result = subprocess.run(
            ['node', 'backend.js'],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(result.stdout)
        if result.stderr:
            print(f"{RED}Errors:{RESET}\n{result.stderr}")
    except Exception as e:
        print(f"{RED}Error running backend: {e}{RESET}")

def generate_csv_reports():
    """Generate CSV reports from log files using csvExtractor"""
    print(f"{GREEN}Generating CSV reports from log files...{RESET}")
    
    try:
        # Create timestamped output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(CSV_REPORTS_DIR, f"csv_reports_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)

        # Run CSV extraction
        csvExtractor.main([
            "--source", LOG_DIR,
            "--output_dir", output_dir
        ])

        # Verify and display results
        print(f"\n{GREEN}Report generation completed!{RESET}")
        print(f"{CYAN}Output directory: {output_dir}{RESET}")
        
        csv_files = [f for f in os.listdir(output_dir) if f.endswith('.csv')]
        if csv_files:
            print(f"{GREEN}Generated files:{RESET}")
            for file in csv_files:
                print(f" - {file}")
        else:
            print(f"{YELLOW}No CSV files were generated{RESET}")
            print(f"{YELLOW}Check if log files exist in: {LOG_DIR}{RESET}")

    except Exception as e:
        print(f"\n{RED}Error generating reports: {str(e)}{RESET}")
        if 'output_dir' in locals():
            print(f"{YELLOW}Partial files might exist in: {output_dir}{RESET}")


def ai_log_result(scan_type, result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(AI_LOG_FILE, "a") as log:  # Fixed variable name
        log.write(f"[{timestamp}] {scan_type} Results:\n{result}\n\n")
    
    with open(HTML_LOG_FILE, "a") as html_log:
        html_log.write(f"<h2>{scan_type} Results ({timestamp})</h2><pre>{result}</pre><hr>")

def delete_logs():
    open(LOG_FILE, "w").close()

def view_ai_logs():  # New function to view AI logs
    print(f"{GREEN}Displaying AI log contents...{RESET}")
    try:
        if not os.path.exists(AI_LOG_FILE):
            print(f"{YELLOW}No AI logs found.{RESET}")
            return
            
        with open(AI_LOG_FILE, "r") as f:
            contents = f.read()
            print(f"{CYAN}AI Logs:\n{RESET}{contents}")
    except Exception as e:
        print(f"{RED}Error reading AI log file: {e}{RESET}")




def run_nmap_scan(target_ip):
    print(f"{GREEN}Running Nmap scan on {target_ip}...{RESET}")
    result = subprocess.run(['nmap', '-sV', target_ip],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True)
    output = result.stdout if result.returncode == 0 else result.stderr
    print(f"{CYAN}Nmap scan results for {target_ip}:\n{RESET}{output}")
    log_result("Nmap Scan", f"Target: {target_ip}\n{output}")

def run_bandit_scan():
    print(f"{GREEN}Running Bandit code analysis...{RESET}")
    target_dir = input(f"{YELLOW}Enter directory path to scan (e.g., /home/projects): {RESET}")
    
    if not os.path.isdir(target_dir):
        print(f"{RED}ERROR: Invalid directory path{RESET}")
        return

    try:
        result = subprocess.run(
            ['bandit', '-r', target_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output = result.stdout if result.returncode == 0 else result.stderr
        print(f"{CYAN}Bandit scan results for {target_dir}:\n{RESET}{output}")
        log_result("Bandit Code Scan", f"Target: {target_dir}\n{output}")
    except FileNotFoundError:
        print(f"{RED}ERROR: Bandit command not found. Please install bandit with 'pip install bandit'{RESET}")
    except Exception as e:
        print(f"{RED}Error running Bandit scan: {e}{RESET}")

def run_lynis_scan():
    print(f"{GREEN}Running Lynis audit on the local system...{RESET}")

    try:
        # Check if Lynis is installed
        subprocess.run(['lynis', '--version'],
                       check=True,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}ERROR: Lynis not found. Please install Lynis first.{RESET}")
        print("Installation instructions: https://cisofy.com/lynis/")
        return

    try:
        # Run Lynis in non-interactive mode using --cronjob flag
        process = subprocess.Popen(
            ['lynis', 'audit', 'system', '--quick', '--no-colors', '--cronjob'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )

        output_lines = []
        while True:
            line = process.stdout.readline()
            if not line:
                break
            print(line, end='')  # Print each line as it appears
            sys.stdout.flush()
            output_lines.append(line.strip())  # Store output for logging

        process.stdout.close()
        process.wait()

        # Combine output and log it
        output = "\n".join(output_lines)
        print(f"{CYAN}Lynis audit completed. Saving results...{RESET}")
        log_result("Lynis Audit", output)

    except subprocess.TimeoutExpired:
        print(f"{RED}ERROR: Lynis scan timed out after 10 minutes{RESET}")
    except Exception as e:
        print(f"{RED}Error running Lynis scan: {str(e)}{RESET}")



def run_naabu_scanner(target_ip):
    print(f"{GREEN}Running Naabu scan on {target_ip}...{RESET}")
    try:
        # Replace '/usr/local/bin/naabu' with the correct path if needed
        result = subprocess.run(['/home/agastsya-joshi/go/bin/naabu', '-host', target_ip],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
    except FileNotFoundError:
        print(f"{RED}ERROR: Naabu command not found. Please install Naabu.{RESET}")
        return
    output = result.stdout if result.returncode == 0 else result.stderr
    print(f"{CYAN}Naabu scan results for {target_ip}:\n{RESET}{output}")
    log_result("Naabu Scan", f"Target: {target_ip}\n{output}")


def run_ffuf_scan(target_url):
    # Validate and normalize URL
    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = f"http://{target_url}"
        parsed = urlparse(target_url)
    
    if not parsed.netloc:
        print(f"{RED}ERROR: Invalid URL format{RESET}")
        return

    print(f"\n{GREEN}Starting FFUF scan on {target_url}{RESET}")
    
    # Configure paths
    wordlist_path = "/usr/share/wordlists/dirb/common.txt"
    report_path = os.path.join(LOG_DIR, "ffuf_report.csv")
    
    # Verify wordlist exists
    if not os.path.exists(wordlist_path):
        print(f"{RED}ERROR: Wordlist not found at {wordlist_path}{RESET}")
        print(f"{YELLOW}Install dirb wordlists with: sudo apt install dirb{RESET}")
        return

    try:
        # Verify FFUF is installed
        subprocess.run(['ffuf', '-h'], check=True, 
                      stdout=subprocess.DEVNULL, 
                      stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}ERROR: ffuf not installed. Install with:{RESET}")
        print("go install github.com/ffuf/ffuf/v2@latest")
        return

    try:
        # Build FFUF command
        command = [
            'ffuf',
            '-w', f"{wordlist_path}:FUZZ",
            '-u', f"{target_url}/FUZZ",
            '-t', '50',
            '-mc', '200,301,302,403,500',
            '-ac',
            '-v',
            '-o', report_path,
            '-of', 'csv',
            '-s'
        ]

        # Run FFUF with real-time output
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Capture and display output
        output = []
        print(f"{CYAN}[+] Scanning started{RESET}")
        while True:
            line = process.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line:
                print(f"  {YELLOW}{line}{RESET}")
                output.append(line)
        
        process.wait()
        
        # Log results
        log_result("FFUF Scan", f"Target: {target_url}\nOutput:\n" + "\n".join(output))

        # Display results
        if os.path.exists(report_path):
            print(f"\n{GREEN}[+] Scan results:{RESET}")
            with open(report_path, 'r') as f:
                reader = csv.reader(f)
                headers = next(reader)  # Skip header
                for row in reader:
                    if len(row) >= 6:
                        print(f"{CYAN}URL: {row[0]} | Status: {row[3]} | Size: {row[4]} | Words: {row[5]}{RESET}")
            print(f"{GREEN}Full report saved to: {report_path}{RESET}")
        else:
            print(f"{RED}No results found{RESET}")

    except Exception as e:
        print(f"{RED}Error running FFUF scan: {str(e)}{RESET}")

def run_ai_recommendations():
    print(f"{GREEN}Generating AI security recommendations...{RESET}")
    try:
        result = subprocess.run(
            ['python3', os.path.join(SCRIPT_DIR, "aiRecommendation.py")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output = result.stdout if result.returncode == 0 else result.stderr
        print(f"{CYAN}AI Recommendations:\n{RESET}{output}")
    except Exception as e:
        print(f"{RED}Error running AI recommendations: {e}{RESET}")

def view_logs():
    print(f"{GREEN}Opening log file in web browser...{RESET}")
    webbrowser.open(HTML_LOG_FILE)

def infra_scanner():
    while True:
        print(f"\n{YELLOW}Infra Scanner Options:{RESET}")
        print(f"{BLUE}(1){RESET} {GREEN}Scan multiple IPs using Nmap{RESET}")
        print(f"{BLUE}(2){RESET} {GREEN}Run Lynis scan{RESET}")
        print(f"{BLUE}(3){RESET} {GREEN}Scan multiple IPs using Naabu{RESET}")
        print(f"{BLUE}(4){RESET} {GREEN}Back to Main Menu{RESET}")
        
        try:
            choice = int(input(f"\n{CYAN}Enter your choice (1-4): {RESET}"))
            if choice == 1:
                ips = input(f"{YELLOW}Enter target IPs (comma-separated) for Nmap scan: {RESET}")
                ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()]
                for ip in ip_list:
                    run_nmap_scan(ip)
            elif choice == 2:
                run_lynis_scan()
            elif choice == 3:
                ips = input(f"{YELLOW}Enter target IPs (comma-separated) for Naabu scan: {RESET}")
                ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()]
                for ip in ip_list:
                    run_naabu_scanner(ip)
            elif choice == 4:
                break
            else:
                print(f"{RED}Invalid choice. Please select between 1-4.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input. Please enter a numeric value.{RESET}")

def run_patching_system():
    print(f"{GREEN}Running security patching system...{RESET}")
    patching_log = "/home/agastsya-joshi/Documents/ScamDroid/aiReport/ai_report.txt"
    
    # Verify AI report exists
    if not os.path.exists(patching_log):
        print(f"{RED}Error: AI report not found at {patching_log}{RESET}")
        print(f"{YELLOW}Please generate an AI report first{RESET}")
        return

    try:
        # Backup original arguments
        original_argv = sys.argv.copy()
        try:
            # Simulate command line arguments for patching system
            sys.argv = ["patchingSystem.py", patching_log]
            print(f"{CYAN}Processing security recommendations from:{RESET} {patching_log}")
            patchingSystem.main()
        finally:
            # Restore original arguments
            sys.argv = original_argv
    except Exception as e:
        print(f"{RED}Error during patching: {str(e)}{RESET}")


def web_scanner():
    while True:
        print(f"\n{YELLOW}Web Scanner Options:{RESET}")
        print(f"{BLUE}(1){RESET} {GREEN}Run ffuf : fast web fuzzer{RESET}")
        print(f"{BLUE}(2){RESET} {GREEN}Run Nuclei Vulnerability Scan{RESET}")
        print(f"{BLUE}(3){RESET} {GREEN}Back to Main Menu{RESET}")
        print(f"{CYAN}Note: reconnaissance now lives in the dedicated tool -> python3 recon.py{RESET}")

        try:
            choice = int(input(f"\n{CYAN}Enter your choice (1-3): {RESET}"))
            if choice == 1:
                url = input(f"{YELLOW}Enter target URL: {RESET}")
                run_ffuf_scan(url)
            elif choice == 2:
                url = input(f"{YELLOW}Enter target URL: {RESET}")
                run_nuclei_scan(url)
            elif choice == 3:
                break
            else:
                print(f"{RED}Invalid choice. Please select between 1-3.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input. Please enter a numeric value.{RESET}")


def main():
    display_banner()
    if os.geteuid() != 0:
        print(f"{RED}This script requires root privileges. Please run with 'sudo'.{RESET}")
        sys.exit(1)
    
    while True:
        print(f"\n{YELLOW}Main Menu:{RESET}")
        print(f"{BLUE}(1){RESET} {GREEN}Infrastructure Scanners{RESET}")
        print(f"{BLUE}(2){RESET} {GREEN}Web Scanners{RESET}")
        print(f"{BLUE}(3){RESET} {GREEN}Bandit Scanner{RESET}")
        print(f"{BLUE}(4){RESET} {GREEN}View Logs{RESET}")
        print(f"{BLUE}(5){RESET} {GREEN}View AI Logs{RESET}")
        print(f"{BLUE}(6){RESET} {GREEN}Get AI Recommendations{RESET}")
        print(f"{BLUE}(7){RESET} {GREEN}Initiate Patching System{RESET}")
        print(f"{BLUE}(8){RESET} {GREEN}Upload Files to backend{RESET}")
        print(f"{BLUE}(9){RESET} {GREEN}Exit{RESET}")
        
        try:
            choice = int(input(f"\n{CYAN}Enter your choice (1-9): {RESET}"))
            if choice == 1:
                infra_scanner()
            elif choice == 2:
                web_scanner()
            elif choice == 3:
                run_bandit_scan()
            elif choice == 4:
                view_logs()
            elif choice == 5:
                view_ai_logs()
            elif choice == 6:
                run_ai_recommendations()
            elif choice == 7:
                run_patching_system()
            elif choice == 8:
                run_backend()
            elif choice == 9:
                print(f"{GREEN}Exiting...{RESET}")
                break
            else:
                print(f"{RED}Invalid choice. Please select between 1-9.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input. Please enter a numeric value.{RESET}")

if __name__ == "__main__":
    main()
