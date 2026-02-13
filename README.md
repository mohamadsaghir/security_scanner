# DX2 Security Recon Tool

A comprehensive security reconnaissance and vulnerability scanning tool designed for educational and authorized testing purposes. This tool performs both passive and active checks to identify potential weaknesses in web applications and services.

## Features

The DX2 Security Recon tool includes a wide range of modules for thorough security assessment:

### Core Capabilities
- **Stealth Mode**: Uses randomized User-Agents and delays to evade basic detection.
- **Active Scanning**: Performs targeted payload injection for common vulnerabilities.
- **Risk Assessment**: Calculates a dynamic risk score based on findings and their severity.
- **Confidence Levels**: Categorizes findings as Confirmed, Potential, or Theoretical.

### Scanning Modules
1.  **Service & Tech Stack Analysis** (`ServiceVersionAwareness`, `WebScanner`)
    -   Identifies server technologies and versions.
    -   Checks for known CVEs associated with specific versions.
    -   Analyzes HTTP headers for security best practices (HSTS, CSP, X-Frame-Options, etc.).

2.  **Authentication & Session Security** (`LoginLogicModule`, `CookieSecurity`)
    -   Detects login forms and evaluates authentication mechanisms.
    -   Checks for cleartext transmission (HTTP vs HTTPS).
    -   Validates anti-CSRF tokens.
    -   Inspects cookies for `Secure`, `HttpOnly`, and `SameSite` flags.

3.  **Network & SSL/TLS** (`PortScanner`, `SSLAnalyzer`)
    -   Scans common ports (21, 22, 80, 443, 3306, 8080, etc.).
    -   Analyzes SSL/TLS configurations for weak protocols (TLS 1.0/1.1) and ciphers.

4.  **Vulnerability Detection** (`SQLInjectionScanner`, `XSSScanner`, `LFIScanner`)
    -   **SQL Injection**: Fuzzes parameters with SQL payloads to detect database errors.
    -   **Reflected XSS**: Injects script payloads to test for reflection.
    -   **LFI (Local File Inclusion)**: Attempts to read sensitive system files (e.g., `/etc/passwd`).

5.  **Infrastructure Checks** (`DirectoryBruteforce`, `RateLimitDetector`)
    -   Brute-forces common sensitive paths (`.env`, `.git`, `admin/`, etc.).
    -   Tests for rate limiting on endpoints.

### Advanced Analysis
-   **Kill Chain Construction**: Correlates findings to build potential attack paths (e.g., SQLi -> Admin Takeover).
-   **Baseline Comparison**: Compares current scan results with previous baselines to track new vs. persistent issues.
-   **Reporting**: Generates executive summaries and detailed technical recommendations.

## Usage

To run the scanner, execute the main script:

```bash
python security_scanner.py
```

Follow the on-screen prompts (if any) or modify the script to target specific URLs.

## Disclaimer

**Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.**

## key Classes

-   `ScanResult`: Aggregates all findings, assets, and risk scores.
-   `Finding`: standardized format for reporting vulnerabilities.
-   `StealthConfig`: Manages request headers and timing to mimic legitimate traffic.
