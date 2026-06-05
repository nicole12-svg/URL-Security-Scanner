"""
Security-Focused URL/Link Scanner
==================================
Crawls a website and detects:
  - Broken/unreachable links (404, timeout, etc.)
  -SQL injection attempts in URLs
  -XSS payloads in URLs
  -Suspicious redirects (domain-hopping)
  -Malicious/blacklisted domains
  -Embedded malicious scripts in page content
  -Phishing indicators

Author: Nicole Akinyi
"""

import re
import sys
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import socket
import time


# ─────────────────────────────────────────────
#  MALICIOUS PATTERNS (Detection Rules)
# ─────────────────────────────────────────────

# Common SQL Injection Patterns in URLs
SQL_INJECTION_PATTERNS = [
    r"('\s*(OR|AND)\s*'|1\s*=\s*1)",  # Classic: ' OR '1'='1
    r"(UNION.*SELECT|SELECT.*FROM)",   # UNION-based: UNION SELECT
    r"(;.*DROP|;.*DELETE|;.*INSERT)",  # Command injection: ; DROP
    r"(--|#|\/\*)",                     # Comment chars: --, #, /*
]

SQL_REGEX = re.compile('|'.join(SQL_INJECTION_PATTERNS), re.IGNORECASE)

# Common XSS (Cross-Site Scripting) Patterns in URLs
XSS_PATTERNS = [
    r"<script[^>]*>",                   # <script tags
    r"javascript:",                      # javascript: protocol
    r"on(load|error|click|mouse)=",     # Event handlers
    r"<iframe[^>]*>",                   # Embedded iframes
    r"<img[^>]*onerror=",               # Image with onerror
    r"eval\(",                          # eval() calls
    r"(alert|confirm|prompt)\(",        # Popup functions
]

XSS_REGEX = re.compile('|'.join(XSS_PATTERNS), re.IGNORECASE)

# Known malware/phishing domains (basic blacklist)
MALICIOUS_DOMAINS = {
    "malicious.com",
    "phishing-bank.net",
    "bit.ly",  # URL shortener (can hide destination)
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
}

# Suspicious keywords that often appear in phishing/malware sites
SUSPICIOUS_KEYWORDS = [
    "verify", "confirm", "update", "urgently", "act now",
    "click here", "validate", "authenticate", "suspicious activity",
]

# High-risk file extensions
RISKY_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".sh", ".ps1",  # Executables
    ".dll", ".so", ".dylib",                 # Libraries
    ".zip", ".rar", ".7z",                   # Archives
    ".scr", ".vbs", ".jar",                 # Scripts
]

# ─────────────────────────────────────────────
#  DETECTION FUNCTIONS
# ─────────────────────────────────────────────

def detect_sql_injection(url: str) -> bool:
    """Check if URL contains SQL injection patterns."""
    return bool(SQL_REGEX.search(url))


def detect_xss(url: str) -> bool:
    """Check if URL contains XSS payloads."""
    return bool(XSS_REGEX.search(url))


def detect_malicious_domain(domain: str) -> bool:
    """Check if domain is in our blacklist."""
    domain_lower = domain.lower()
    return domain_lower in MALICIOUS_DOMAINS or any(
        domain_lower.endswith(bad) for bad in MALICIOUS_DOMAINS
    )


def detect_phishing_indicators(url: str, page_title: str = "") -> list[str]:
    """
    Scan for phishing red flags.
    Returns list of warnings.
    """
    warnings = []
    url_lower = url.lower()
    page_lower = page_title.lower()
    
    # Check for suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower or keyword in page_lower:
            warnings.append(f"Phishing keyword found: '{keyword}'")
    
    # Suspect if URL has many parameters (common in phishing)
    if url.count('?') > 2 or url.count('&') > 5:
        warnings.append("Unusually high number of URL parameters (phishing sign)")
    
    # Suspicious if domain and page title don't match
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    if page_title and domain not in page_title.lower():
        if len(page_title) > 3:  # Avoid false positives on tiny titles
            warnings.append(f"Domain mismatch: URL is '{domain}' but page title is '{page_title}'")
    
    return warnings


def detect_malicious_scripts(html_content: str) -> list[str]:
    """
    Scan page HTML for suspicious scripts.
    Returns list of warnings.
    """
    warnings = []
    
    # Check for obfuscated JavaScript (common in malware)
    if 'atob(' in html_content or 'eval(' in html_content:
        warnings.append("Found obfuscated/eval'd JavaScript (potential malware)")
    
    # Check for suspicious iframe injections
    iframe_pattern = r'<iframe[^>]*src=["\']([^"\']+)["\']'
    iframes = re.findall(iframe_pattern, html_content, re.IGNORECASE)
    for iframe_src in iframes:
        if 'ads' not in iframe_src.lower() and 'analytics' not in iframe_src.lower():
            warnings.append(f"Suspicious iframe detected: {iframe_src[:60]}")
    
    # Check for hidden divs (malware often hides stuff)
    if 'display:none' in html_content or 'visibility:hidden' in html_content:
        warnings.append("Found hidden HTML elements (potential malware injection)")
    
    return warnings


def is_risky_file(url: str) -> bool:
    """Check if URL points to a risky file type."""
    return any(url.lower().endswith(ext) for ext in RISKY_EXTENSIONS)

# ─────────────────────────────────────────────
#  NETWORK FUNCTIONS
# ─────────────────────────────────────────────

def fetch_page(url: str, timeout: int = 5) -> tuple[str | None, int]:
    """
    Download HTML from a URL.
    Returns (html_content, status_code) or (None, 0) if fails.
    """
    try:
        import urllib.request
        import urllib.error
        
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            html = response.read().decode('utf-8', errors='ignore')
            return html, response.status
    except urllib.error.HTTPError as e:
        return None, e.code
    except socket.timeout:
        return None, 0  # 0 means timeout
    except Exception as e:
        return None, 0


def check_link_status(url: str, timeout: int = 3) -> dict:
    """
    Check if a link is accessible and return its status.
    Returns a dict with status info.
    """
    try:
        import urllib.request
        import urllib.error
        
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0'},
            method='HEAD'  # HEAD request = faster than GET
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return {
                "url": url,
                "status": response.status,
                "accessible": True,
                "reason": "OK"
            }
    except urllib.error.HTTPError as e:
        return {
            "url": url,
            "status": e.code,
            "accessible": e.code < 400,  # 3xx redirects are OK
            "reason": {
                301: "Moved Permanently",
                302: "Found (Redirect)",
                304: "Not Modified",
                400: "Bad Request",
                401: "Unauthorized",
                403: "Forbidden",
                404: "Not Found",
                500: "Internal Server Error",
                503: "Service Unavailable",
            }.get(e.code, f"HTTP {e.code}")
        }
    except socket.timeout:
        return {
            "url": url,
            "status": 0,
            "accessible": False,
            "reason": "Timeout (no response)"
        }
    except Exception as e:
        return {
            "url": url,
            "status": 0,
            "accessible": False,
            "reason": f"Error: {type(e).__name__}"
        }


def extract_links(html_content: str, base_url: str) -> list[str]:
    """
    Extract all <a href> links from HTML.
    Converts relative URLs to absolute.
    """
    links = []
    # Find all <a href="..."> patterns
    href_pattern = r'href=["\']([^"\']+)["\']'
    matches = re.findall(href_pattern, html_content, re.IGNORECASE)
    
    for href in matches:
        # Skip anchors (#), email, javascript
        if href.startswith(('#', 'mailto:', 'javascript:', 'tel:')):
            continue
        
        # Convert relative URLs to absolute
        absolute_url = urljoin(base_url, href)
        
        # Only keep http/https
        if absolute_url.startswith(('http://', 'https://')):
            links.append(absolute_url)
    
    return list(set(links))  # Remove duplicates

# ─────────────────────────────────────────────
#  CRAWLER ENGINE
# ─────────────────────────────────────────────

def crawl(starting_url: str, max_depth: int = 2, max_pages: int = 50, log_callback=None) -> dict:
    """
    Crawl a website starting from starting_url.
    Follow links up to max_depth levels.
    Returns comprehensive analysis.
    """
    visited = set()
    to_visit = [(starting_url, 0)]  # (url, depth)
    results = {
        "good_links": [],
        "broken_links": [],
        "sql_injection_urls": [],
        "xss_urls": [],
        "malicious_domains": [],
        "suspicious_redirects": [],
        "phishing_indicators": [],
        "malware_scripts": [],
        "risky_files": [],
        "total_links": 0,
    }
    
    # Get base domain to stay within scope
    base_domain = urlparse(starting_url).netloc
    
    pages_crawled = 0
    
    # Small helper so callers (CLI or GUI) can receive progress messages
    def _log(msg: str):
        if log_callback:
            try:
                log_callback(msg)
            except Exception:
                # Ensure crawler doesn't crash on logging errors
                print(msg)
        else:
            print(msg)

    _log(f"\n🔍 Starting scan of {starting_url}\n")
    
    while to_visit and pages_crawled < max_pages:
        url, depth = to_visit.pop(0)
        
        # Skip if already visited
        if url in visited:
            continue
        visited.add(url)
        pages_crawled += 1
        
        # Skip if exceeded depth
        if depth > max_depth:
            continue
        
        _log(f"  [{pages_crawled}] Scanning (depth {depth}): {url[:70]}")
        
        # Fetch the page
        html, status = fetch_page(url, timeout=5)
        
        if html is None:
            status_check = check_link_status(url)
            results["broken_links"].append({
                "url": url,
                "status": status_check["status"],
                "reason": status_check["reason"]
            })
            continue
        
        # Get page title for phishing detection
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        page_title = title_match.group(1) if title_match else ""
        
        # Extract links
        links = extract_links(html, url)
        results["total_links"] += len(links)
        
        for link in links:
            # Check for security threats in URL
            if detect_sql_injection(link):
                results["sql_injection_urls"].append(link)
                continue
            
            if detect_xss(link):
                results["xss_urls"].append(link)
                continue
            
            parsed = urlparse(link)
            if detect_malicious_domain(parsed.netloc):
                results["malicious_domains"].append(link)
                continue
            
            if is_risky_file(link):
                results["risky_files"].append(link)
                continue
            
            # Check phishing indicators
            phishing = detect_phishing_indicators(link, page_title)
            if phishing:
                results["phishing_indicators"].append({
                    "url": link,
                    "warnings": phishing
                })
                continue
            
            # If link is on same domain, add to crawl queue
            link_domain = parsed.netloc
            if link_domain == base_domain:
                if link not in visited:
                    to_visit.append((link, depth + 1))
            
            # Check link accessibility
            status_check = check_link_status(link)
            if status_check["accessible"]:
                results["good_links"].append(link)
            else:
                results["broken_links"].append(status_check)
        
        # Check for malicious scripts in page content
        scripts = detect_malicious_scripts(html)
        if scripts:
            results["malware_scripts"].append({
                "url": url,
                "warnings": scripts
            })
    
    return results

# ─────────────────────────────────────────────
#  REPORT DISPLAY
# ─────────────────────────────────────────────

def print_report(results: dict) -> None:
    """Print a formatted security scan report."""
    print(format_report(results))


def format_report(results: dict) -> str:
    """Return a formatted security scan report as a string."""
    parts = []
    parts.append("\n" + "="*70)
    parts.append("  SECURITY URL SCAN REPORT")
    parts.append("="*70)
    parts.append("\n📊 SUMMARY:")
    parts.append(f"  Total links found      : {results['total_links']}")
    parts.append(f"  Good links             : {len(results['good_links'])}")
    parts.append(f"  Broken links           : {len(results['broken_links'])}")

    # SQL Injection
    if results['sql_injection_urls']:
        parts.append(f"\n🚨 SQL INJECTION DETECTED ({len(results['sql_injection_urls'])} URLs):")
        for url in results['sql_injection_urls'][:10]:
            parts.append(f"  ❌ {url[:70]}")

    # XSS
    if results['xss_urls']:
        parts.append(f"\n⚠️  XSS PAYLOADS DETECTED ({len(results['xss_urls'])} URLs):")
        for url in results['xss_urls'][:10]:
            parts.append(f"  ❌ {url[:70]}")

    # Malicious domains
    if results['malicious_domains']:
        parts.append(f"\n🔴 MALICIOUS DOMAINS ({len(results['malicious_domains'])} URLs):")
        for url in results['malicious_domains'][:10]:
            parts.append(f"  ❌ {url[:70]}")

    # Phishing
    if results['phishing_indicators']:
        parts.append(f"\n🎣 PHISHING INDICATORS ({len(results['phishing_indicators'])} pages):")
        for item in results['phishing_indicators'][:5]:
            parts.append(f"  📄 {item['url'][:70]}")
            for warn in item['warnings']:
                parts.append(f"     • {warn}")

    # Malware scripts
    if results['malware_scripts']:
        parts.append(f"\n💾 MALWARE/SUSPICIOUS SCRIPTS ({len(results['malware_scripts'])} pages):")
        for item in results['malware_scripts'][:5]:
            parts.append(f"  📄 {item['url'][:70]}")
            for warn in item['warnings']:
                parts.append(f"     • {warn}")

    # Risky files
    if results['risky_files']:
        parts.append(f"\n⚠️  RISKY FILE DOWNLOADS ({len(results['risky_files'])} files):")
        for url in results['risky_files'][:10]:
            parts.append(f"  ⬇️  {url[:70]}")

    # Broken links
    if results['broken_links']:
        parts.append(f"\n🔗 BROKEN LINKS ({len(results['broken_links'])} URLs):")
        for item in results['broken_links'][:10]:
            parts.append(f"  [{item['status']}] {item['reason']:<30} {item['url'][:50]}")

    parts.append("\n" + "="*70 + "\n")
    return "\n".join(parts)

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print("🔒 Security-Focused URL Scanner")
    print("   Detects: broken links, SQL injection, XSS, malware, phishing\n")
    
    url = input("Enter starting URL (e.g. https://example.com): ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print("\nScan depth:")
    print("  1 = shallow (just this page)")
    print("  2 = normal (follow one level of links)")
    print("  3 = deep (follow 2 levels)")
    
    try:
        depth = int(input("Choose depth [1-3, default=2]: ").strip() or "2")
        depth = max(1, min(3, depth))
    except ValueError:
        depth = 2
    
    results = crawl(url, max_depth=depth, max_pages=50)
    print_report(results)


if __name__ == "__main__":
    main()