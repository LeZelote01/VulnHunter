import requests
from bs4 import BeautifulSoup
import re

class WebVulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })
    
    def scan(self, urls):
        results = {}
        for url in urls:
            try:
                vulns = []
                
                # Test XSS
                xss_vuln = self.test_xss(url)
                if xss_vuln:
                    vulns.append(xss_vuln)
                
                # Test SQL Injection
                sqli_vuln = self.test_sqli(url)
                if sqli_vuln:
                    vulns.append(sqli_vuln)
                
                # Test CORS
                cors_vuln = self.test_cors(url)
                if cors_vuln:
                    vulns.append(cors_vuln)
                
                # Détection de technologies vulnérables
                tech_vulns = self.detect_vulnerable_tech(url)
                vulns.extend(tech_vulns)
                
                if vulns:
                    results[url] = vulns
            except Exception:
                continue
        return results

    def test_xss(self, url):
        test_payload = "<script>alert('VulnHunter_XSS_Test');</script>"
        try:
            response = self.session.get(url, params={"q": test_payload}, timeout=5)
            if test_payload in response.text:
                return {
                    "name": "Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "description": "Reflected XSS vulnerability detected",
                    "payload": test_payload
                }
        except Exception:
            pass
        return None

    def test_sqli(self, url):
        test_payload = "' OR 1=1--"
        try:
            response = self.session.get(url, params={"id": test_payload}, timeout=5)
            if "error in your SQL syntax" in response.text:
                return {
                    "name": "SQL Injection",
                    "severity": "Critical",
                    "description": "Possible SQL injection vulnerability detected",
                    "payload": test_payload
                }
        except Exception:
            pass
        return None

    def test_cors(self, url):
        try:
            response = self.session.get(url, headers={"Origin": "https://attacker.com"}, timeout=5)
            if "access-control-allow-origin" in response.headers:
                if response.headers["access-control-allow-origin"] == "https://attacker.com":
                    return {
                        "name": "Misconfigured CORS",
                        "severity": "Medium",
                        "description": "CORS misconfiguration allows arbitrary origin"
                    }
        except Exception:
            pass
        return None

    def detect_vulnerable_tech(self, url):
        vulns = []
        try:
            response = self.session.get(url, timeout=5)
            server = response.headers.get("Server", "").lower()
            powered = response.headers.get("X-Powered-By", "").lower()
            
            # Détection de versions vulnérables
            if "apache/2.4.49" in server:
                vulns.append({
                    "name": "Apache Path Traversal (CVE-2021-41773)",
                    "severity": "Critical",
                    "description": "Vulnerable Apache version detected (2.4.49)"
                })
            
            if "php/5.6" in powered:
                vulns.append({
                    "name": "PHP End-of-Life",
                    "severity": "High",
                    "description": "Outdated PHP version with known vulnerabilities"
                })
            
            # Recherche dans le code HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = soup.find_all('meta', attrs={"name": "generator"})
            for tag in meta_tags:
                content = tag.get('content', '').lower()
                if "wordpress" in content:
                    vulns.append({
                        "name": "WordPress Security Risks",
                        "severity": "Medium",
                        "description": "Common WordPress vulnerabilities may exist"
                    })
                
        except Exception:
            pass
        return vulns