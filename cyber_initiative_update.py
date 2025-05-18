#!/usr/bin/env python3
"""
CYBER INITIATIVE AI - PRODUCTION-READY SCANNER (STREAMLIT CLOUD EDITION)
-> All original functionality preserved
-> In-memory report generation
-> Cloud-optimized performance
"""

import requests
import re
import json
import logging
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
from fpdf import FPDF
from io import BytesIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

class CyberScanner:
    def __init__(self):
        self.visited = set()
        self.findings = {}
        self.logs = []
        self.headers = {
            'User-Agent': 'CyberInitiativeAI/2.0 (Streamlit Cloud)',
            'Accept': 'text/html,application/xhtml+xml'
        }
        self.start_time = datetime.now()
        
        # Enhanced security rules (unchanged from original)
        self.rules = {
            "SQL Injection": {
                "patterns": [
                    r"\bUNION\s+SELECT\b.+?\bFROM\b",
                    r"\bSELECT\s.+?\bFROM\s.+?\bWHERE\s.+?\=\s*.+?--",
                    r"\bOR\s+1\s*=\s*1--"
                ],
                "severity": "CRITICAL",
                "advice": "Use parameterized queries immediately"
            },
            "XSS": {
                "patterns": [
                    r"<(script|iframe)[^>]*>.*?alert\(.*?</\1>",
                    r"javascript:(?!\/\/)[\"']?[\s\S]*?eval\([\s\S]*?[\"']",
                    r"on(error|load|click)\s*=\s*[\"'].*?\(.*?[\"']"
                ],
                "severity": "HIGH",
                "advice": "Implement Content Security Policy (CSP)"
            },
            "Exposed API Keys": {
                "patterns": [
                    r"\bAKIA[0-9A-Z]{16}\b",
                    r"\b(?:access|secret)[_\-]?key\s*=\s*[\"'][0-9a-zA-Z]{32,45}[\"']"
                ],
                "severity": "CRITICAL",
                "advice": "Rotate keys immediately and remove from code"
            }
        }
        self._validate_patterns()

    def _log(self, message):
        """Helper method for consistent logging"""
        self.logs.append(message)
        logging.info(message)

    def _validate_patterns(self):
        """Validate all regex patterns to catch errors early"""
        for vuln_name, rule in self.rules.items():
            for pattern in rule["patterns"]:
                try:
                    re.compile(pattern)
                except re.error as e:
                    error_msg = f"Invalid regex pattern for {vuln_name}: {pattern} - {str(e)}"
                    self._log(error_msg)
                    raise

    def _is_false_positive(self, match, context):
        """Enhanced false positive detection"""
        whitelist = [
            'googletagmanager.com',
            'google-analytics.com',
            'youtube.com/embed',
            'youtube-nocookie.com',
            'gstatic.com',
            'gtag.js',
            'gtm.js',
            'w-json',
            'dataLayer.push',
            'jquery',
            'webflow',
            'react-dom',
            'next-head'
        ]
        return any(w in context.lower() for w in whitelist) or \
               re.search(r'\{[\s\S]*"\w+":\s*"[^"]*"[\s\S]*\}', context)

    def scan_page(self, url, html):
        """Enterprise-grade scanning"""
        for vuln_name, rule in self.rules.items():
            for pattern in rule["patterns"]:
                try:
                    for match in re.finditer(pattern, html, re.IGNORECASE):
                        context = html[max(0, match.start()-100):match.end()+100]
                        if not self._is_false_positive(match.group(), context):
                            fingerprint = f"{vuln_name}||{url}||{match.group()[:50]}"
                            self.findings[fingerprint] = {
                                "vulnerability": vuln_name,
                                "severity": rule["severity"],
                                "url": url,
                                "evidence": match.group()[:200],
                                "advice": rule["advice"],
                                "context": f"...{context[:100]}..."
                            }
                except Exception as e:
                    error_msg = f"Error scanning for {vuln_name} on {url}: {str(e)}"
                    self._log(error_msg)

    def crawl(self, start_url, max_depth=3):
        """Safe crawling with depth control"""
        if not start_url.startswith(('http://', 'https://')):
            start_url = 'https://' + start_url
            
        queue = [(start_url, 0)]
        
        while queue and len(self.visited) < 20:
            url, depth = queue.pop(0)
            if depth > max_depth or url in self.visited:
                continue
                
            try:
                for attempt in range(3):
                    try:
                        response = requests.get(url, headers=self.headers, timeout=15)
                        if response.status_code == 200:
                            self.scan_page(url, response.text)
                            self.visited.add(url)
                            
                            soup = BeautifulSoup(response.text, 'html.parser')
                            for link in soup.find_all('a', href=True):
                                next_url = urljoin(url, link['href'])
                                if urlparse(next_url).netloc == urlparse(start_url).netloc:
                                    queue.append((next_url, depth + 1))
                        break
                    except requests.exceptions.RequestException as e:
                        if attempt == 2:
                            error_msg = f"Failed to scan {url} after 3 attempts: {str(e)}"
                            self._log(error_msg)
                            break
                        continue
            except Exception as e:
                error_msg = f"Error scanning {url}: {str(e)}"
                self._log(error_msg)

    def generate_pdf_report(self):
        """Generate professional PDF report in memory"""
        try:
            pdf = FPDF()
            pdf.add_page()
            
            # Header
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(0, 10, "Cyber Initiative", 0, 1)
            
            pdf.set_font("Arial", 'B', 20)
            pdf.cell(0, 15, "Cyber Initiative AI Security Report", 0, 1, 'C')
            
            pdf.set_font("Arial", 'I', 10)
            pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", 0, 1, 'C')
            pdf.ln(10)
            
            # Scan Summary
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, "Scan Summary", 0, 1)
            pdf.set_font("Arial", '', 12)
            
            scan_duration = (datetime.now() - self.start_time).total_seconds()
            
            col_width = pdf.w / 2.5
            pdf.cell(col_width, 8, "Pages Scanned:", 1)
            pdf.cell(col_width, 8, str(len(self.visited)), 1, 1)
            pdf.cell(col_width, 8, "Total Findings:", 1)
            pdf.cell(col_width, 8, str(len(self.findings)), 1, 1)
            pdf.cell(col_width, 8, "Scan Duration:", 1)
            pdf.cell(col_width, 8, f"{scan_duration:.2f} seconds", 1, 1)
            
            pdf.ln(15)
            
            # Findings
            if self.findings:
                pdf.set_font("Arial", 'B', 14)
                pdf.cell(0, 10, "Vulnerability Findings", 0, 1)
                pdf.set_font("Arial", '', 12)
                
                for finding in self.findings.values():
                    if finding['severity'] == "CRITICAL":
                        pdf.set_text_color(255, 0, 0)
                    elif finding['severity'] == "HIGH":
                        pdf.set_text_color(255, 128, 0)
                    elif finding['severity'] == "MEDIUM":
                        pdf.set_text_color(255, 255, 0)
                    else:
                        pdf.set_text_color(0, 0, 0)
                    
                    pdf.set_font('', 'B')
                    pdf.cell(0, 8, f"{finding['severity']}: {finding['vulnerability']}", 0, 1)
                    pdf.set_text_color(0, 0, 0)
                    
                    pdf.set_font('', '')
                    pdf.cell(10)
                    pdf.cell(0, 6, f"URL: {finding['url']}", 0, 1)
                    pdf.cell(10)
                    pdf.multi_cell(0, 6, f"Evidence: {finding['evidence'][:200]}")
                    
                    pdf.cell(10)
                    pdf.set_font('', 'B')
                    pdf.cell(0, 6, "Business Risk:", 0, 1)
                    pdf.cell(10)
                    pdf.set_font('', '')
                    risk_desc = {
                        "CRITICAL": "This could lead to complete system compromise and data theft",
                        "HIGH": "Could enable attackers to steal sensitive data or disrupt services",
                        "MEDIUM": "May allow limited unauthorized access or information disclosure",
                        "LOW": "Limited impact but should be addressed for security best practices"
                    }.get(finding['severity'], "Potential security weakness")
                    pdf.multi_cell(0, 6, risk_desc)
                    
                    pdf.cell(10)
                    pdf.set_font('', 'B')
                    pdf.cell(0, 6, "Recommendation:", 0, 1)
                    pdf.cell(10)
                    pdf.set_font('', '')
                    pdf.multi_cell(0, 6, finding['advice'])
                    
                    pdf.ln(5)
            else:
                pdf.cell(0, 10, "No critical vulnerabilities found", 0, 1)
            
            # Footer
            pdf.set_y(-15)
            pdf.set_font("Arial", 'I', 8)
            pdf.cell(0, 10, "Report generated by Cyber Initiative AI Scanner", 0, 0, 'C')
            
            # Return PDF as bytes directly
            return pdf.output(dest='S')  # No .encode('latin-1') needed
        except Exception as e:
            error_msg = f"Failed to generate PDF report: {str(e)}"
            self._log(error_msg)
            return None

    def generate_reports(self):
        """Generate all report types in memory"""
        reports = {
            "pdf": self.generate_pdf_report(),
            "json": json.dumps({
                "meta": {
                    "scanner": "Cyber Initiative AI Pro",
                    "date": datetime.now().isoformat(),
                    "stats": {
                        "pages": len(self.visited),
                        "findings": len(self.findings)
                    }
                },
                "results": list(self.findings.values())
            }, indent=2),
            "html": self._generate_html_report()
        }
        return reports

    def _generate_html_report(self):
        """Generate HTML report as string"""
        return f"""<!DOCTYPE html>
        <html>
        <head>
            <title>Cyber Initiative AI Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 2em; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                .critical {{ color: #dc2626; font-weight: bold; }}
                .high {{ color: #ea580c; }}
                .medium {{ color: #d97706; }}
            </style>
        </head>
        <body>
            <h1>Cyber Initiative AI Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
            <h2>Vulnerabilities</h2>
            <table>
                <tr><th>Type</th><th>Severity</th><th>Location</th><th>Recommendation</th></tr>
                {"".join(
                    f"<tr><td>{f['vulnerability']}</td>"
                    f"<td class='{f['severity'].lower()}'>{f['severity']}</td>"
                    f"<td><a href='{f['url']}' target='_blank'>{f['url']}</a></td>"
                    f"<td>{f['advice']}</td></tr>"
                    for f in self.findings.values()
                )}
            </table>
        </body>
        </html>"""

    def get_logs(self):
        """Get all logged messages"""
        return "\n".join(self.logs)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            scanner = CyberScanner()
            scanner.crawl(sys.argv[1])
            reports = scanner.generate_reports()
            if reports["pdf"]:
                with open("report.pdf", "wb") as f:
                    f.write(reports["pdf"])
            print(scanner.get_logs())
            sys.exit(0)
        except Exception as e:
            logging.error(f"Fatal error: {str(e)}")
            sys.exit(1)
    else:
        print("Usage: python3 cyber_scanner.py https://example.com")
        sys.exit(1)
