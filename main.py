# main.py (nouvelle version)
import threading
import time
from scanner import PortScanner
from cve_lookup import CVESearcher
from web_scanner import WebVulnerabilityScanner
from flask import Flask, render_template, request, jsonify
import json
import os
from datetime import datetime
from prettytable import PrettyTable

app = Flask(__name__)

def generate_report(target, scan_results, vulns, web_vulns):
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_base = f"results/report_{target}_{timestamp}"
    
    # Rapport texte
    with open(f"{filename_base}.txt", "w") as f:
        f.write(f"VulnHunter Report - {target}\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("="*70 + "\n\n")
        
        f.write("[OPEN PORTS & SERVICES]\n")
        for port, data in scan_results.items():
            f.write(f"Port {port}: {data['service']} {data['version']}\n")
            for vuln in vulns.get(port, []):
                f.write(f"  [CVE] {vuln['id']} (CVSS: {vuln.get('cvss', '?')}) - {vuln['summary'][:150]}...\n")
        
        if web_vulns:
            f.write("\n[WEB VULNERABILITIES]\n")
            for url, vulns_list in web_vulns.items():
                f.write(f"\nURL: {url}\n")
                for vuln in vulns_list:
                    f.write(f"  [{vuln['severity']}] {vuln['name']}: {vuln['description']}\n")
    
    # Rapport JSON
    with open(f"{filename_base}.json", "w") as f:
        json.dump({
            "target": target,
            "timestamp": timestamp,
            "services": scan_results,
            "cve_vulnerabilities": vulns,
            "web_vulnerabilities": web_vulns
        }, f, indent=2)
    
    return filename_base

def display_results_table(scan_results, vulns, web_vulns):
    print("\n" + "="*70)
    print(f"VULNHUNTER SCAN REPORT".center(70))
    print("="*70)
    
    # Tableau des services
    service_table = PrettyTable()
    service_table.field_names = ["Port", "Service", "Version", "CVEs"]
    service_table.align = "l"
    service_table.max_width = 60
    
    for port, data in scan_results.items():
        cve_list = [v['id'] for v in vulns.get(port, [])]
        service_table.add_row([port, data['service'], data['version'], "\n".join(cve_list or ["None"])])
    
    print("\n[OPEN PORTS & SERVICES]")
    print(service_table)
    
    # Tableau des vulnérabilités web
    if web_vulns:
        web_table = PrettyTable()
        web_table.field_names = ["URL", "Vulnerability", "Severity"]
        web_table.align = "l"
        
        for url, vulns_list in web_vulns.items():
            for vuln in vulns_list:
                web_table.add_row([url, vuln['name'], vuln['severity']])
        
        print("\n[WEB VULNERABILITIES]")
        print(web_table)

def run_scan(target, ports, web_scan=False):
    start_time = time.time()
    
    # Scan de ports
    scanner = PortScanner()
    scan_results = scanner.scan(target, ports)
    
    # Recherche CVE avec multithreading
    cve_searcher = CVESearcher()
    vulns = {}
    threads = []
    
    def process_port(port, data):
        if data['state'] == "open":
            vulns[port] = cve_searcher.search(data['service'], data['version'])
    
    for port, data in scan_results.items():
        t = threading.Thread(target=process_port, args=(port, data))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # Scan web
    web_vulns = {}
    if web_scan:
        web_scanner = WebVulnerabilityScanner()
        web_urls = [f"http://{target}:{port}" for port in scan_results if str(port) in ['80', '443', '8080']]
        web_vulns = web_scanner.scan(web_urls)
    
    # Génération des rapports
    report_base = generate_report(target, scan_results, vulns, web_vulns)
    
    return {
        "scan_time": time.time() - start_time,
        "services": scan_results,
        "cve_vulnerabilities": vulns,
        "web_vulnerabilities": web_vulns,
        "report": f"{report_base}.txt"
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def api_scan():
    data = request.json
    target = data.get('target')
    ports = data.get('ports', '1-1000')
    web_scan = data.get('web_scan', False)
    
    if not target:
        return jsonify({"error": "Target required"}), 400
    
    results = run_scan(target, ports, web_scan)
    return jsonify(results)

def cli_interface():
    print("""
    ██╗   ██╗██╗   ██╗██╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██║   ██║██║   ██║██║     ██║ ██╔╝██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ╚██╗ ██╔╝██║   ██║██║     ██╔═██╗ ██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
     ╚████╔╝ ╚██████╔╝███████╗██║  ██╗╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    """)
    
    target = input("Target (IP/hostname): ").strip()
    ports = input("Ports (ex: 80,443 or 1-1000) [default: 1-1000]: ").strip() or "1-1000"
    web_scan = input("Enable web vulnerability scan? (y/n) [default: n]: ").strip().lower() == 'y'
    
    results = run_scan(target, ports, web_scan)
    
    display_results_table(
        results['services'], 
        results['cve_vulnerabilities'], 
        results['web_vulnerabilities']
    )
    
    print(f"\n[+] Scan completed in {results['scan_time']:.2f} seconds")
    print(f"[+] Report saved to {results['report']}")

if __name__ == "__main__":
    # Mode CLI
    cli_interface()
    
    # Mode Web (décommentez pour activer)
    # app.run(host='0.0.0.0', port=5000, threaded=True)