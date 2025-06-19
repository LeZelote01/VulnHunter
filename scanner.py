import nmap
import socket
import os

class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

        # Vérification du chemin Nmap
        self.verify_nmap_path()
    
    def verify_nmap_path(self):
        """Vérifie que nmap est accessible et affiche un message d'erreur si non trouvé"""
        try:
            # Tente d'obtenir la version nmap pour vérifier l'installation
            version = self.scanner.nmap_version()
            print(f"[*] Nmap version {version[0]}.{version[1]} détectée")
        except nmap.PortScannerError:
            print("\n[ERREUR CRITIQUE] Nmap n'est pas installé ou n'est pas dans le PATH")
            print("Veuillez installer Nmap :")
            print("  Linux: sudo apt install nmap")
            print("  macOS: brew install nmap")
            print("  Windows: Téléchargez depuis https://nmap.org/download.html")
            print("\nAssurez-vous d'ajouter Nmap à votre PATH pendant l'installation")
            exit(1)
    
    def scan(self, target, ports="1-1000"):
        try:
            print(f"[*] Scanning {target} on ports {ports}...")
            self.scanner.scan(
                hosts=target, 
                ports=ports, 
                arguments="-sV -T4 --script=banner,vulners"
            )
            return self.parse_results(target)
        except nmap.PortScannerError as e:
            print(f"Nmap error: {e}")
            return {}

    def parse_results(self, target):
        results = {}
        if target not in self.scanner.all_hosts():
            # Résolution DNS si nécessaire
            try:
                ip = socket.gethostbyname(target)
                if ip in self.scanner.all_hosts():
                    target = ip
            except socket.gaierror:
                return {}
        
        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == "up":
                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()
                    for port in ports:
                        service = self.scanner[host][proto][port]
                        results[port] = {
                            "state": service['state'],
                            "service": service['name'],
                            "version": service.get('version', '?'),
                            "banner": service.get('product', '?'),
                            "cpe": service.get('cpe', '?')
                        }
        return results