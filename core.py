import nmap
import os
import time
import json
from datetime import datetime

class NetInspector:
    def __init__(self):
        try:
            # Inizializza il PortScanner di Nmap
            self.nm = nmap.PortScanner()
            print("[*] Motore Nmap inizializzato con successo.")
        except Exception as e:
            print(f"[!] Errore inizializzazione Nmap: {e}")
            print("[i] Assicurati che Nmap sia installato nel sistema.")

    def scan_network(self, network_range):
        print(f"\n[*] Scansione in corso su {network_range}...")
        # -sn: Ping scan (Host discovery)
        self.nm.scan(hosts=network_range, arguments='-sn')
        
        found_hosts = []
        print(f"{'IP ADDRESS':<15} | {'HOSTNAME':<20} | {'VENDOR'}")
        print("-" * 50)
        
        for host in self.nm.all_hosts():
            ip = host
            hostname = self.nm[host].hostname() or "Unknown"
            
            # Recupero MAC e Vendor (solo se lanciato come admin)
            mac = "Unknown"
            vendor = "Unknown"
            if 'addresses' in self.nm[host] and 'mac' in self.nm[host]['addresses']:
                mac = self.nm[host]['addresses']['mac']
                vendor = self.nm[host].get('vendor', {}).get(mac, "Unknown")

            print(f"{ip:<15} | {hostname:<20} | {vendor}")
            found_hosts.append(ip)
            
        print(f"\n[*] Scansione completata. Trovati {len(found_hosts)} host attivi.")
        return found_hosts

    import json
import nmap

class NetInspector:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.services_db = self.load_services()

    def load_services(self):
        """Carica la lista dei servizi dal file JSON esterno"""
        try:
            with open('services.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print("[!] Avviso: services.json non trovato. Uso descrizioni generiche.")
            return {}

    def scan_ports(self, ip):
        print(f"\n[*] Analisi porte per: {ip}")
        # Scansione rapida (-F) o range specifico
        self.nm.scan(ip, arguments='-p1-1000 -sT')
        
        if ip not in self.nm.all_hosts():
            return

        for proto in self.nm[ip].all_protocols():
            ports = sorted(self.nm[ip][proto].keys())
            
            print(f"\n{'PORTA':<8} | {'STATO':<10} | {'DESCRIZIONE'}")
            print("-" * 50)
            
            for port in ports:
                state = self.nm[ip][proto][port]['state']
                
                # Cerchiamo nel JSON usando la stringa della porta
                description = self.services_db.get(str(port), "Servizio sconosciuto")
                
                print(f"{port:<8} | {state:<10} | {description}")

    def monitor_host(self, ip):
        print(f"\n[*] Monitoraggio LIVE di {ip} (CTRL+C per fermare)...")
        last_status = None
        try:
            while True:
                param = "-n" if os.name == "nt" else "-c"
                response = os.system(f"ping {param} 1 {ip} > nul 2>&1")
                current_status = "ONLINE" if response == 0 else "OFFLINE"
                
                if current_status != last_status:
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    print(f"[{timestamp}] STATO: {ip} è ora {current_status}")
                    last_status = current_status
                time.sleep(3)
        except KeyboardInterrupt:
            print("\n[*] Monitoraggio terminato.")