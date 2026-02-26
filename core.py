import nmap
import mysql.connector
import os
import time
from datetime import datetime
from config import DB_CONFIG

class NetInspector:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            self.db = mysql.connector.connect(**DB_CONFIG)
            self.cursor = self.db.cursor(dictionary=True)
        except Exception as e:
            print(f"[!] Errore inizializzazione: {e}")

    def log_event(self, ip, message):
        query = "INSERT INTO logs (ip, event) VALUES (%s, %s)"
        self.cursor.execute(query, (ip, message))
        self.db.commit()

    def scan_network(self, network_range):
        print(f"[*] Scansione Nmap in corso su {network_range}...")
        # -sn: Host discovery (senza port scan, molto veloce)
        self.nm.scan(hosts=network_range, arguments='-sn')
        
        found_hosts = []
        for host in self.nm.all_hosts():
            ip = host
            hostname = self.nm[host].hostname() or "Unknown"
            # Nmap cattura il MAC solo se eseguito come admin
            mac = "Unknown"
            vendor = "Unknown"
            if 'addresses' in self.nm[host] and 'mac' in self.nm[host]['addresses']:
                mac = self.nm[host]['addresses']['mac']
                vendor = self.nm[host].get('vendor', {}).get(mac, "Unknown")

            # Inserimento/Aggiornamento nel DB
            query = """INSERT INTO devices (ip, hostname, mac_address, vendor) 
                       VALUES (%s, %s, %s, %s) 
                       ON DUPLICATE KEY UPDATE last_seen=NOW()"""
            self.cursor.execute(query, (ip, hostname, mac, vendor))
            self.db.commit()
            
            print(f"[+] Trovato: {ip} | {hostname} | {vendor}")
            found_hosts.append(ip)
        return found_hosts

    def scan_ports(self, ip):
        print(f"[*] Analisi porte profonde per {ip}...")
        # -F: scan veloce delle 100 porte più comuni, -sV: rileva versione servizio
        self.nm.scan(ip, arguments='-F -sV')
        
        if ip not in self.nm.all_hosts():
            print("[!] Host non risponde.")
            return

        # Recupero ID per la chiave esterna
        self.cursor.execute("SELECT id FROM devices WHERE ip = %s", (ip,))
        device = self.cursor.fetchone()
        
        for proto in self.nm[ip].all_protocols():
            ports = self.nm[ip][proto].keys()
            for port in ports:
                state = self.nm[ip][proto][port]['state']
                service = self.nm[ip][proto][port]['name']
                
                query = """INSERT INTO scan_results (device_id, port, protocol, status, service) 
                           VALUES (%s, %s, %s, %s, %s)"""
                self.cursor.execute(query, (device['id'], port, proto, state, service))
                print(f"    [!] Porta {port}/{proto}: {state} ({service})")
        
        self.db.commit()

    def monitor_host(self, ip):
        print(f"[*] Monitoraggio {ip} avviato (CTRL+C per uscire)...")
        last_status = None
        try:
            while True:
                # Ping di sistema
                param = "-n" if os.name == "nt" else "-c"
                response = os.system(f"ping {param} 1 {ip} > nul 2>&1")
                current_status = "ONLINE" if response == 0 else "OFFLINE"
                
                if current_status != last_status:
                    self.log_event(ip, f"Stato cambiato in {current_status}")
                    print(f"[EVENTO] {datetime.now().strftime('%H:%M:%S')} - {ip} è {current_status}")
                    last_status = current_status
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[*] Monitoraggio terminato.")