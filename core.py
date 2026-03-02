import threading
import nmap
import os
import time
import subprocess
import platform
import speedtest
from datetime import datetime

class NetInspector:
    def __init__(self):
        try:
            # Inizializza il PortScanner di Nmap
            self.nm = nmap.PortScanner()
            self.log_file = "network_events.log"
            self.lock = threading.Lock()
            print("[*] Motore Nmap inizializzato con successo.")
        except Exception as e:
            print(f"[!] Errore inizializzazione Nmap: {e}")

    def log_event(self, category, message):
        """Scrive l'evento sul file e forza la scrittura immediata sul disco"""
        timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        log_entry = f"[{category}] {timestamp}\n{message}\n" + "-"*40 + "\n"
        
        with self.lock: # Protegge il file durante la scrittura
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(log_entry)
                    f.flush()
                    os.fsync(f.fileno()) 
            except Exception as e:
                print(f"[!] Errore scrittura log: {e}")

    def scan_network(self, network_range):
        print(f"[*] Scansione della rete {network_range} in corso...")
        self.nm.scan(hosts=network_range, arguments='-sn -PR')
        
        print(f"\n{'IP':<15} | {'HOSTNAME':<20} | {'MAC ADDRESS':<18} | {'VENDOR'}")
        print("-" * 75)

        for host in self.nm.all_hosts():
            ip = host
            hostname = self.nm[host].hostname() if self.nm[host].hostname() else "Sconosciuto"
            
            # Recupero MAC e Vendor
            mac = "Non rilevato"
            vendor = "Sconosciuto"
            
            if 'addresses' in self.nm[host]:
                addrs = self.nm[host]['addresses']
                if 'mac' in addrs:
                    mac = addrs['mac']
                    vendor = self.nm[host].get('vendor', {}).get(mac, "Vendor Generico")

            print(f"{ip:<15} | {hostname:<20} | {mac:<18} | {vendor}")

    def scan_ports(self, ip):
        print(f"\n" + "="*50 + f"\n SCAN DETTAGLIATO PORTE: {ip}\n" + "="*50)
        self.nm.scan(ip, arguments='-sV --version-intensity 0')
        
        if ip not in self.nm.all_hosts():
            print(f"[!] L'host {ip} non risponde.")
            return

        for proto in self.nm[ip].all_protocols():
            print(f"\n--- Protocollo: {proto.upper()} ---")

            ports = sorted(self.nm[ip][proto].keys())
            
            print(f"{'PORTA':<8} | {'STATO':<10} | {'SERVIZIO':<15} | {'VERSIONE'}")
            print("-" * 60)
            
            for port in ports:
                state = self.nm[ip][proto][port]['state']
                service = self.nm[ip][proto][port]['name']
                product = self.nm[ip][proto][port].get('product', 'N/D')
                version = self.nm[ip][proto][port].get('version', '')
                
                full_version = f"{product} {version}".strip() or "Sconosciuta"
                
                print(f"{port:<8} | {state:<10} | {service:<15} | {full_version}")


        print("\n[*] Analisi completata.")

    def ping_test(self, ip, count=4):
        print(f"[*] Ping test su {ip}...")
        
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, str(count), ip]

        try:
            processo = subprocess.run(command, capture_output=True, text=True, shell=True)
            if processo.returncode == 0:
                print(f"[+] Risposta ricevuta da {ip}:")
                linee = processo.stdout.splitlines()
                for linea in linee:
                    if "ms" in linea.lower():
                        print(f"    {linea.strip()}")
                return True
            else:
                print(f"[!] L'host {ip} non risponde (Richiesta scaduta).")
                return False
                
        except Exception as e:
            print(f"[!] Errore tecnico durante il ping: {e}")
            return False

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

    def run_speedtest(self):
        print("[*] Avvio Speed Test (potrebbe richiedere un minuto)...")
        try:
            # Aggiungiamo secure=True per evitare blocchi HTTP
            st = speedtest.Speedtest(secure=True) 
            st.get_best_server()
            
            download = st.download() / 1_000_000  # Mbps
            upload = st.upload() / 1_000_000      # Mbps
            ping = st.results.ping

            print(f"\n[+] RISULTATI:")
            print(f" > Download: {download:.2f} Mbps")
            print(f" > Upload: {upload:.2f} Mbps")
            print(f" > Ping: {ping} ms")

        except Exception as e:
            print(f"[!] Errore durante lo Speedtest: {e}")
            print("[i] Consiglio: Prova a fare 'pip install --upgrade speedtest-cli'")

    def detect_arp_spoofing(self):
        print("\n" + "!"*10 + " SECURITY CHECK: ARP SPOOFING " + "!"*10)
        
        hosts = self.nm.all_hosts()
        mac_database = {} # Dizionario {MAC: IP}
        alerts_found = False

        for ip in hosts:
            if 'addresses' in self.nm[ip] and 'mac' in self.nm[ip]['addresses']:
                mac = self.nm[ip]['addresses']['mac']
                
                # Se il MAC è già nel database ma con un IP diverso...
                if mac in mac_database and mac_database[mac] != ip:
                    print(f"\n[🚨 ALERT] POSSIBILE ATTACCO MITM RILEVATO!")
                    print(f" > Il MAC Address [{mac}] è associato a due IP:")
                    print(f"   1. {mac_database[mac]}")
                    print(f"   2. {ip}")
                    print(f" [!] Qualcuno sta eseguendo ARP Poisoning nella rete.")
                    alerts_found = True
                else:
                    mac_database[mac] = ip
        
        if not alerts_found:
            print("[✓] Nessun conflitto ARP rilevato. La tabella dei MAC è coerente.")
        
        print("!"*50)
        return alerts_found

    def live_monitor_worker(self, network_range, interval=10):
        """Questa funzione gira in background nel thread e scrive sul log"""
        
        # 1. Scansione iniziale (Baseline)
        try:
            self.nm.scan(hosts=network_range, arguments='-sn -PR')
            known_devices = {}
            for host in self.nm.all_hosts():
                mac = self.nm[host].get('addresses', {}).get('mac', 'N/A')
                hostname = self.nm[host].hostname() or "Sconosciuto"
                known_devices[host] = {"mac": mac, "name": hostname}

            self.log_event("SISTEMA", f"Monitoraggio avviato su {network_range}. Dispositivi iniziali: {len(known_devices)}")
        except Exception as e:
            self.log_event("ERRORE INIZIALE", f"Impossibile avviare scansione: {e}")
            return

        while True:
            try:
                time.sleep(interval)
                self.nm.scan(hosts=network_range, arguments='-sn -PR')
                current_hosts = self.nm.all_hosts()

                for ip in current_hosts:
                    if ip not in known_devices:
                        mac = self.nm[ip].get('addresses', {}).get('mac', 'N/A')
                        hostname = self.nm[ip].hostname() or "Sconosciuto"
                        vendor = self.nm[ip].get('vendor', {}).get(mac, "Generico")
                        
                        msg = f" > IP: {ip}\n > MAC: {mac}\n > Host: {hostname}\n > Vendor: {vendor}"
                        self.log_event("ONLINE", msg)
                        known_devices[ip] = {"mac": mac, "name": hostname}

                to_remove = []
                for ip, info in known_devices.items():
                    if ip not in current_hosts:
                        msg = f" > IP: {ip}\n > MAC: {info['mac']}\n > Host: {info['name']}"
                        self.log_event("OFFLINE", msg)
                        to_remove.append(ip)
                
                for ip in to_remove:
                    del known_devices[ip]
                    
            except Exception as e:
                self.log_event("ERRORE MONITOR", str(e))
                time.sleep(5) 