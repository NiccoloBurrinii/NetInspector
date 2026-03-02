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

    def run_speedtestt(self):   #
        print("\n[*] Preparazione Speed Test in corso...")
        try:
            st = speedtest.Speedtest(secure=True)
            print("[*] Ricerca del miglior server disponibile...")
            st.get_best_server()
            
            def display_progress(status_msg):
                print(f"\r[ℹ] {status_msg}...", end="", flush=True)

            display_progress("Test DOWNLOAD in corso")
            download = st.download() / 1_000_000
            
            display_progress("Test UPLOAD in corso  ")
            upload = st.upload() / 1_000_000
            
            ping = st.results.ping

            print("\r" + " " * 50 + "\r", end="") 
            print(f"Speed Test Completato!")
            print(f"\n" + "═"*30)
            print(f" -DOWNLOAD: {download:.2f} Mbps")
            print(f" -UPLOAD:   {upload:.2f} Mbps")
            print(f" -PING:     {ping:.1f} ms")
            print("═"*30)

        except Exception as e:
            print(f"\n[!] Errore durante lo Speedtest: {e}")

    def run_speedtest(self):    #migliorata con barra di progresso e risultati più chiari
        import sys

        def draw_progress_bar(percent, label=""):
            """Disegna una barra di caricamento professionale in console"""
            bar_length = 30
            filled_length = int(round(bar_length * percent / 100))
            bar = '█' * filled_length + '-' * (bar_length - filled_length)
            sys.stdout.write(f'\r[*] {label:15} |{bar}| {percent:>3}%')
            sys.stdout.flush()

        print("\n" + "═"*50 + "\n   AVVIO SPEED TEST INTERATTIVO\n" + "═"*50)
        
        try:
            st = speedtest.Speedtest(secure=True)
            
            # Step 1: Server
            draw_progress_bar(10, "Ricerca Server")
            st.get_best_server()
            draw_progress_bar(25, "Server Trovato")
            time.sleep(0.5)

            # Step 2: Download
            # Simuliamo l'avanzamento durante l'inizio del test
            for i in range(26, 45): 
                draw_progress_bar(i, "Test Download")
                time.sleep(0.05)
            
            download = st.download() / 1_000_000
            draw_progress_bar(60, "Download OK")

            # Step 3: Upload
            for i in range(61, 85):
                draw_progress_bar(i, "Test Upload")
                time.sleep(0.05)

            upload = st.upload() / 1_000_000
            draw_progress_bar(100, "Completato!")
            
            ping = st.results.ping

            # Risultati Finali
            print(f"\n\n" + "📊 RISULTATI FINALI:")
            print(f" > DOWNLOAD: {download:.2f} Mbps")
            print(f" > UPLOAD:   {upload:.2f} Mbps")
            print(f" > PING:     {ping:.1f} ms")
            print("═"*50 + "\n")

            # Log
            self.log_event("SPEEDTEST", f"DL: {download:.2f} Mbps | UL: {upload:.2f} Mbps | Ping: {ping}ms")

        except Exception as e:
            print(f"\n[!] Errore: {e}")

    def detect_arp_spoofing(self):
        print("\n" + "!"*10 + " SECURITY CHECK: ARP SPOOFING " + "!"*10)
        
        hosts = self.nm.all_hosts()
        mac_database = {} # Dizionario {MAC: IP}
        alerts_found = False

        for ip in hosts:
            if 'addresses' in self.nm[ip] and 'mac' in self.nm[ip]['addresses']:
                mac = self.nm[ip]['addresses']['mac']
                
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