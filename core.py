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
            print("[*] Motore Nmap inizializzato con successo.")
        except Exception as e:
            print(f"[!] Errore inizializzazione Nmap: {e}")
            print("[i] Assicurati che Nmap sia installato nel sistema.")

    def scan_network(self, network_range):
        print(f"[*] Scansione della rete {network_range} in corso...")
        # -sn: Ping scan (discovery)
        # -PR: ARP discovery (il modo più veloce per avere i MAC in LAN)
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
                # Nmap mette il MAC dentro il dizionario 'mac' se lo trova
                if 'mac' in addrs:
                    mac = addrs['mac']
                    # Se trova il MAC, Nmap prova a cercare il Vendor nel suo database
                    vendor = self.nm[host].get('vendor', {}).get(mac, "Vendor Generico")

            print(f"{ip:<15} | {hostname:<20} | {mac:<18} | {vendor}")

    def scan_ports(self, ip):
        print(f"\n" + "="*50)
        print(f" SCAN DETTAGLIATO PORTE: {ip}")
        print("="*50)
        
        # -sV: Tenta di capire la versione del servizio (es. Apache 2.4)
        # --version-intensity 0: Lo rende più veloce
        self.nm.scan(ip, arguments='-sV --version-intensity 0')
        
        if ip not in self.nm.all_hosts():
            print(f"[!] L'host {ip} non risponde. Potrebbe esserci un firewall.")
            return

        for proto in self.nm[ip].all_protocols():
            print(f"\n--- Protocollo: {proto.upper()} ---")
            
            # Ordiniamo le porte numericamente
            ports = sorted(self.nm[ip][proto].keys())
            
            print(f"{'PORTA':<8} | {'STATO':<10} | {'SERVIZIO':<15} | {'VERSIONE'}")
            print("-" * 60)
            
            for port in ports:
                state = self.nm[ip][proto][port]['state']
                
                # Recuperiamo le informazioni sul servizio
                service = self.nm[ip][proto][port]['name']
                product = self.nm[ip][proto][port].get('product', 'N/D')
                version = self.nm[ip][proto][port].get('version', '')
                
                # Formattiamo l'output
                full_version = f"{product} {version}".strip() or "Sconosciuta"
                
                print(f"{port:<8} | {state:<10} | {service:<15} | {full_version}")

            res_log = f" > Target: {ip}\n > Risultato: Scansione porte completata."
            self.log_event("PORT SCAN", res_log)

        print("\n[*] Analisi completata.")

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

    def ping_test(self, ip, count=4):
        print(f"[*] Ping test su {ip}...")
        
        # Determina il parametro corretto (-n su Windows, -c su Linux/Mac)
        param = "-n" if platform.system().lower() == "windows" else "-c"
        
        # Costruiamo il comando come una lista per evitare errori di shell
        command = ["ping", param, str(count), ip]
        
        try:
            # shell=True aiuta Python a trovare il comando 'ping' nelle variabili d'ambiente di Windows
            processo = subprocess.run(command, capture_output=True, text=True, shell=True)
            
            if processo.returncode == 0:
                print(f"[+] Risposta ricevuta da {ip}:")
                # Estraiamo solo le righe con i tempi (ms) per pulire l'output
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

    def log_event(self, category, message):
        """Scrive qualsiasi tipo di evento nel log con Categoria e Timestamp"""
        timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        log_entry = f"[{category}] {timestamp}\n{message}\n" + "-"*40 + "\n"
        
        try:
            with open("network_events.log", "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"[!] Errore salvataggio log: {e}")

    def run_speedtest(self):
        print("[*] Avvio Speed Test (potrebbe richiedere un minuto)...")
        st = speedtest.Speedtest()
        st.get_best_server()
        
        download = st.download() / 1_000_000  # Mbps
        upload = st.upload() / 1_000_000      # Mbps
        ping = st.results.ping

        speed_log = f" > Download: {download:.2f} Mbps\n > Upload: {upload:.2f} Mbps\n > Ping: {ping} ms"
        self.log_event("SPEED TEST", speed_log)
        
        print(f"\n[+] RISULTATI:")
        print(f" > Download: {download:.2f} Mbps")
        print(f" > Upload: {upload:.2f} Mbps")
        print(f" > Ping: {ping} ms")

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
        
        mitm_log = f"🚨 ATTENZIONE: Rilevato conflitto MAC su {mac}!\n > IP coinvolti: {ip1}, {ip2}"
        self.log_event("SECURITY ALERT", mitm_log)

        print("!"*50)
        return alerts_found
    
    def live_network_monitor(self, network_range, interval=15):
        """Funzione che gira in background e logga tutto"""
        # Baseline iniziale
        self.nm.scan(hosts=network_range, arguments='-sn -PR')
        known_devices = {host: (self.nm[host].hostname() or "Sconosciuto") 
                         for host in self.nm.all_hosts()}

        try:
            while True:
                time.sleep(interval)
                self.nm.scan(hosts=network_range, arguments='-sn -PR')
                current_hosts = self.nm.all_hosts()
                
                # --- LOGICA NUOVI ACCESSI ---
                for ip in current_hosts:
                    if ip not in known_devices:
                        mac = self.nm[ip].get('addresses', {}).get('mac', 'N/A')
                        hostname = self.nm[ip].hostname() or "Sconosciuto"
                        vendor = self.nm[ip].get('vendor', {}).get(mac, "Generico")
                        
                        event_msg = (f"[🟢 ONLINE] IP: {ip} | MAC: {mac}\n"
                                     f" > Hostname: {hostname} | Vendor: {vendor}")
                        
                        # Scrive nel file senza interrompere il tuo menu
                        self.log_event("BACKGROUND MONITOR", event_msg)
                        known_devices[ip] = hostname

                # --- LOGICA DISCONNESSIONI ---
                to_remove = []
                for ip, name in known_devices.items():
                    if ip not in current_hosts:
                        event_msg = f"[🔴 OFFLINE] IP: {ip} ({name}) è uscito dalla rete."
                        self.log_event("BACKGROUND MONITOR", event_msg)
                        to_remove.append(ip)
                
                for ip in to_remove:
                    del known_devices[ip]

        except Exception as e:
            self.log_event("ERRORE MONITOR", str(e))