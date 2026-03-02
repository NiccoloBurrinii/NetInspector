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

    def generate_report(self):
        """Crea un file TXT con il riepilogo dell'ultima scansione o dei dati nel DB"""
        filename = f"report_network_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Qui potresti recuperare i dati dal Database invece che ricanalizzare
        try:
            with open(filename, "w") as f:
                f.write("="*40 + "\n")
                f.write(f" NETINSPECTOR - REPORT AUTOMATICO\n")
                f.write(f" Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                f.write("="*40 + "\n\n")
                
                # Se il DB è collegato, qui faremmo una SELECT
                f.write("[+] SUGGERIMENTI DI SICUREZZA:\n")
                f.write("- Chiudi la porta 21 (FTP) se non necessaria.\n")
                f.write("- Assicurati che SSH (22) usi chiavi e non password.\n")
                
            print(f"[+] Report generato con successo: {filename}")
        except Exception as e:
            print(f"[!] Errore generazione report: {e}")

    def run_speedtest(self):
        print("[*] Avvio Speed Test (potrebbe richiedere un minuto)...")
        st = speedtest.Speedtest()
        st.get_best_server()
        
        download = st.download() / 1_000_000  # Mbps
        upload = st.upload() / 1_000_000      # Mbps
        ping = st.results.ping
        
        print(f"\n[+] RISULTATI:")
        print(f" > Download: {download:.2f} Mbps")
        print(f" > Upload: {upload:.2f} Mbps")
        print(f" > Ping: {ping} ms")