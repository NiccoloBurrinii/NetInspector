from scanner import run_network_scan
from port_scanner import run_port_scan
from monitor import start_monitoring
from config import NETWORK

def main():
    hosts_cache = [] # Memorizza gli host trovati nell'ultima scansione
    
    while True:
        print("\n" + "="*30)
        print("    NETINSPECTOR PRO v1.0")
        print("="*30)
        print("1. Scansione Rete (Threaded)")
        print("2. Analisi Porte (Host specifico)")
        print("3. Monitoraggio Host (Real-time)")
        print("0. Esci")
        
        scelta = input("\nScegli un'opzione: ")

        if scelta == "1":
            hosts_cache = run_network_scan(NETWORK)
            print(f"\n[OK] Trovati {len(hosts_cache)} dispositivi attivi.")

        elif scelta == "2":
            if not hosts_cache:
                print("[!] Errore: Esegui prima la scansione rete (Opzione 1).")
                continue
            ip = input("Inserisci l'IP del dispositivo da analizzare: ")
            target = next((h for h in hosts_cache if h['ip'] == ip), None)
            if target:
                run_port_scan(target['ip'], target['id'])
            else:
                print("[!] IP non trovato nell'ultima scansione.")

        elif scelta == "3":
            ip = input("Inserisci IP da monitorare: ")
            start_monitoring(ip)

        elif scelta == "0":
            print("Chiusura programma...")
            break

if __name__ == "__main__":
    main()