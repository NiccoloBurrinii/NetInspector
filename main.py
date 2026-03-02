import os
import threading
import time

from core import NetInspector
from config import NETWORK_RANGE

def main():
    inspector = NetInspector()
    print(f"[*] Rete rilevata: {NETWORK_RANGE}")

    # 1. Inizializzazione Log
    if not os.path.exists("network_events.log"):
        with open("network_events.log", "w") as f:
            f.write("--- LOG INIZIALIZZATO ---\n")
    else:
        # Se il file esiste già, aggiungiamo una riga di separazione per la nuova sessione
        inspector.log_event("SISTEMA", ">>> NUOVA SESSIONE AVVIATA <<<")

    # 2. Avvio finestra esterna e Thread (come prima)
    os.system('start powershell.exe -NoExit -Command "Get-Content network_events.log -Wait"')
    
    monitor_thread = threading.Thread(
        target=inspector.live_monitor_worker, 
        args=(NETWORK_RANGE, 10), 
        daemon=True
    )
    monitor_thread.start()

    try:
        print(f"[*] Monitoraggio attivo su {NETWORK_RANGE}")
        print("[*] Controlla la finestra PowerShell esterna per i log live.")
        
        while True:
            print("\n" + "="*30)
            print("      NETINSPECTOR PRO")
            print("="*30)
            print("1. Scansione Rete (Discovery)")
            print("2. Ping Test (Latenza/Stato)")
            print("3. Scansione Porte (Service Detection)")
            print("4. Speed Test (Internet Performance)")
            print("5. Monitoraggio Host (Real-time)")
            print("6. Security Check (ARP Spoofing Detector)")
            print("0. Esci")
            
            choice = input("\nScegli un'opzione: ")
            
            if choice == '1':
                inspector.scan_network(NETWORK_RANGE)
            elif choice == '2':
                ip = input("Inserisci l'IP da testare: ")
                inspector.ping_test(ip)
            elif choice == '3':
                ip = input("Inserisci IP per analisi porte: ")
                inspector.scan_ports(ip)
            elif choice == '4':
                inspector.run_speedtest()
            elif choice == '5':
                ip = input("Inserisci l'IP da monitorare: ")
                inspector.monitor_host(ip)
            elif choice == '6':
                inspector.detect_arp_spoofing()
            elif choice == '0':
                print("Chiusura...")
                break
            else:
                print("Scelta non valida.")
    except KeyboardInterrupt:
        print("\n[!] Interruzione rilevata.")
    
    finally:
        print("[*] Salvataggio stato finale nel log...")
        inspector.log_event("SISTEMA", "--- LOG TERMINATO / MONITORAGGIO CHIUSO ---")
        time.sleep(1)

if __name__ == "__main__":
    main()