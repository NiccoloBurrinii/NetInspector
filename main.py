import os
import platform
import threading
import time
from core import NetInspector
from config import NETWORK_RANGE

def main():
    # Inizializzazione NetInspector e rilevamento rete
    inspector = NetInspector()
    print(f"[*] Rete rilevata: {NETWORK_RANGE}")

    # Apre il log in una finestra PowerShell separata
    if not os.path.exists("network_events.log"):
        with open("network_events.log", "w") as f:
            f.write("--- LOG INIZIALIZZATO ---\n")
    else:
        inspector.log_event("SISTEMA", ">>> NUOVA SESSIONE AVVIATA <<<")

    # Comando di sistema per lanciare PowerShell con 'Wait' (dashboard live)
    #os.system('start powershell.exe -NoExit -Command "Get-Content network_events.log -Wait"')
    sistema = platform.system().lower()

    if sistema == "windows":
        os.system(f'start powershell.exe -NoExit -Command "Get-Content {"network_events.log"} -Wait"')
    elif sistema == "linux":
        # Prova ad aprire il terminale Gnome (comune su Ubuntu/Kali)
        os.system(f'gnome-terminal -- bash -c "tail -f {"network_events.log"}"; exec bash" &')

    # Lancio del monitor in background come DAEMON thread
    monitor_thread = threading.Thread(
        target=inspector.live_monitor_worker, 
        args=(NETWORK_RANGE, 5), 
        daemon=True
    )
    monitor_thread.start()

    try:
        print(f"[*] Monitoraggio attivo su {NETWORK_RANGE}")
        print("[*] Controlla la finestra PowerShell esterna per i log live.")
        
        while True:
            print("\n" + "="*30 + "\n      NETINSPECTOR      \n" + "="*30)
            print("1. Scansione Rete\n2. Ping Test\n3. Scansione Porte\n4. Speed Test\n5. Monitoraggio Host (Real-time)\n6. Security Check (ARP Spoofing Detector)\n0. Esci")
            
            choice = input("\nScegli un'opzione: ")
            
            if choice == '1': inspector.scan_network(NETWORK_RANGE)
            elif choice == '2': inspector.ping_test(input("IP: "))
            elif choice == '3': inspector.scan_ports(input("IP: "))
            elif choice == '4': inspector.run_speedtest()
            elif choice == '5': inspector.monitor_host(input("IP: "))
            elif choice == '6': inspector.detect_arp_spoofing()
            elif choice == '0': break
            else: print("Scelta non valida.")
    except KeyboardInterrupt: pass
    
    finally:
        inspector.log_event("SISTEMA", "--- LOG TERMINATO / MONITORAGGIO CHIUSO ---")
        time.sleep(1)

if __name__ == "__main__":
    main()