from core import NetInspector
from config import NETWORK_RANGE

def main():
    inspector = NetInspector()
    print(f"[*] Rete rilevata: {NETWORK_RANGE}")
    
    while True:
        print("\n" + "="*30)
        print("      NETINSPECTOR PRO")
        print("="*30)
        print("1. Scansione Rete (Discovery)")
        print("2. Ping Test (Latenza/Stato)")
        print("3. Scansione Porte (Service Detection)")
        print("4. Speed Test (Internet Performance)")
        print("5. Monitoraggio Host (Real-time)")
        print("6. Genera Report Finale (da implementare)")
        print("7. Security Check (ARP Spoofing Detector)")
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
            print("[*] Funzione di generazione report non ancora implementata.")
        elif choice == '7':
            inspector.detect_arp_spoofing()
        elif choice == '0':
            print("Chiusura...")
            break
        else:
            print("Scelta non valida.")

if __name__ == "__main__":
    main()