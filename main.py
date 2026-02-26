from core import NetInspector
from config import NETWORK_RANGE

def main():
    inspector = NetInspector()
    
    while True:
        print("\n" + "="*30)
        print("      NETINSPECTOR PRO")
        print("="*30)
        print("1. Scansione Rete (Discovery)")
        print("2. Analisi Porte (Service Detection)")
        print("3. Monitoraggio Host (Real-time)")
        print("0. Esci")
        
        choice = input("\nScegli un'opzione: ")
        
        if choice == '1':
            inspector.scan_network(NETWORK_RANGE)
        elif choice == '2':
            ip = input("Inserisci l'IP da analizzare: ")
            inspector.scan_ports(ip)
        elif choice == '3':
            ip = input("Inserisci l'IP da monitorare: ")
            inspector.monitor_host(ip)
        elif choice == '0':
            print("Chiusura...")
            break
        else:
            print("Scelta non valida.")

if __name__ == "__main__":
    main()