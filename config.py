import psutil
import ipaddress
import socket

def get_real_network_range():
    """
    Rileva dinamicamente la configurazione di rete locale.
    Evita di dover cablare a mano l'IP nel codice.
    """
    try:
        # Crea un socket UDP per determinare l'interfaccia di rete attiva
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Non invia dati, serve solo a interrogare la tabella di routing del sistema
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Itera sulle interfacce di rete per trovare la Netmask associata all'IP locale
        addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in addrs.items():
            for addr in interface_addresses:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    netmask = addr.netmask
                    # Calcola il network range in formato CIDR (es. 192.168.1.0/24)
                    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                    return str(network)
        
        return f"{local_ip}/24" # Fallback se non trova la maschera
    except Exception as e:
        print(f"[!] Errore rilevamento rete: {e}")
        return "127.0.0.1/32"

NETWORK_RANGE = get_real_network_range()

