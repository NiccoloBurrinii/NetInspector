import psutil
import ipaddress
import socket

def get_real_network_range():
    try:
        # 1. Troviamo l'IP che il PC usa per andare su internet
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # 2. Cerchiamo la netmask associata a quell'IP tra tutte le schede di rete
        addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in addrs.items():
            for addr in interface_addresses:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    netmask = addr.netmask
                    # Creiamo il network reale (es. 172.20.10.0/28)
                    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                    return str(network)
        
        return f"{local_ip}/24" # Fallback se non trova la maschera
    except Exception as e:
        print(f"[!] Errore rilevamento rete: {e}")
        return "127.0.0.1/32"

# Ora NETWORK_RANGE è dinamico e preciso al 100%
NETWORK_RANGE = get_real_network_range()

