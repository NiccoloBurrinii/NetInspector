from scapy.all import ARP, Ether, srp
from utils import get_hostname, get_vendor
from db_logger import logger
import ipaddress
import socket

def run_network_scan(network):
    print(f"\n[*] Avvio scansione con riconoscimento Vendor su {network}...")
    scan_id = logger.log_scan_start(network)
    found_hosts = {}

    # --- FASE 1: ARP SCAN (MAC + Vendor) ---
    try:
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered_list = srp(packet, timeout=3, verbose=False, retry=2)[0]

        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc.upper()
            
            name = get_hostname(ip)
            vendor = get_vendor(mac) # Scopre la marca!
            
            host_id = logger.log_host_found(scan_id, ip, name, mac, vendor)
            found_hosts[ip] = {'hostname': name, 'id': host_id}
            
            print(f"[+] TROVATO: {ip} | {mac} | {vendor} ({name})")
            
    except Exception as e:
        print(f"[!] Errore Scapy (Amministratore?): {e}")

    # --- FASE 2: TCP CHECK (Per i silenti) ---
    print("[*] Ricerca dispositivi nascosti...")
    for ip in ipaddress.IPv4Network(network):
        addr = str(ip)
        if addr not in found_hosts:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            if s.connect_ex((addr, 80)) == 0:
                name = get_hostname(addr)
                host_id = logger.log_host_found(scan_id, addr, name, "Unknown", "Unknown")
                found_hosts[addr] = {'hostname': name, 'id': host_id}
                print(f"[+] TROVATO (TCP): {addr} - {name}")
            s.close()

    return list(found_hosts.items())