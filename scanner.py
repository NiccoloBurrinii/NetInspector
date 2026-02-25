from scapy.all import ARP, Ether, srp
from utils import get_hostname
from db_logger import logger
import ipaddress

def run_network_scan(network):
    print(f"\n[*] Avvio scansione ARP professionale su {network}...")
    scan_id = logger.log_scan_start(network)
    found_hosts = []

    try:
        # 1. Creiamo il pacchetto ARP (Who has IP?)
        # Ether(dst="ff:ff:ff:ff:ff:ff") invia il pacchetto in broadcast a tutti
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # 2. Inviamo il pacchetto e aspettiamo le risposte
        # timeout: quanto aspettare la risposta, inter: intervallo tra pacchetti
        print("[*] Invio pacchetti ARP in corso...")
        answered_list = srp(packet, timeout=2, verbose=False)[0]

        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc # Possiamo anche loggare il MAC address se vogliamo!
            
            name = get_hostname(ip)
            
            # Salvataggio nel database
            host_id = logger.log_host_found(scan_id, ip, name)
            
            found_hosts.append({'ip': ip, 'hostname': name, 'id': host_id})
            print(f"[+] DISPOSITIVO TROVATO: {ip} | MAC: {mac} | Host: {name}")

    except Exception as e:
        print(f"[!] Errore durante la scansione Scapy: {e}")
        print("[i] Assicurati di eseguire il terminale come AMMINISTRATORE.")

    return found_hosts