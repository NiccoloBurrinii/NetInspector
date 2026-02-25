import socket
from config import PORTS, TIMEOUT
from db_logger import logger

def run_port_scan(ip, host_id):
    print(f"[*] Analisi porte su {ip}...")
    found_count = 0
    for port in PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((ip, port)) == 0:
            print(f"  [!] APERTA: {port}")
            logger.log_port_found(host_id, port)
            found_count += 1
        s.close()
    print(f"[*] Analisi completata: {found_count} porte aperte.")