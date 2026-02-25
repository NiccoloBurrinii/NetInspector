import os
import time
from db_logger import logger
from config import MONITOR_INTERVAL

def start_monitoring(ip):
    print(f"[*] Monitoraggio LIVE di {ip} (CTRL+C per uscire)...")
    last_status = None
    try:
        while True:
            # Comando ping diverso tra Windows e Linux
            param = "-n" if os.name == "nt" else "-c"
            is_up = os.system(f"ping {param} 1 {ip} > nul 2>&1") == 0
            current_status = "ONLINE" if is_up else "OFFLINE"
            
            if current_status != last_status:
                logger.log_event(ip, current_status)
                print(f"[EVENTO] {ip} è ora {current_status}")
                last_status = current_status
            time.sleep(MONITOR_INTERVAL)
    except KeyboardInterrupt:
        print("\n[*] Monitoraggio interrotto.")