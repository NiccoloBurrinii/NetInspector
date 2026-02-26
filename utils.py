import socket
import requests

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_vendor(mac):
    if mac == "Unknown" or not mac: return "Unknown"
    try:
        # Usiamo un'API di backup se la prima fallisce
        res = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return res.text if res.status_code == 200 else "Generic Device"
    except:
        return "Generic Device"

def identify_device_type(open_ports, vendor):
    """Logica di identificazione basata su porte e produttore"""
    vendor = vendor.lower()
    
    if 631 in open_ports or 9100 in open_ports: return "Stampante"
    if 8009 in open_ports or "google" in vendor: return "Chromecast/Google Home"
    if 62078 in open_ports or "apple" in vendor: return "Dispositivo Apple (iPhone/iPad)"
    if 5000 in open_ports or 5001 in open_ports: return "NAS / Server"
    if 22 in open_ports and "raspberry" in vendor: return "Raspberry Pi"
    if 445 in open_ports: return "PC Windows / Server"
    if 80 in open_ports or 443 in open_ports: return "Router / Interfaccia Web"
    
    return "Dispositivo Generico"