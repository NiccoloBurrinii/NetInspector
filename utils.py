import socket
import requests

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_vendor(mac):
    """Interroga un'API per trovare il produttore dal MAC Address"""
    if mac == "Unknown":
        return "Unknown"
    try:
        # API gratuita che restituisce il nome del produttore
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if response.status_code == 200:
            return response.text
        return "Unknown Vendor"
    except:
        return "Lookup Error"