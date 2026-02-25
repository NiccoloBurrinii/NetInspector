# utils.py
import socket

def get_hostname(ip):
    """Tenta di risolvere l'hostname di un indirizzo IP"""
    try:
        # gethostbyaddr restituisce una tupla, prendiamo il primo elemento [0]
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, IndexError):
        return "Unknown"