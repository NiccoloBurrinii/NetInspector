# Impostazioni di Rete
NETWORK = "192.168.1.0/24"  # Controlla che il tuo router usi questa classe (es. 192.168.1.1)
PORTS = [21, 22, 80, 443, 3306, 8080]
TIMEOUT = 0.3
MONITOR_INTERVAL = 5

# Credenziali Database
DB_CONFIG = {
    'host': '127.0.0.1', 
    'user': 'netuser',
    'password': 'password123',
    'database': 'netinspector'
}