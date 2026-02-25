import mysql.connector
from config import DB_CONFIG

class DBLogger:
    def _connect(self):
        return mysql.connector.connect(**DB_CONFIG)

    def log_scan_start(self, network):
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (network) VALUES (%s)", (network,))
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return last_id

    def log_host_found(self, scan_id, ip, hostname):
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO hosts (scan_id, ip, hostname) VALUES (%s, %s, %s)", (scan_id, ip, hostname))
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return last_id

    def log_port_found(self, host_id, port):
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO ports (host_id, port) VALUES (%s, %s)", (host_id, port))
        conn.commit()
        conn.close()

    def log_event(self, ip, status):
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO events (ip, status) VALUES (%s, %s)", (ip, status))
        conn.commit()
        conn.close()

logger = DBLogger()