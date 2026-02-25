import mysql.connector
from config import DB_CONFIG

try:
    conn = mysql.connector.connect(**DB_CONFIG)
    if conn.is_connected():
        print("✅ CONNESSIONE RIUSCITA! Il database risponde correttamente.")
        conn.close()
except Exception as e:
    print(f"❌ ERRORE: {e}")