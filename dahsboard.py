from flask import Flask, render_template
import mysql.connector
from config import DB_CONFIG

app = Flask(__name__)

def get_data():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    # Prendiamo gli ultimi host trovati con il loro produttore
    cursor.execute("""
        SELECT ip, hostname, mac_address, vendor 
        FROM hosts 
        WHERE scan_id = (SELECT MAX(id) FROM scans)
    """)
    data = cursor.fetchall()
    conn.close()
    return data

@app.route('/')
def index():
    hosts = get_data()
    return render_template('index.html', hosts=hosts)

if __name__ == '__main__':
    print("[*] Dashboard avviata su http://127.0.0.1:5000")
    app.run(debug=True)