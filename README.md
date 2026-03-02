# 🛡️ NetInspector: Network Security & Monitoring Tool

**NetInspector** è una soluzione avanzata per la sicurezza e l'analisi di rete sviluppata in Python. Il software combina strumenti di scansione passiva e attiva con un sistema di monitoraggio in tempo reale (IDS) per la protezione dei perimetri domestici e aziendali.

---

## Caratteristiche Principali

### 1. Monitoraggio Live Multi-finestra
Il tool utilizza il **Multithreading** per avviare una console separata che monitora costantemente gli accessi alla rete. Ogni volta che un dispositivo entra o esce dalla rete, l'evento viene visualizzato in diretta.

### 2. Logging Forense (Audit Trail)
Ogni azione, scansione e rilevamento viene salvata nel file `network_events.log`. La gestione dei file è ottimizzata con `fsync` per garantire la persistenza dei dati anche in caso di crash improvviso.

### 3. Network & Port Scanning
- **Network Discovery:** Identifica IP, Hostname, MAC Address e Vendor dei dispositivi connessi.
- **Port Analysis:** Scansiona le porte aperte e tenta di identificare la versione dei servizi (Banner Grabbing) per trovare vulnerabilità.

### 4. Security Check (ARP Spoofing)
Analizza la tabella ARP alla ricerca di conflitti MAC-IP, segnalando potenziali attacchi **Man-In-The-Middle (MITM)**.

### 5. Performance Test
Integrazione con i server Ookla per misurare la velocità di Download, Upload e la latenza (Ping) della connessione.

---

## Requisiti Tecnici

### Software Necessario
* **Python 3.10+**
* **Nmap (Binary):** Il motore Nmap deve essere installato sul sistema e configurato nelle variabili d'ambiente (PATH).

### Installazione Dipendenze
Installa le librerie Python necessarie tramite il file requirements:
```bash
pip install -r requirements.txt
