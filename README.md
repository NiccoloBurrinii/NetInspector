# 🛡️ NetInspector Pro

**NetInspector Pro** è uno strumento di analisi di rete sviluppato in Python. Permette di effettuare il discovery dei dispositivi attivi, la scansione dettagliata delle porte (Service Detection) e il monitoraggio in tempo reale degli host.

Il software è progettato per adattarsi automaticamente alla rete a cui è connesso, rilevando IP e Netmask senza configurazione manuale.

---

## 🚀 Caratteristiche Principali

* **Network Discovery Automatico**: Rileva l'interfaccia di rete attiva e calcola il range di scansione (CIDR) tramite l'IP e la Subnet Mask del sistema.
* **Port Scanning Intelligente**: Identifica le porte aperte e i servizi associati utilizzando il motore `Nmap`.
* **Rilevamento Anomalie**: Confronta i servizi rilevati con un database standard (`services.json`) per segnalare potenziali camuffamenti (es. un database sulla porta 80).
* **Live Monitoring**: Funzione di monitoraggio continuo dello stato Online/Offline di un host specifico.
* **Modularità**: Architettura divisa in `config`, `core` e `main` per una facile manutenzione.

---

## 🛠️ Requisiti Installazione

### 1. Requisito di Sistema
Il software richiede **Nmap** installato nel sistema operativo.
* Scarica Nmap da: [https://nmap.org/download.html](https://nmap.org/download.html)
* *Nota: Durante l'installazione su Windows, assicurati di spuntare la voce "Add Nmap to the system PATH".*

### 2. Librerie Python
Installa le dipendenze necessarie tramite terminale:
```bash
pip install python-nmap psutil