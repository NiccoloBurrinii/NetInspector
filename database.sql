CREATE DATABASE IF NOT EXISTS netinspector;
USE netinspector;

-- Tabella per l'anagrafica dei dispositivi
CREATE TABLE IF NOT EXISTS devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(50) UNIQUE,
    hostname VARCHAR(100),
    mac_address VARCHAR(17),
    vendor VARCHAR(100),
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabella per i risultati delle scansioni porte
CREATE TABLE IF NOT EXISTS scan_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT,
    port INT,
    protocol VARCHAR(10),
    status VARCHAR(50),
    service VARCHAR(100),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

-- Tabella per il log degli eventi (Online/Offline)
CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(50),
    event VARCHAR(100),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);