# Windows FTP Sync Service

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6.svg)](#)
[![Language: C++](https://img.shields.io/badge/Language-C++-00599C.svg)](#)
[![Version](https://img.shields.io/badge/Version-2.1--Enterprise-green.svg)](#)

> **[IT]** Un servizio Windows robusto e ad alte prestazioni scritto in C++ per la sincronizzazione bidirezionale di file tra una cartella locale e un server FTP remoto.
>
> **[EN]** A robust, high-performance Windows service written in C++ for bidirectional file synchronization between a local folder and a remote FTP server.

---

## Features / Funzionalita

### Bidirectional Synchronization / Sincronizzazione Bidirezionale

- **[IT]** Propaga automaticamente le modifiche dal Client al Server e viceversa.
- **[EN]** Automatically propagates changes from Client to Server and vice versa.

### Real-Time Monitoring / Monitoraggio Real-Time

- **[IT]** Utilizza `ReadDirectoryChangesW` per rilevare istantaneamente creazioni, modifiche e cancellazioni locali.
- **[EN]** Uses `ReadDirectoryChangesW` to instantly detect local file creations, modifications, and deletions.

### Smart Rename Handling / Gestione Intelligente dei Rename

- **[IT]** Ottimizza il traffico di rete utilizzando i comandi FTP `RNFR`/`RNTO` per rinominare i file sul server invece di ricaricarli.
- **[EN]** Optimizes network traffic by using FTP `RNFR`/`RNTO` commands to rename files on the server instead of re-uploading them.

### Recursive Directory Structure / Struttura Ricorsiva

- **[IT]** Gestisce completamente sottocartelle e alberi di directory complessi.
- **[EN]** Fully handles subfolders and complex directory trees.

### Advanced Logging / Logging Avanzato

- **Sequential Log**: Cronologia lineare di tutti gli eventi / Linear chronology of all events.
- **Thread Diagram**: Visualizzazione grafica (stile diagramma di flusso) dell'esecuzione dei thread / Graphical visualization (flowchart-style) of thread execution for immediate debugging.
- **Statistics**: Report periodici (ogni 10 min) su byte trasferiti, memoria occupata e stato dei thread / Periodic reports (every 10 min) on transferred bytes, memory usage, and thread status.

### Robustness / Robustezza

- **[IT]** Gestione degli overflow del buffer di notifica, riconnessione automatica FTP e prevenzione dei loop di sincronizzazione.
- **[EN]** Handles notification buffer overflows, automatic FTP reconnection, and sync loop prevention.

---

## Architecture / Architettura

```
+-------------------+          +-------------------+
|   Local Folder    |  <---->  |    FTP Server     |
+-------------------+          +-------------------+
        |                              |
        v                              v
+-------------------+          +-------------------+
|  WATCHER Thread   |          |  POLLER Thread    |
|  (Real-time I/O)  |          |  (Periodic Sync)  |
+-------------------+          +-------------------+
        |                              |
        +----------+  +---------------+
                   |  |
                   v  v
            +----------------+
            |  SERVICE_MAIN  |
            |   (Heartbeat   |
            |   + Logging)   |
            +----------------+
```

| Thread | Role / Ruolo |
|--------|-------------|
| **SERVICE_MAIN** | Main loop, heartbeat every 60s, periodic summary every 10 min |
| **WATCHER** | Monitors local folder via `ReadDirectoryChangesW`, uploads/deletes/renames on FTP |
| **POLLER** | Polls FTP server every 10s, downloads new/updated files locally |

---

## Build / Compilazione

The project is written in standard C++ and requires WinAPI libraries. Tested with **MinGW32**.

Il progetto e scritto in C++ standard e richiede le librerie WinAPI. Testato con **MinGW32**.

```bash
g++ -o ftp_sync_service.exe ftp_sync_service.cpp -lwininet -ladvapi32 -lpsapi -static
```

### Linked Dependencies / Dipendenze

| Library | Purpose |
|---------|---------|
| `wininet` | FTP operations / Operazioni FTP |
| `advapi32` | Windows Service management / Gestione Servizi Windows |
| `psapi` | Memory usage monitoring / Monitoraggio utilizzo memoria |

---

## Configuration / Configurazione

The service reads settings from a `config.ini` file located in the same folder as the executable.

Il servizio legge le impostazioni da un file `config.ini` posizionato nella stessa cartella dell'eseguibile.

Copy `config.ini.example` to `config.ini` and edit it:

```ini
[FTP]
IP=192.168.1.100
Port=21
User=ftpuser
Password=ftppassword
LocalFolder=C:\LocalData
RemoteFolder=/backup
```

---

## Installation / Installazione

### Install as Windows Service / Installa come Servizio Windows

1. Open Command Prompt **as Administrator** / Apri il Prompt dei Comandi **come Amministratore**
2. Navigate to the executable folder / Naviga nella cartella dell'eseguibile
3. Install / Installa:

```cmd
ftp_sync_service.exe --install
```

4. Start the service / Avvia il servizio:

```cmd
sc start FTPSyncService
```

5. To stop / Per arrestare:

```cmd
sc stop FTPSyncService
```

---

## Logs & Monitoring / Log e Monitoraggio

Logs are automatically saved in the `log` subfolder.

I log vengono salvati automaticamente nella sottocartella `log`.

| File | Description |
|------|-------------|
| `YYYY-MM-DD_sequential.log` | Classic chronological log with heartbeat, statistics, and operational details |
| `YYYY-MM-DD_thread.log` | Visual thread activity diagram, useful for forensic analysis and optimization |

### Log Example / Esempio Log

```
[25/02 10:38:15.042] [SERVICE_MAIN] [START] Spawning Worker Threads
[25/02 10:38:15.043] [WATCHER] [START] Monitoring Loop Started
[25/02 10:38:15.044] [POLLER] [START] FTP CONNECT & SYNC START
[25/02 10:38:15.500] [POLLER] [DOWNLOAD] File: document.pdf (1024 bytes)
[25/02 10:38:16.100] [POLLER] [END] SYNC CYCLE COMPLETE
```

---

## License / Licenza

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

Questo progetto e distribuito sotto licenza **MIT**. Vedi il file [LICENSE](LICENSE) per i dettagli.
