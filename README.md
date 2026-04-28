# Windows FTP Sync Service

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6.svg)](#)
[![Language: C++](https://img.shields.io/badge/Language-C++-00599C.svg)](#)
[![Version](https://img.shields.io/badge/Version-2.1--Enterprise-green.svg)](#)

> **[IT]** Un servizio Windows robusto e ad alte prestazioni scritto in C++ per la sincronizzazione bidirezionale di file tra una cartella locale e un server FTP remoto.
>
> **[EN]** A robust, high-performance Windows service written in C++ for bidirectional file synchronization between a local folder and a remote FTP server.

> **Documentazione completa / Full documentation:** [Project Wiki](https://github.com/umeglio/ftp-sync-service/wiki)

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

### File Exclusions / Esclusioni File

- **[IT]** Lista configurabile di pattern glob (`*.csv|*.prm|*.xls`) per escludere intere categorie di file dalla sincronizzazione bidirezionale.
- **[EN]** Configurable list of glob patterns (`*.csv|*.prm|*.xls`) to exclude entire file categories from bidirectional synchronization.

### Recursive Directory Structure / Struttura Ricorsiva

- **[IT]** Gestisce completamente sottocartelle e alberi di directory complessi.
- **[EN]** Fully handles subfolders and complex directory trees.

### Advanced Logging / Logging Avanzato

- **Sequential Log**: Cronologia lineare di tutti gli eventi / Linear chronology of all events.
- **Thread Diagram**: Visualizzazione grafica (stile diagramma di flusso) dell'esecuzione dei thread / Graphical visualization (flowchart-style) of thread execution.
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
| **POLLER** | Polls FTP server every 10 min (configurable), downloads new/updated files locally |

> **[IT]** Per maggiori dettagli architetturali consulta la pagina [Architecture](https://github.com/umeglio/ftp-sync-service/wiki/Architecture) del wiki.
> **[EN]** For deeper architectural details see the [Architecture](https://github.com/umeglio/ftp-sync-service/wiki/Architecture) wiki page.

---

## Build / Compilazione

The project is written in standard C++ and requires WinAPI libraries. Tested with **MinGW** (32 and 64-bit).

Il progetto e scritto in C++ standard e richiede le librerie WinAPI. Testato con **MinGW** (32 e 64 bit).

```bash
g++ -O2 -Wall -o ftp_sync_service.exe ftp_sync_service.cpp -lwininet -ladvapi32 -lpsapi -lshlwapi -static
```

Or via Makefile / Oppure tramite Makefile:

```bash
make
```

### Linked Dependencies / Dipendenze

| Library | Purpose |
|---------|---------|
| `wininet` | FTP operations / Operazioni FTP |
| `advapi32` | Windows Service management / Gestione Servizi Windows |
| `psapi` | Memory usage monitoring / Monitoraggio utilizzo memoria |
| `shlwapi` | Pattern matching for exclusions / Pattern matching esclusioni |

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
Exclusions=*.tmp|*.bak|~*
```

| Key | Description |
|-----|-------------|
| `IP` | FTP server hostname or IP / IP o hostname del server FTP |
| `Port` | FTP server port (default 21) / Porta del server FTP |
| `User` / `Password` | FTP credentials / Credenziali FTP |
| `LocalFolder` | Absolute path to the local folder to sync / Percorso assoluto della cartella locale |
| `RemoteFolder` | Remote root folder on FTP / Cartella radice remota su FTP |
| `Exclusions` | Pipe-separated glob patterns to skip / Pattern glob separati da pipe da escludere |

### Exclusions / Esclusioni

- **[IT]** Lista opzionale di pattern glob (`*`, `?`) separati da `|`. I file il cui nome corrisponde a uno qualsiasi dei pattern non vengono sincronizzati (in nessuna direzione). Esempio: `*.csv|*.prm|*.xls`.
- **[EN]** Optional list of glob patterns (`*`, `?`) separated by `|`. Files whose name matches any pattern are not synchronized (in either direction). Example: `*.csv|*.prm|*.xls`.

> **[IT]** Pagina dedicata: [Exclusions](https://github.com/umeglio/ftp-sync-service/wiki/Exclusions).
> **[EN]** Dedicated page: [Exclusions](https://github.com/umeglio/ftp-sync-service/wiki/Exclusions).

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

> **[IT]** Guida completa: [Installation](https://github.com/umeglio/ftp-sync-service/wiki/Installation).
> **[EN]** Full guide: [Installation](https://github.com/umeglio/ftp-sync-service/wiki/Installation).

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

> **[IT]** Approfondimento sui formati di log: [Logging](https://github.com/umeglio/ftp-sync-service/wiki/Logging).
> **[EN]** Deep-dive on log formats: [Logging](https://github.com/umeglio/ftp-sync-service/wiki/Logging).

---

## Documentation / Documentazione

| Page | Topic |
|------|-------|
| [Home](https://github.com/umeglio/ftp-sync-service/wiki) | Index / Indice |
| [Installation](https://github.com/umeglio/ftp-sync-service/wiki/Installation) | Service install/uninstall / Installazione e disinstallazione |
| [Configuration](https://github.com/umeglio/ftp-sync-service/wiki/Configuration) | All `config.ini` keys / Tutte le chiavi |
| [Build](https://github.com/umeglio/ftp-sync-service/wiki/Build) | Compiling from source / Compilazione |
| [Architecture](https://github.com/umeglio/ftp-sync-service/wiki/Architecture) | Threads & data flow / Thread e flusso dati |
| [Logging](https://github.com/umeglio/ftp-sync-service/wiki/Logging) | Log formats / Formati di log |
| [Exclusions](https://github.com/umeglio/ftp-sync-service/wiki/Exclusions) | Pattern syntax / Sintassi pattern |
| [Troubleshooting](https://github.com/umeglio/ftp-sync-service/wiki/Troubleshooting) | Common issues / Problemi comuni |

---

## License / Licenza

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

Questo progetto e distribuito sotto licenza **MIT**. Vedi il file [LICENSE](LICENSE) per i dettagli.
