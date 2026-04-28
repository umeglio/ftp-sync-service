# Windows FTP Sync Service Wiki

> **[IT]** Documentazione completa del servizio Windows di sincronizzazione bidirezionale FTP.
>
> **[EN]** Complete documentation for the Windows bidirectional FTP synchronization service.

---

## Overview / Panoramica

**[IT]** FTP Sync Service e un servizio Windows scritto in C++ che mantiene allineata in tempo reale una cartella locale con una cartella remota su un server FTP. Le modifiche locali vengono propagate immediatamente (`ReadDirectoryChangesW`), mentre le modifiche remote vengono raccolte tramite polling periodico.

**[EN]** FTP Sync Service is a Windows service written in C++ that keeps a local folder in real-time alignment with a remote folder on an FTP server. Local changes propagate immediately (`ReadDirectoryChangesW`), while remote changes are picked up via periodic polling.

| Property | Value |
|----------|-------|
| Version | `2.1-Enterprise` |
| Language | C++ (C++17) |
| Toolchain | MinGW (32 / 64-bit) |
| Platform | Windows 7 / 10 / 11 / Server 2012+ |
| License | MIT |

---

## Quick Start / Avvio Rapido

```cmd
:: 1. Build
make

:: 2. Configure / Configura
copy config.ini.example config.ini
notepad config.ini

:: 3. Install (Admin) / Installa (come Admin)
ftp_sync_service.exe --install
sc start FTPSyncService
```

---

## Documentation Index / Indice Documentazione

| Page | Description / Descrizione |
|------|---------------------------|
| [Installation](Installation) | Service install/uninstall / Installazione del servizio |
| [Configuration](Configuration) | All `config.ini` keys / Tutte le chiavi di configurazione |
| [Build](Build) | Compile from source / Compilazione da sorgente |
| [Architecture](Architecture) | Threads, locks, data flow / Thread, lock, flusso dati |
| [Logging](Logging) | Log formats and rotation / Formati di log e rotazione |
| [Exclusions](Exclusions) | File-pattern exclusions / Esclusione file via pattern |
| [Troubleshooting](Troubleshooting) | Common issues / Problemi frequenti |

---

## Project Links / Link Progetto

- **Repository:** [github.com/umeglio/ftp-sync-service](https://github.com/umeglio/ftp-sync-service)
- **Issues:** [Report a bug / Segnala un bug](https://github.com/umeglio/ftp-sync-service/issues)
- **License:** [MIT](https://github.com/umeglio/ftp-sync-service/blob/master/LICENSE)
