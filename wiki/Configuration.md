# Configuration / Configurazione

**[IT]** Tutta la configurazione vive in un singolo file `config.ini`, posto nella stessa cartella di `ftp_sync_service.exe`. Il servizio legge il file una sola volta all'avvio: per applicare modifiche occorre riavviare con `sc stop FTPSyncService && sc start FTPSyncService`.

**[EN]** All configuration lives in a single `config.ini` file placed alongside `ftp_sync_service.exe`. The service reads the file only at startup: to apply changes you must restart with `sc stop FTPSyncService && sc start FTPSyncService`.

---

## File Format / Formato del File

**[IT]** Sintassi INI standard di Windows (`GetPrivateProfileString`). Una sola sezione `[FTP]`.

**[EN]** Standard Windows INI syntax (`GetPrivateProfileString`). A single `[FTP]` section.

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

---

## Keys / Chiavi

### `IP`
- **[IT]** Hostname o indirizzo IP del server FTP. Obbligatorio.
- **[EN]** FTP server hostname or IP address. Required.

### `Port`
- **[IT]** Porta FTP. Default: `21`.
- **[EN]** FTP port. Default: `21`.

### `User` / `Password`
- **[IT]** Credenziali FTP in chiaro. Per FTP anonimo lascia entrambi vuoti.
- **[EN]** FTP credentials in plain text. For anonymous FTP leave both empty.

> **[IT]** Il file `config.ini` contiene credenziali in chiaro: assicurati che le ACL della cartella siano restrittive.
> **[EN]** The `config.ini` file contains plain-text credentials: make sure the folder ACLs are restrictive.

### `LocalFolder`
- **[IT]** Percorso assoluto Windows (con backslash) della cartella locale da sincronizzare. Obbligatorio.
- **[EN]** Absolute Windows path (with backslashes) of the local folder to synchronize. Required.

### `RemoteFolder`
- **[IT]** Cartella radice remota su FTP (con slash). Per la root del FTP usa `/`.
- **[EN]** Remote root folder on FTP (with slashes). For the FTP root use `/`.

### `Exclusions`
- **[IT]** Lista opzionale di pattern glob separati da pipe. Vedi [Exclusions](Exclusions) per i dettagli.
- **[EN]** Optional list of pipe-separated glob patterns. See [Exclusions](Exclusions) for details.

---

## Internal Defaults / Default Interni

**[IT]** I seguenti valori non sono esposti in `config.ini` ma sono codificati nel sorgente. Modificarli richiede ricompilazione.

**[EN]** The following values are not exposed in `config.ini` and are hard-coded in the source. Changing them requires recompilation.

| Constant | Value | Source / Sorgente |
|----------|-------|--------------------|
| Poll interval / Intervallo polling | `600 000 ms` (10 min) | `Config::pollIntervalMs` |
| Anti-loop window / Finestra anti-loop | `5 s` | `CheckAndClearRecentAction` |
| Local-delete pause / Pausa post-delete locale | `10 s` | `DELETE_PAUSE_THRESHOLD_SEC` |
| Deleted-set retention / TTL elenco cancellati | `60 s` | `CleanupOldDeletedEntries` |
| Heartbeat | `60 s` | `ServiceMain` |
| Periodic summary / Riepilogo periodico | `600 s` | `ServiceMain` |
| Watcher buffer / Buffer watcher | `64 KiB` | `WATCHER_CONTEXT::buffer` |

---

## Sample Configurations / Esempi di Configurazione

### Anonymous FTP / FTP Anonimo
```ini
[FTP]
IP=ftp.example.com
Port=21
User=
Password=
LocalFolder=C:\Mirror
RemoteFolder=/pub
```

### Backup with Exclusions / Backup con Esclusioni
```ini
[FTP]
IP=10.0.0.5
Port=21
User=backup
Password=secret
LocalFolder=D:\Documents
RemoteFolder=/backup/docs
Exclusions=*.tmp|*.bak|~*|Thumbs.db|desktop.ini
```

### Pure Upload (read-only remote) / Solo Upload (remoto read-only)
**[IT]** Per ora il servizio e sempre bidirezionale: per disabilitare il download serve un fork del codice o impostare permessi FTP read-only sull'account.

**[EN]** The service is currently always bidirectional: to disable download you must fork the code or set read-only FTP permissions on the account.

---

## See Also / Vedi Anche

- [Installation](Installation)
- [Exclusions](Exclusions)
- [Troubleshooting](Troubleshooting)
