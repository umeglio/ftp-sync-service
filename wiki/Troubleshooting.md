# Troubleshooting / Risoluzione Problemi

**[IT]** Soluzioni per i problemi piu comuni durante installazione, configurazione e operativita.

**[EN]** Solutions to the most common installation, configuration, and runtime problems.

---

## Service Will Not Start / Il Servizio Non Parte

### Symptom / Sintomo
**[IT]** `sc query FTPSyncService` riporta `STOPPED` subito dopo `sc start`.

**[EN]** `sc query FTPSyncService` reports `STOPPED` right after `sc start`.

### Diagnosis / Diagnosi
**[IT]** Apri l'ultimo `log/YYYY-MM-DD_sequential.log`. La causa quasi sempre e configurazione mancante.

**[EN]** Open the latest `log/YYYY-MM-DD_sequential.log`. The cause is almost always missing configuration.

### Common Causes / Cause Frequenti

| Cause / Causa | Fix / Soluzione |
|---------------|-----------------|
| `config.ini` missing in EXE folder / `config.ini` assente dalla cartella dell'EXE | Copy `config.ini.example` to `config.ini` |
| `IP` empty / vuoto | Set a valid hostname or IP / Imposta hostname o IP valido |
| `LocalFolder` empty / vuoto | Set an existing absolute Windows path / Imposta un percorso Windows assoluto esistente |
| `LocalFolder` does not exist / non esiste | Create the folder before service start / Crea la cartella prima di avviare |

---

## FTP Connection Failed / Connessione FTP Fallita

### Symptom / Sintomo
```
[POLLER] [ERROR] FTP Connection Failed
```

### Checklist

**[IT]**
1. Server FTP raggiungibile? Prova `telnet IP 21` o `ftp IP` da console.
2. Credenziali corrette? Verifica con un client FTP grafico (FileZilla, WinSCP).
3. Firewall: il servizio gira come `LocalSystem` di default; controlla che la porta 21 in uscita sia aperta.
4. FTP attivo vs passivo: il servizio usa `INTERNET_FLAG_PASSIVE`. Se il server richiede modalita attiva o se NAT sta bloccando le connessioni dati, l'FTP fallisce.

**[EN]**
1. FTP server reachable? Try `telnet IP 21` or `ftp IP` from the console.
2. Correct credentials? Verify with a graphical FTP client (FileZilla, WinSCP).
3. Firewall: the service runs as `LocalSystem` by default; ensure outbound port 21 is open.
4. Active vs passive FTP: the service uses `INTERNET_FLAG_PASSIVE`. If the server requires active mode or NAT is blocking data connections, FTP will fail.

---

## Files Not Uploading / I File Non Vengono Caricati

### Diagnosis Steps / Passi di Diagnosi

**[IT]**
1. Crea un file di test in `LocalFolder` e attendi qualche secondo.
2. Apri `log/YYYY-MM-DD_sequential.log` e cerca `[WATCHER]` / `[UPLOAD]`.
3. Se vedi `[EXCLUDED] Upload skipped` -> il pattern di esclusione corrisponde. Vedi [Exclusions](Exclusions).
4. Se non c'e nessun evento WATCHER -> verifica i permessi sulla cartella locale.

**[EN]**
1. Create a test file in `LocalFolder` and wait a few seconds.
2. Open `log/YYYY-MM-DD_sequential.log` and look for `[WATCHER]` / `[UPLOAD]`.
3. If you see `[EXCLUDED] Upload skipped` -> the exclusion pattern matches. See [Exclusions](Exclusions).
4. If there is no WATCHER event at all -> check permissions on the local folder.

### Common Pitfalls / Insidie Comuni

**[IT]**
- File creati molto velocemente (es. da uno script) possono essere ancora aperti dal writer quando il WATCHER prova ad uploadarli. Il servizio attende 300 ms prima di caricare, ma per file pesanti potrebbe non bastare. Considera di scrivere prima su una cartella temporanea e poi spostare.
- Il file e in uso da un altro processo: `FtpPutFileA` fallisce silenziosamente. Si vedra una riga `[ERROR]` nel log.

**[EN]**
- Files created very quickly (e.g. by a script) may still be held open by the writer when WATCHER tries to upload them. The service waits 300 ms before uploading, but it may not be enough for big files. Consider writing to a staging folder and moving it.
- File in use by another process: `FtpPutFileA` fails silently. An `[ERROR]` line will appear in the log.

---

## Files Not Downloading / I File Non Vengono Scaricati

**[IT]** Il POLLER e periodico (default 10 min): il download non e immediato. Per forzarlo, riavvia il servizio.

**[EN]** POLLER is periodic (default 10 min): downloads are not immediate. To force one, restart the service.

### Other Causes / Altre Cause

| Cause / Causa | Fix / Soluzione |
|---------------|-----------------|
| File matches an exclusion pattern / Il file corrisponde a un pattern di esclusione | Remove the pattern or rename the file / Rimuovi il pattern o rinomina il file |
| Local file is newer than remote / File locale piu recente del remoto | This is correct behavior: only newer remote files are downloaded / Comportamento corretto: solo file remoti piu recenti vengono scaricati |
| File was just locally deleted (< 60 s) / File appena cancellato localmente | The deletion guard prevents "restoring" the file. Wait > 60 s. / La protezione anti-resurrezione impedisce di ripristinare il file. Attendi > 60 s. |

---

## Sync Loop / Loop di Sincronizzazione

### Symptom / Sintomo
**[IT]** Lo stesso file viene caricato e scaricato in continuazione.

**[EN]** The same file is uploaded and downloaded continuously.

### Cause
**[IT]** L'orologio del client e del server FTP sono fuori sincrono di piu di qualche secondo, oppure il server FTP non preserva il `mtime` dei file.

**[EN]** Client and FTP server clocks are out of sync by more than a few seconds, or the FTP server does not preserve file `mtime`.

### Fix / Soluzione

**[IT]**
- Sincronizza il tempo del client (W32Time) e del server NTP.
- Verifica che il server FTP supporti `MFMT` o l'aggiornamento del timestamp via `SetFileTime` lato client (gestito dal servizio).
- In casi estremi, aggiungi i file problematici a `Exclusions`.

**[EN]**
- Sync the client clock (W32Time) and NTP server.
- Make sure the FTP server supports `MFMT` or the client-side `SetFileTime` update (handled by the service).
- In extreme cases, add the problematic files to `Exclusions`.

---

## Buffer Overflow Warnings / Warning Buffer Overflow

### Symptom / Sintomo
```
[WATCHER] [ERROR] Buffer Overflow
```

### Cause
**[IT]** Volume di eventi del filesystem locale superiore alla capacita del buffer da 64 KiB di `ReadDirectoryChangesW`.

**[EN]** Local filesystem event volume exceeds the 64 KiB `ReadDirectoryChangesW` buffer.

### Mitigation / Mitigazione
**[IT]** Il servizio ri-arma il watcher e prosegue, ma alcuni eventi potrebbero essere persi. Per cartelle molto attive considera di:
- aumentare la dimensione del buffer (`WATCHER_CONTEXT::buffer`, ricompilare);
- ridurre il rumore (esclusioni di file temporanei via `Exclusions`);
- evitare di sincronizzare cartelle ad altissimo throughput (es. `%TEMP%`).

**[EN]** The service re-arms the watcher and continues, but some events may be lost. For very busy folders consider:
- increasing the buffer size (`WATCHER_CONTEXT::buffer`, recompile);
- reducing noise (temp-file exclusions via `Exclusions`);
- not syncing very high-throughput folders (e.g. `%TEMP%`).

---

## High Memory Usage / Consumo di Memoria Elevato

**[IT]** I report periodici (`Periodic Report`) mostrano la memoria del processo. Cause tipiche:
- log molto vecchi accumulati in `log/` -> applica retention con `forfiles` (vedi [Logging](Logging));
- alberi remoti enormi: il POLLER usa una `std::queue` per la BFS; cartelle con milioni di file richiedono RAM proporzionale durante il ciclo.

**[EN]** Periodic reports (`Periodic Report`) show process memory. Typical causes:
- very old logs accumulating in `log/` -> apply retention with `forfiles` (see [Logging](Logging));
- enormous remote trees: POLLER uses a `std::queue` for BFS; folders with millions of files need proportional RAM during the cycle.

---

## Service Stops Suddenly / Il Servizio si Ferma Improvvisamente

### Diagnosis / Diagnosi
1. Open Event Viewer / Apri Visualizzatore Eventi: `Windows Logs > System` and `Windows Logs > Application`.
2. Filter by source `Service Control Manager` and `FTPSyncService`.
3. Cross-reference the timestamp with the last entry in `log/YYYY-MM-DD_sequential.log`.

### Recovery / Recupero
**[IT]** Configura il recovery automatico:
```cmd
sc failure FTPSyncService reset= 86400 actions= restart/60000/restart/60000/restart/60000
```
**[EN]** Configure auto-recovery:
```cmd
sc failure FTPSyncService reset= 86400 actions= restart/60000/restart/60000/restart/60000
```

**[IT]** Il servizio verra riavviato 3 volte con 60 s di intervallo a ogni crash.

**[EN]** The service will be restarted 3 times with 60 s intervals on each crash.

---

## Reporting Bugs / Segnalare Bug

**[IT]** Apri una issue su [GitHub](https://github.com/umeglio/ftp-sync-service/issues) allegando:
1. Estratto del log sequenziale che mostra il problema.
2. Versione di Windows (`winver`).
3. Versione di MinGW usata per compilare (se hai compilato tu).
4. Configurazione `config.ini` **senza credenziali**.

**[EN]** Open an issue on [GitHub](https://github.com/umeglio/ftp-sync-service/issues) attaching:
1. Sequential log excerpt showing the problem.
2. Windows version (`winver`).
3. MinGW version used to build (if you built it).
4. `config.ini` configuration **without credentials**.

---

## See Also / Vedi Anche

- [Installation](Installation)
- [Configuration](Configuration)
- [Logging](Logging)
- [Exclusions](Exclusions)
