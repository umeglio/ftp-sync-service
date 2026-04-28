# Architecture / Architettura

## High-Level Diagram / Diagramma Generale

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

---

## Threads / Thread

### `SERVICE_MAIN`
- **[IT]** Avviato dal Service Control Manager. Carica la configurazione, registra l'handler di stop, fa spawn di WATCHER e POLLER, poi entra in un loop con `Sleep(1000)` per emettere heartbeat ogni 60 s e riepiloghi periodici ogni 600 s.
- **[EN]** Spawned by the Service Control Manager. Loads configuration, registers the stop handler, spawns WATCHER and POLLER, then enters a `Sleep(1000)` loop emitting heartbeats every 60 s and periodic summaries every 600 s.

### `WATCHER`
- **[IT]** Apre la cartella locale con `FILE_FLAG_OVERLAPPED` e arma `ReadDirectoryChangesW` con callback APC. Il thread dorme in `SleepEx(INFINITE, TRUE)` e si sveglia ad ogni evento. Gestisce upload, delete e rename verso il server.
- **[EN]** Opens the local folder with `FILE_FLAG_OVERLAPPED` and arms `ReadDirectoryChangesW` with an APC callback. The thread sleeps in `SleepEx(INFINITE, TRUE)` and wakes on each event. Handles upload, delete and rename towards the server.

### `POLLER`
- **[IT]** Loop con `Sleep` interrompibile. Ogni 10 minuti si connette al server FTP e percorre l'albero remoto (BFS via `std::queue`). Per ogni file confronta il `FILETIME` remoto con quello locale e scarica solo se piu recente.
- **[EN]** Loop with interruptible `Sleep`. Every 10 minutes it connects to the FTP server and walks the remote tree (BFS via `std::queue`). For every file it compares the remote `FILETIME` against the local one and downloads only if newer.

---

## Synchronous vs Asynchronous Operations / Operazioni Sincrone vs Asincrone

| Direction / Direzione | Mechanism / Meccanismo | Latency / Latenza |
|-----------------------|------------------------|-------------------|
| Local -> Remote | `ReadDirectoryChangesW` + APC | < 1 s |
| Remote -> Local | Periodic polling / Polling periodico | up to 10 min / fino a 10 min |

**[IT]** L'asimmetria e voluta: il monitoraggio FTP in tempo reale richiederebbe FTP sftp/inotify-style non disponibili in WinINet.

**[EN]** The asymmetry is intentional: real-time FTP watching would require sftp/inotify-style mechanisms not available in WinINet.

---

## Anti-Loop and Race Protection / Protezioni Anti-Loop e Race

### `g_recentlyProcessed`
- **[IT]** Mappa `path -> timestamp`. Quando il POLLER scarica un file, marca il path con la chiamata a `MarkRecentAction`. Quando il WATCHER vede l'evento `FILE_ACTION_MODIFIED` causato dal download, `CheckAndClearRecentAction` riconosce il path entro 5 s e salta l'upload.
- **[EN]** `path -> timestamp` map. When POLLER downloads a file it marks the path via `MarkRecentAction`. When WATCHER sees the `FILE_ACTION_MODIFIED` event caused by the download, `CheckAndClearRecentAction` recognizes the path within 5 s and skips the upload.

### `g_locallyDeleted` + `g_lastLocalDeleteTime`
- **[IT]** Quando il WATCHER batchifica delle cancellazioni locali, registra i path. Il POLLER, se vede una cancellazione recente (< 10 s), va in pausa per evitare di "ripristinare" file appena rimossi. Lista pulita dopo 60 s.
- **[EN]** When WATCHER batches local deletions, it records the paths. POLLER, if it sees a recent deletion (< 10 s), pauses to avoid "restoring" just-deleted files. List is purged after 60 s.

### Mutex
| Lock | Protects / Protegge |
|------|---------------------|
| `g_logMutex` | Logger files and per-thread maps / File log e mappe per-thread |
| `g_stateMutex` | Anti-loop maps / Mappe anti-loop |

---

## FTP Operation Flow / Flusso Operazioni FTP

### Upload (Local -> Remote)
1. `ReadDirectoryChangesW` returns `FILE_ACTION_ADDED` or `FILE_ACTION_MODIFIED`.
2. `IsExcluded(relativePath)` -> if true, skip.
3. `CheckAndClearRecentAction(relativePath)` -> if true (came from a download), skip.
4. `Sleep(300)` to let the writer finish.
5. `EnsureRemoteDirectoryExists` (recursive `MKD` per segment).
6. `FtpPutFileA` with binary transfer.

### Rename
1. `ReadDirectoryChangesW` returns paired `RENAMED_OLD_NAME` + `RENAMED_NEW_NAME`.
2. Exclusion logic / Logica esclusione:
   - both excluded -> skip;
   - old excluded -> upload of new path / upload del nuovo path;
   - new excluded -> delete of old path / delete del vecchio path;
   - none excluded -> `FtpRenameFileA` (RNFR/RNTO); on failure -> delete + re-upload.
3. **[IT]** Le ottimizzazioni RNFR/RNTO evitano di trasferire i byte quando il file non e cambiato.
4. **[EN]** RNFR/RNTO optimizations avoid transferring bytes when the file content is unchanged.

### Download (Remote -> Local)
1. POLLER lists each remote directory via `FtpFindFirstFileA` / `InternetFindNextFileA`.
2. For every file: `IsExcluded` -> skip; `IsLocallyDeleted` -> skip.
3. Compare `FILETIME` (last write) remote vs local.
4. If remote > local (or local missing) -> `MarkRecentAction` + `FtpGetFileA` + `SetFileTime` to align timestamps.

---

## Error Handling / Gestione Errori

| Failure / Errore | Handler |
|------------------|---------|
| `ReadDirectoryChangesW` buffer overflow (`ERROR_NOTIFY_ENUM_DIR`) | Logged as `WATCHER_ERR`, callback re-armed / Loggato come `WATCHER_ERR`, callback ri-armata |
| FTP connection failure | Logged as `[ERROR]`, retry on next cycle / Loggato come `[ERROR]`, retry al prossimo ciclo |
| Generic exception in WATCHER | `catch (...)` block, logged as `WATCHER_ERR` / Blocco `catch (...)`, loggato come `WATCHER_ERR` |
| Service stop request | `g_running = false`, threads exit on next iteration / Uscita thread alla iterazione successiva |

---

## See Also / Vedi Anche

- [Logging](Logging) - **[IT]** Come leggere i log dei thread / **[EN]** How to read thread logs
- [Configuration](Configuration) - **[IT]** Costanti modificabili / **[EN]** Tunable constants
- [Exclusions](Exclusions)
