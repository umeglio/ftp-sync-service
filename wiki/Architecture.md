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
- **[IT]** Loop con `Sleep` interrompibile. Ogni `FullSyncInterval` secondi (default 600) esegue un **full sync forzato**: si connette al server FTP e percorre l'intero albero remoto (BFS via `std::queue`). Per ogni file confronta il `FILETIME` remoto con quello locale e scarica solo se più recente. "Forzato" significa che il ciclo non viene rimandato da una cancellazione locale appena avvenuta (salta la pausa di ciclo), ma le guardie per-file `IsLocallyDeleted` restano attive per non riscaricare i file appena cancellati.
- **[EN]** Loop with interruptible `Sleep`. Every `FullSyncInterval` seconds (default 600) it runs a **forced full sync**: it connects to the FTP server and walks the entire remote tree (BFS via `std::queue`). For every file it compares the remote `FILETIME` against the local one and downloads only if newer. "Forced" means the cycle is not postponed by a just-occurred local deletion (it skips the cycle-level pause), but the per-file `IsLocallyDeleted` guards stay active so just-deleted files are not re-downloaded.

---

## Synchronous vs Asynchronous Operations / Operazioni Sincrone vs Asincrone

| Direction / Direzione | Mechanism / Meccanismo | Latency / Latenza |
|-----------------------|------------------------|-------------------|
| Local -> Remote | `ReadDirectoryChangesW` + APC | < 1 s |
| Remote -> Local | Forced full sync / Full sync forzato | up to `FullSyncInterval`s (default 600) / fino a `FullSyncInterval`s |

**[IT]** L'asimmetria e voluta: il monitoraggio FTP in tempo reale richiederebbe FTP sftp/inotify-style non disponibili in WinINet.

**[EN]** The asymmetry is intentional: real-time FTP watching would require sftp/inotify-style mechanisms not available in WinINet.

---

## Anti-Loop and Race Protection / Protezioni Anti-Loop e Race

### `g_recentlyProcessed`
- **[IT]** Mappa `path -> timestamp`. Quando il POLLER scarica un file, marca il path con la chiamata a `MarkRecentAction`. Quando il WATCHER vede l'evento `FILE_ACTION_MODIFIED` causato dal download, `CheckAndClearRecentAction` riconosce il path entro 5 s e salta l'upload.
- **[EN]** `path -> timestamp` map. When POLLER downloads a file it marks the path via `MarkRecentAction`. When WATCHER sees the `FILE_ACTION_MODIFIED` event caused by the download, `CheckAndClearRecentAction` recognizes the path within 5 s and skips the upload.

### `g_locallyDeleted` + `g_lastLocalDeleteTime`
- **[IT]** Quando il WATCHER batchifica delle cancellazioni locali, registra i path in `g_locallyDeleted` (TTL 60 s) e l'istante in `g_lastLocalDeleteTime`. Due livelli di protezione: (1) la **pausa di ciclo** — un sync *non forzato* che vede una cancellazione recente (< 10 s) salta l'intero ciclo; il full sync forzato **non** applica questa pausa. (2) Le **guardie per-file** `IsLocallyDeleted` — applicate **sempre**, anche nel full sync forzato: un file/cartella presente in `g_locallyDeleted` non viene mai riscaricato. Questo è ciò che impedisce la "resurrezione" dei file appena cancellati.
- **[EN]** When WATCHER batches local deletions, it records the paths in `g_locallyDeleted` (60 s TTL) and the instant in `g_lastLocalDeleteTime`. Two protection levels: (1) the **cycle pause** — a *non-forced* sync that sees a recent deletion (< 10 s) skips the whole cycle; the forced full sync does **not** apply this pause. (2) The **per-file guards** `IsLocallyDeleted` — applied **always**, including in the forced full sync: a file/dir present in `g_locallyDeleted` is never re-downloaded. This is what prevents "resurrection" of just-deleted files.

> **[IT]** ⚠️ La protezione per-file dura quanto il TTL (60 s). Se la cancellazione remota fallisce (delete fire-and-forget del WATCHER) e il file resta sul server oltre i 60 s, il full sync successivo lo riscaricherà. È un limite pre-esistente del design (TTL < intervallo di sync), non introdotto dal full sync.
> **[EN]** ⚠️ The per-file protection lasts as long as the TTL (60 s). If the remote deletion fails (WATCHER's fire-and-forget delete) and the file survives on the server beyond 60 s, the next full sync will re-download it. This is a pre-existing design limitation (TTL < sync interval), not introduced by the full sync.

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

### Download (Remote -> Local, Forced Full Sync)
1. POLLER runs `SyncRemoteToLocal(forced=true)` every `FullSyncInterval` seconds.
2. The forced flag skips ONLY the cycle-level delete pause (the `g_lastLocalDeleteTime` early-return); the per-path guards below still apply.
3. POLLER lists each remote directory via `FtpFindFirstFileA` / `InternetFindNextFileA` (full BFS tree walk).
4. For every file: `IsLocallyDeleted` -> skip (always, even forced); `IsExcluded` -> skip.
5. Compare `FILETIME` (last write) remote vs local.
6. If remote > local (or local missing) -> `MarkRecentAction` + `FtpGetFileA` + `SetFileTime` to align timestamps.

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
