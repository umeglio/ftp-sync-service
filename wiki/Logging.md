# Logging / Logging

**[IT]** Il servizio scrive due log paralleli con rotazione giornaliera nella sottocartella `log/` (creata automaticamente accanto all'eseguibile).

**[EN]** The service writes two parallel logs with daily rotation in the `log/` subfolder (auto-created next to the executable).

---

## Log Files / File di Log

| File | Format / Formato | Use Case / Caso d'uso |
|------|------------------|------------------------|
| `YYYY-MM-DD_sequential.log` | Linear chronological / Cronologia lineare | Day-to-day audit / Audit quotidiano |
| `YYYY-MM-DD_thread.log` | Indented thread diagram / Diagramma thread indentato | Thread forensics / Analisi forense thread |

**[IT]** Allo scoccare della mezzanotte i file vengono chiusi e si aprono nuovi file con la nuova data. Sul file in chiusura viene scritto un `=== DAILY SUMMARY ===`.

**[EN]** At midnight the files are closed and new files for the new date are opened. A `=== DAILY SUMMARY ===` is written to the closing file.

---

## Sequential Log

### Anatomy of a Line / Anatomia di una Riga

```
[28/04 11:38:15.042] [WATCHER] [UPLOAD] File: report.pdf (4096 bytes)
       ^                ^         ^         ^
       |                |         |         +-- message / messaggio
       |                |         +-- workflow tag
       |                +-- thread name / nome thread
       +-- timestamp (DD/MM HH:MM:SS.mmm)
```

### Workflow Tags

| Tag | Meaning / Significato |
|-----|------------------------|
| `[UPLOAD]` | File uploaded to FTP / File caricato su FTP |
| `[DOWNLOAD]` | File downloaded from FTP / File scaricato da FTP |
| `[DELETE]` | Remote deletion / Cancellazione remota |
| `[RENAME]` | Remote rename / Rinomina remota |
| `[BATCH_OP]` | Batch of local events / Batch di eventi locali |
| `[EXCLUDED]` | Skipped due to exclusion pattern / Saltato per pattern di esclusione |
| `[CONFIG]` | Configuration loaded at startup / Configurazione caricata all'avvio |
| `[HEARTBEAT]` | 60-second alive marker / Marker vita ogni 60 s |
| `[START]` / `[END]` / `[PAUSE]` / `[RESUME]` / `[ERROR]` | Flow markers / Marker di flusso |

### Periodic Report / Report Periodico

**[IT]** Ogni 10 minuti il `SERVICE_MAIN` scrive un blocco `=== PERIODIC REPORT (10m) ===` con statistiche cumulate dall'avvio.

**[EN]** Every 10 minutes `SERVICE_MAIN` writes a `=== PERIODIC REPORT (10m) ===` block with cumulative statistics since startup.

```
[28/04 11:38:15.042] === PERIODIC REPORT (10m) ===
[28/04 11:38:15.042] Uptime: 600s
[28/04 11:38:15.042] --- Traffic ---
[28/04 11:38:15.042]   Uploads:   12 files (4.32 MB)
[28/04 11:38:15.042]   Downloads: 3 files (256.00 KB)
[28/04 11:38:15.042]   Deletes:   2 ops
[28/04 11:38:15.042]   Renames:   1 ops
[28/04 11:38:15.042]   Errors:    0
[28/04 11:38:15.042] --- System ---
[28/04 11:38:15.042]   Memory Usage: 12.40 MB
[28/04 11:38:15.042]   Active Threads: 3 (Peak: 3)
[28/04 11:38:15.042]   Active Threads Status:
[28/04 11:38:15.042]     -> [SERVICE_MAIN] TID:1234 Life:600s State: HEARTBEAT
[28/04 11:38:15.042]     -> [WATCHER] TID:5678 Life:599s State: BATCH_OP Detected 2 deletions/renames
[28/04 11:38:15.042]     -> [POLLER] TID:9012 Life:599s State: SYNC CYCLE COMPLETE
```

---

## Thread Log

**[IT]** Lo stesso flusso del log sequenziale ma reso come "diagramma" indentato per parentela tra thread (root - figli - nipoti). Ogni evento riporta il delta in millisecondi rispetto all'evento precedente dello stesso thread.

**[EN]** Same flow as the sequential log but rendered as an indented "diagram" by thread parentage (root - children - grandchildren). Every event reports the delta in milliseconds since the previous event of the same thread.

### Sample / Esempio

```
[28/04 10:38:15.042]    | THREAD START: SERVICE_MAIN [TID:1234]
[28/04 10:38:15.043]    | [START]   Spawning Worker Threads (Δ 1ms)
[28/04 10:38:15.044]        | [SPAWN]
[28/04 10:38:15.044]        | THREAD START:      WATCHER [TID:5678]
[28/04 10:38:15.044]        | Generator:    SERVICE_MAIN [TID:1234]
[28/04 10:38:15.045]        | [START]   Monitoring Loop Started (Δ 1ms)
[28/04 10:38:15.046]        | [SPAWN]
[28/04 10:38:15.046]        | THREAD START:       POLLER [TID:9012]
[28/04 10:38:15.046]        | Generator:    SERVICE_MAIN [TID:1234]
[28/04 10:38:15.500]        | [START]   FTP CONNECT & SYNC START (Δ 454ms)
[28/04 10:38:16.100]        | [INFO]    DOWNLOAD File: doc.pdf (1024 bytes) (Δ 600ms)
[28/04 10:38:16.110]        | [END]     SYNC CYCLE COMPLETE (Δ 10ms)
```

**[IT]** Ottimo per ricostruire latenze e identificare thread "pigri" (delta troppo grandi tra eventi).

**[EN]** Great for reconstructing latency and spotting "lazy" threads (overly large deltas between events).

---

## Statistics Counters / Contatori Statistiche

**[IT]** I contatori sono `std::atomic` e si azzerano alla rotazione giornaliera.

**[EN]** Counters are `std::atomic` and reset on daily rotation.

| Counter | Description / Descrizione |
|---------|---------------------------|
| `countUploads` | Total uploads / Upload totali |
| `countDownloads` | Total downloads / Download totali |
| `countDeletes` | Remote deletes / Cancellazioni remote |
| `countRenames` | Remote renames / Rinomine remote |
| `countErrors` | Logged errors / Errori loggati |
| `bytesUp` / `bytesDown` | Bytes transferred per direction / Byte trasferiti per direzione |
| `activeThreads` / `peakThreads` | Live thread count / Conteggio thread vivi |

---

## Log Rotation and Retention / Rotazione e Conservazione

**[IT]** La rotazione avviene per data calcolata sul timestamp locale del primo evento dopo mezzanotte. Non c'e politica di retention automatica: i file storici si accumulano in `log/`. Per pulizia periodica usa una scheduled task con `forfiles /p log /m *.log /d -30 /c "cmd /c del @path"`.

**[EN]** Rotation happens by date computed from the local timestamp of the first event after midnight. There is no automatic retention policy: historical files accumulate in `log/`. For periodic cleanup use a scheduled task such as `forfiles /p log /m *.log /d -30 /c "cmd /c del @path"`.

---

## See Also / Vedi Anche

- [Architecture](Architecture)
- [Troubleshooting](Troubleshooting)
