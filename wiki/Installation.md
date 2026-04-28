# Installation / Installazione

## Prerequisites / Prerequisiti

**[IT]**
- Windows 7 / 10 / 11 / Server 2012 o superiore
- Privilegi di Amministratore per l'installazione del servizio
- File `config.ini` correttamente compilato (vedi [Configuration](Configuration))
- Accesso di rete al server FTP

**[EN]**
- Windows 7 / 10 / 11 / Server 2012 or higher
- Administrator privileges for service installation
- A properly filled `config.ini` (see [Configuration](Configuration))
- Network access to the FTP server

---

## Installing the Service / Installazione del Servizio

### Step 1 - Open an Administrator Prompt / Apri un prompt come Amministratore

**[IT]** Premi `Win + X` e seleziona "Windows Terminal (Amministratore)" o "Prompt dei comandi (Amministratore)".

**[EN]** Press `Win + X` and choose "Windows Terminal (Administrator)" or "Command Prompt (Administrator)".

### Step 2 - Navigate to the Executable Folder / Vai nella cartella dell'eseguibile

```cmd
cd C:\Path\To\FTPSyncService
```

### Step 3 - Register the Service / Registra il servizio

```cmd
ftp_sync_service.exe --install
```

**[IT]** Il programma registra il servizio con nome `FTPSyncService` e tipo di avvio `SERVICE_DEMAND_START` (avvio manuale).

**[EN]** The program registers the service named `FTPSyncService` with `SERVICE_DEMAND_START` (manual start) startup type.

### Step 4 - Configure Auto-Start (Optional) / Avvio Automatico (Opzionale)

```cmd
sc config FTPSyncService start= auto
```

### Step 5 - Start the Service / Avvia il servizio

```cmd
sc start FTPSyncService
```

---

## Verifying the Service / Verifica del Servizio

### Check Status / Controlla stato

```cmd
sc query FTPSyncService
```

**[IT]** Stato atteso: `RUNNING`. Se vedi `STOPPED`, controlla i log.

**[EN]** Expected status: `RUNNING`. If you see `STOPPED`, check the logs.

### Inspect Logs / Ispeziona i log

```cmd
type log\YYYY-MM-DD_sequential.log
```

**[IT]** Cerca la riga `[CONFIG] Loading configuration from:` per verificare che `config.ini` sia stato letto.

**[EN]** Look for the `[CONFIG] Loading configuration from:` line to confirm that `config.ini` has been read.

---

## Stopping the Service / Arresto del Servizio

```cmd
sc stop FTPSyncService
```

---

## Uninstalling the Service / Disinstallazione

```cmd
sc stop FTPSyncService
sc delete FTPSyncService
```

**[IT]** Dopo `sc delete` puoi rimuovere la cartella dell'eseguibile in sicurezza.

**[EN]** After `sc delete` you can safely remove the executable folder.

---

## Running Without Service (Debug) / Esecuzione senza Servizio (Debug)

**[IT]** Il binario e progettato per girare come servizio Windows tramite `StartServiceCtrlDispatcher`. Eseguirlo direttamente da console termina con un errore `1063` quasi immediatamente: e il comportamento atteso. Per testare la logica usa sempre l'installazione come servizio e ispeziona i log.

**[EN]** The binary is designed to run as a Windows service via `StartServiceCtrlDispatcher`. Running it directly from the console terminates with error `1063` almost immediately: this is expected behavior. To test the logic always install it as a service and inspect the logs.

---

## See Also / Vedi Anche

- [Configuration](Configuration) - **[IT]** Configura `config.ini` / **[EN]** Configure `config.ini`
- [Troubleshooting](Troubleshooting) - **[IT]** Errori comuni / **[EN]** Common errors
