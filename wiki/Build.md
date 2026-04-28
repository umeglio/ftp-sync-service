# Build / Compilazione

## Toolchain Requirements / Requisiti Toolchain

**[IT]** Il progetto compila pulito su qualsiasi MinGW recente (testato su MinGW32 e MinGW-w64 con GCC 8 - 15). Lo standard richiesto e C++17.

**[EN]** The project builds cleanly on any recent MinGW (tested on MinGW32 and MinGW-w64 with GCC 8 - 15). Required standard: C++17.

| Tool | Tested Versions / Versioni testate |
|------|------------------------------------|
| GCC | 8.x - 15.x |
| MinGW | 32-bit and 64-bit / 32 e 64 bit |
| Make | GNU Make 3.81+ |

---

## Build with Make / Build con Make

```bash
make
```

**[IT]** Produce `ftp_sync_service.exe` con flag di ottimizzazione `-O2`, warning `-Wall` e linkaggio statico (`-static`).

**[EN]** Produces `ftp_sync_service.exe` with `-O2` optimization, `-Wall` warnings, and static linking (`-static`).

---

## Manual Build / Build Manuale

```bash
g++ -O2 -Wall -o ftp_sync_service.exe ftp_sync_service.cpp \
    -lwininet -ladvapi32 -lpsapi -lshlwapi -static
```

### Flag Reference / Riferimento Flag

| Flag | Purpose / Scopo |
|------|-----------------|
| `-O2` | Compiler optimization / Ottimizzazione compilatore |
| `-Wall` | Enable warnings / Attiva i warning |
| `-static` | Embed runtime so the EXE has no `libgcc/libstdc++` deps / Incorpora il runtime, niente DLL esterne |
| `-lwininet` | FTP API |
| `-ladvapi32` | Service Control Manager |
| `-lpsapi` | Process memory queries / Query memoria di processo |
| `-lshlwapi` | `PathMatchSpec` for exclusions / `PathMatchSpec` per esclusioni |

---

## Cleaning / Pulizia

```bash
make clean
```

**[IT]** Rimuove `ftp_sync_service.exe`.

**[EN]** Removes `ftp_sync_service.exe`.

---

## Installing After Build / Installazione Dopo Build

```bash
make install
```

**[IT]** Equivalente a eseguire `ftp_sync_service.exe --install`. Richiede privilegi di Amministratore.

**[EN]** Equivalent to running `ftp_sync_service.exe --install`. Requires Administrator privileges.

---

## Common Build Issues / Problemi Comuni di Build

### `undefined reference to PathMatchSpecA`
**[IT]** Manca `-lshlwapi`. Verifica che il Makefile e la riga di compilazione lo includano.

**[EN]** `-lshlwapi` is missing. Verify the Makefile and the compile line include it.

### `cannot find -lwininet`
**[IT]** MinGW non trova le librerie WinAPI. Verifica che la toolchain sia installata correttamente (es. `pacman -S mingw-w64-x86_64-toolchain` su MSYS2).

**[EN]** MinGW cannot find the WinAPI libraries. Make sure your toolchain is installed correctly (e.g. `pacman -S mingw-w64-x86_64-toolchain` on MSYS2).

### `warning: ignoring '#pragma comment'`
**[IT]** Innocuo: il sorgente contiene direttive `#pragma comment(lib, ...)` ad uso di MSVC. Su MinGW il linkaggio avviene tramite i flag `-l...` del Makefile.

**[EN]** Harmless: the source contains `#pragma comment(lib, ...)` directives for MSVC. On MinGW linking happens via the Makefile `-l...` flags.

---

## Output Verification / Verifica Output

```bash
file ftp_sync_service.exe
```

**[IT]** Output atteso: `PE32` (32-bit) o `PE32+` (64-bit) executable for MS Windows.

**[EN]** Expected output: `PE32` (32-bit) or `PE32+` (64-bit) executable for MS Windows.

---

## See Also / Vedi Anche

- [Installation](Installation)
- [Architecture](Architecture)
