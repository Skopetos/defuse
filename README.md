# defuse

A Windows malware-removal tool written in Go for the **DarkComet RAT ("Fynloski")** sample `mal-track.exe`.
It kills the malware, removes its persistence, deletes its files, verifies the result and prints the attacker's IP.

> ⚠️ Educational project. The sample must only ever be executed inside an isolated virtual machine.

| | |
|---|---|
| Sample | `mal-track.exe` (from `Fynloski(ON VM ONLY).zip`) |
| Family | DarkComet RAT (Fynloski variant), 32-bit Delphi PE, compiled 2012-06-07 |
| SHA-256 | `a164abbb6778e1378af208b4a3d4833c2b226c68452d2151fb14e2e01a578fdd` |
| MD5 | `59bc20336206070fa5312f03f1aee02e` |
| Attacker (C2) | `127.0.0.1` port `1010` |

## Build and run

```
GOOS=windows GOARCH=amd64 go build -o defuse.exe .
```

Copy `defuse.exe` into the VM and run it from an **Administrator** prompt (HKLM keys need it):

```
defuse.exe -dry-run     # show what would be killed / removed, change nothing
defuse.exe              # kill, clean, delete, verify, print the attacker IP
defuse.exe -analyze F   # decrypt the config of file F statically (works on Linux/macOS too)
```

Exit code is `0` only if the final verification finds nothing left.

Tests (run on any OS, they parse the real sample statically and never execute it):

```
go test ./...
```

## Program explanation

The tool does not hardcode "kill a process called X". It works from the malware's own configuration and confirms every file before touching it.

```
main.go                 CLI (-dry-run, -analyze)
clean_windows.go        the 6-step sequence below
internal/config         PE parser + RC4 decryptor for the embedded DarkComet config
internal/ioc            indicators of compromise and the matching rules
internal/win            Windows APIs: processes, TCP table, registry, startup folders, files
```

1. **Locate.** It lists running processes, autostart entries and the possible install paths, and keeps whatever matches the indicators (Run value `Mal-Track`, `maltrack\maltrack.exe`, `mal-track.exe`).
2. **Confirm.** Every candidate file is opened and its `DCDATA` resource is decrypted. Only a file that really contains a DarkComet config is treated as the malware, so a legitimate program that happens to share a name is left alone.
3. **Attacker.** The C2 address comes from the decrypted config. It also reads the system's TCP table (what `netstat -ano` shows) and lists any live connection owned by the malware. A hostname would be resolved to an IP.
4. **Kill.** The malware processes and their children (for example the `cmd.exe` of the remote shell) are terminated. It re-checks up to three times in case a watchdog respawns it.
5. **Remove persistence.** Deletes the entries found in:
   - `HKLM` and `HKCU` `...\CurrentVersion\Run` and `RunOnce` (plus the 32-bit `WOW6432Node` view and the Policies `Run` keys)
   - `Winlogon` `Userinit` / `Shell` (restored to the Windows default)
   - msconfig's `startupreg` / `startupfolder` bookkeeping keys
   - the per-user and all-users Startup folders (by name, or by the target inside a shortcut/script)
6. **Delete files and verify.** The binary and the install folder (including the `dclogs` keylogger data) are deleted after clearing the hidden/system/read-only attributes; a locked file is scheduled for deletion at reboot. The tool then re-scans and prints `PASS`/`FAIL` for: no process, no persistence, no files. The install folder is only removed if its name is exactly the configured one.

`-dry-run` performs steps 1-3 and lists the actions without doing them.

## Walkthrough: how the malware was analyzed

### Static analysis (done, nothing executed)
1. `file` → PE32 GUI executable, i386, 9 sections. Hashes recorded above.
2. `strings` revealed a Delphi program with the typical DarkComet vocabulary:
   - persistence: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `Winlogon` / `UserInit`, `MSConfig\startupreg`, `KEYNAME`, `INSTALL`, `EDTPATH`
   - spying and control: `OFFLINEK` / `dclogs\` (offline keylogger), `GetDrives` and file manager commands, `RunPrompt` / `cmd.exe` (remote shell), `AVICAP32.DLL` (webcam), `msacm32.dll` (audio), `GETMONITORS` (desktop)
   - network and update: `NETDATA`, `wsock32.dll`, `TUploadFTP`, `Update from URL`, `PortScanAdd`
3. The plaintext defaults in `.data` (`127.0.0.1:1604`, `#KCMDDC51#-`) were a **decoy**: the real settings are in the `DCDATA` resource (type `RCDATA`, 480 bytes of hex text).
4. `DCDATA` is hex-decoded and RC4-encrypted with the well-known key `#KCMDDC51#-890`. Decrypting it gives:

   ```
   MUTEX={DCMIN_MUTEX-NLY9NFG}    SID={mal-track}
   NETDATA={127.0.0.1:1010}       INSTALL={1}
   EDTPATH={maltrack\maltrack.exe}  COMBOPATH={7}
   KEYNAME={Mal-Track}            OFFLINEK={1}
   ```

   `go run . -analyze sample/mal-track.exe.bin` reproduces this. It gave the attacker address (`127.0.0.1:1010`), the Run value name, the install file, and the mutex.

### Dynamic confirmation (do this in the VM)
Static analysis says *what the config says*; these steps prove *what it does*. Record the output for the report:

1. Snapshot the VM, isolate it (host-only or no network), add the sample to Defender exclusions, run `mal-track.exe`.
2. Task Manager / `tasklist` → note the malware process and PID.
3. `netstat -ano | findstr <PID>` → the connection attempts to `127.0.0.1:1010`.
4. Autoruns / `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → the `Mal-Track` value and the install path it points to.
5. Run `defuse.exe -dry-run`, then `defuse.exe`, and re-check Task Manager, `msconfig`, the four Run/RunOnce keys and the install folder.

> **Note on testing.** The config extraction and matching logic are unit-tested against the real sample. The Windows parts (process, registry, files) were cross-compiled and vet-checked but are **verified only when run in the VM** (step 5 above). The install root (`COMBOPATH={7}`) was not decoded, so the tool searches all usual roots and follows the Run value to find the real path rather than assuming one.

## Malware Mitigation Report Email

**To:** security@[organization].com
**Subject:** Malware Analysis Report: Mitigation of DarkComet RAT (Fynloski, mal-track.exe)

Dear Security Team,

I am writing to report the successful analysis and mitigation of the DarkComet Remote Access Trojan (Fynloski variant, `mal-track.exe`, SHA-256 `a164abbb…c1c6`) identified during an educational malware analysis exercise. Below are the details:

**Summary:**
The sample is a remote access trojan that gives an attacker full control of the infected machine: remote shell, file manager, desktop and webcam access, and a keylogger that stores captured keystrokes in a `dclogs` folder. It installs itself as `maltrack\maltrack.exe`, starts at logon through a `Mal-Track` registry Run value, and holds a mutex (`DCMIN_MUTEX-NLY9NFG`) so only one copy runs. It contacts its command-and-control server repeatedly at the address stored in its encrypted configuration.

**Proof of Mitigation:**
The malware process was terminated and removed from Task Manager. Its persistence mechanisms (Run/RunOnce, Winlogon, msconfig and Startup folder entries) were removed, and its files, including the install directory, were deleted. The removal tool's final verification reported:

```
[PASTE THE VM OUTPUT OF defuse.exe HERE - the 6. Verification section with PASS lines]
```

**Attacker Information:**
The malware communicated with the following IP address: **127.0.0.1** (port 1010), recovered by decrypting the sample's embedded configuration.

Please feel free to reach out for further clarification or additional details.

Best regards,
[Your Name]
[Your Contact Information]

## Remediation: preventing similar infections

- **Keep endpoint protection on and current.** DarkComet is detected by essentially every antivirus. Never add unknown files to exclusions, except in a lab VM for this exercise.
- **Least privilege.** Use a standard account day to day; this limits writes to `HKLM` and system folders.
- **Block untrusted execution.** Application allow-listing (AppLocker / WDAC) would stop an unknown `.exe` running from a user folder.
- **Email and download hygiene.** Filter executables and archives at the mail gateway; train users not to open unexpected attachments or cracked software, the usual delivery routes for RATs.
- **Network controls.** Egress filtering and DNS monitoring; alert on hosts repeatedly trying to reach the same odd address/port (the RAT keeps retrying its C2).
- **Monitor persistence.** Alert on new `Run`/`RunOnce`, Winlogon and Startup-folder entries (Sysmon events 12/13, Autoruns baselines).
- **Patch and back up.** Keep the OS and software patched; keep offline backups.
- **If infected for real:** disconnect from the network, capture evidence, remove persistence, and reset every password entered on that machine, because the keylogger may have captured them.

## Ethical Hacking Report

**Why a controlled environment matters.** Malware is built to spread and to damage. Running it on a normal machine risks infecting the host, the home or company network and other people's files. A VM with a snapshot, no shared folders or clipboard, and host-only (or no) networking contains the sample and can be rolled back to a clean state. The lab exception to security controls (a Defender exclusion) exists only inside that VM.

**Legal and ethical boundaries.** Analyzing a sample you were given, on your own isolated system, for learning or defense, is legitimate. It becomes an offence when the malware or the techniques are used against systems you don't own or have no written permission to test, when malware is distributed or shared outside the exercise, or when it is deployed for any purpose other than defense. Unauthorized access, data theft and installing spying tools are crimes in most jurisdictions (for example, computer-misuse and unauthorized-access laws), regardless of intent claimed afterwards. Analysts also handle data responsibly: no real personal data goes into the lab, and findings such as IP addresses are shared through proper channels.

**Risks of running malware outside isolation.** This particular sample logs keystrokes (passwords, messages), can open a shell and the webcam, can upload and download files, and persists across reboots. On a real machine or network it could expose credentials and private files, give a remote attacker a foothold to move to other systems, and be hard to notice or fully remove. The C2 address in this sample is the loopback address, which keeps this exercise harmless; a real sample would connect to an attacker's server.

**My commitments.** The sample stays in the VM and is not redistributed. It is excluded from the repository (`.gitignore`), and the tool is built to remove this specific threat, not to spread or hide anything.
