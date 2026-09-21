# Audit preparation notes

Personal prep for the demo and the role-play. Not required for submission; the README is the deliverable.

## 1. Submission checklist

- [ ] `main.go`, `clean_windows.go`, `clean_other.go`, `internal/` (the source code)
- [ ] `README.md` with: program explanation, walkthrough, remediation, report email, ethical report
- [ ] README email: real VM output pasted into "Proof of Mitigation", your name and contact filled in
- [ ] README claims checked against what you actually saw in the VM
- [ ] `defuse.exe` built and ready (`GOOS=windows GOARCH=amd64 go build -o defuse.exe .`)
- [ ] `git push` done and the repo opens on the platform

## 2. Demo script (follows the audit order)

**Before the audit:** VM created, snapshot taken, network host-only/none, shared folders and clipboard off. Get the files in through a virtual CD/ISO, not a shared folder.

1. **Setup.** Show the Windows VM. Add `mal-track.exe` to the Defender exclusions. Say why: it's a lab-only exception, inside an isolated VM.
2. **Launch the malware.** Run `mal-track.exe`. Open Task Manager → Details and point at the process (and `netstat -ano | findstr <PID>` to show the connection attempts to `127.0.0.1:1010`).
3. **Show persistence before removal.** `msconfig` → Startup, and `regedit` → `HKCU\...\CurrentVersion\Run` (look for `Mal-Track`). Also check the other three keys from the audit.
4. **Dry run.** In an Administrator prompt: `defuse.exe -dry-run`. Read the output aloud: it shows what it found and what it would do.
5. **Real run.** `defuse.exe`. Walk through the 6 sections as they print.
6. **Prove it.**
   - Task Manager: process gone.
   - `msconfig` Startup: entry gone.
   - `regedit`: `Run`/`RunOnce` under both HKLM and HKCU are clean.
   - The `maltrack` folder is gone.
7. **Attacker IP.** Point at the `ATTACKER IP: 127.0.0.1` line. The audit expects `127.0.0.1`.
8. **Email.** Show the README email: subject, summary, proof, IP.

## 3. Role-play: likely questions and answers

**How did you analyze the malware and identify its behavior?**
I did static analysis first, without running it. `file` and hashes identified a 32-bit Windows Delphi executable. `strings` showed the DarkComet vocabulary: Run key, Winlogon, msconfig, keylogger, remote shell, webcam. The obvious address in the strings (`127.0.0.1:1604`) was a decoy, so I looked for the real settings: they are stored in an encrypted resource called `DCDATA`. It's hex-encoded and RC4-encrypted with the known DarkComet key. Decrypting it gave the attacker address (`127.0.0.1:1010`), the Run value name (`Mal-Track`), the install path and the mutex. Then I ran it in the VM to confirm the behavior with Task Manager, `netstat`, Autoruns and the registry.

**How does your program work and how does it neutralize the malware?**
It doesn't hardcode "kill process X". It finds candidates by the indicators from the analysis, then *confirms* each file by decrypting its embedded config. Only a real DarkComet binary is touched. Then: kill the process and its children, remove persistence (Run/RunOnce, Winlogon, msconfig, Startup folders), delete the binary and the install folder, and finally re-scan and print PASS/FAIL. `-dry-run` shows the plan without changing anything.

**What impact could this malware have in an uncontrolled environment?**
It's a remote access trojan: the attacker gets a shell, a file manager, screen and webcam access, and a keylogger, so passwords, messages and files are exposed. It survives reboots. It also gives the attacker a foothold to move to other machines on the network. Here the C2 is loopback, so it's harmless in the lab, but a real sample would connect to the attacker's server.

**What would you recommend to prevent similar infections?**
Up-to-date antivirus, least privilege, application allow-listing, email and download filtering with user training, egress/DNS monitoring, alerts on new autostart entries, patching and backups. If it happened for real: isolate the machine and reset passwords, since the keylogger may have captured them.

**How did you ensure the analysis was ethical and safe?**
VM with a snapshot, no shared folders or clipboard, host-only/no network, the Defender exception only inside the VM. Static analysis before running anything. The sample stays in the lab and isn't redistributed, and the tool only removes; it doesn't spread anything.

## 4. Where to look in the code when asked

| Question | Show |
|---|---|
| How did you get the attacker IP? | `internal/config/config.go`: `Extract` → `resource` → `decrypt` |
| How do you know a file is the malware? | `clean_windows.go`: `addFile` calls `config.Extract` |
| What do you match on? | `internal/ioc/ioc.go`: `Default`, `MatchName`, `MatchCommand` |
| How do you kill it? | `internal/win/proc.go`: `Kill`, `Descendants` |
| Which persistence do you check? | `internal/win/persist.go`: `runLocations` and the scan functions |
| How do you delete the files? | `internal/win/files.go`: `RemoveFile`, `RemoveInstallDir` |
| How do you prove it's gone? | `clean_windows.go`: `verify` |
| Live connections? | `internal/win/net.go`: `TCPConns` (the data behind `netstat -ano`) |

## 5. If something goes wrong

- **Defender deletes the sample before you run it:** the exclusion wasn't added, or was added after copying. Add the exclusion first, then copy again.
- **`defuse.exe` says it isn't running as Administrator:** open an elevated prompt. HKLM keys and system paths need it.
- **"no trace of the malware found":** you ran it before launching the sample, or in a different user's session. Launch the sample and run again.
- **A file is "scheduled for deletion at next reboot":** it was locked. Reboot and re-run `defuse.exe -dry-run` to confirm it's gone.
- **Something unexpected (different path, different key):** say so and show it. Run `-dry-run`, explain that the install root was not decoded so the tool searches all common folders, and that this is why it also follows the Run value. Honest and specific beats a bluff.

## 6. Terms to be ready to explain

- **RAT** (Remote Access Trojan): malware that lets an attacker control the machine remotely.
- **C2 / C&C**: the command-and-control server the malware connects to. That's the "attacker IP".
- **Persistence**: how malware survives a reboot, here the Run registry value.
- **IOC** (indicator of compromise): a fingerprint of the malware: file name, registry value, mutex, IP.
- **Mutex**: a named lock the malware creates so only one copy runs (`DCMIN_MUTEX-NLY9NFG`).
- **RC4**: the simple stream cipher DarkComet uses to hide its config.
- **Static vs dynamic analysis**: reading the file without running it vs watching it run.
