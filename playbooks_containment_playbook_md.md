# Playbook: ClickFix / Browser Stealer Triage & Response

## 1. Identification & Visual Verification

* [ ] Confirm alert triggers on `powershell.exe` spawned from `explorer.exe` with `-w h` or `iex`.
* [ ] Inspect Registry Path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`.
* [ ] Extract outbound connections from PowerShell or child executables to identify C2 IPs/domains.

### Console Reference: Alert & Endpoint Tree
![Alert View](../screenshots/Captura%20de%20pantalla%202026-10-28%20180458.jpg)
![Endpoint Tree](../screenshots/Captura%20de%20pantalla%202026-10-28%20185143.jpg)

---

## 2. Immediate Containment

* [ ] **Isolate Endpoint:** Issue network isolation command via EDR immediately. DO NOT SHUT DOWN.
* [ ] **Revoke Active Cloud Tokens:** Trigger Global Sign-Out / Session Revocation on Azure AD / M365 console.
* [ ] **Reset Account Credentials:** Force change of Active Directory domain password.
* [ ] **Firewall & DNS Block:** Add staging and C2 endpoints to global perimeter drop lists:
  * `captcha-verify-cdn.example` (`198.51.100.150`)
  * `tracker-stats.example` (`198.51.100.152`)

---

## 3. Evidence Preservation & Eradication

* [ ] Dump volatile system memory (RAM) via EDR live response tool.
* [ ] Collect forensic copies of dropped binaries:
  * `%LOCALAPPDATA%\Temp\VCRedist\svhelper.exe`
* [ ] Record hashes (SHA-256: `0758EE26757EAC80FE1DF6FE6A84745CA9429E268635EE886D58C035CDEEB289`) and upload to sandbox/VT for attribution.
* [ ] Terminate active malicious process tree (`svhelper.exe` PID `6744`).
* [ ] Quarantine/remove the staging directory `%LOCALAPPDATA%\Temp\VCRedist\`.

---

## 4. Post-Incident Review & Hardening

* [ ] Require victim to reset all personal third-party passwords saved within browser autofill.
* [ ] Verify that no new MFA device or authenticator app was registered to the victim's tenant account during the compromise window.
* [ ] Deploy GPO restricting `RunMRU` / Windows Run shortcut for non-technical organizational units.