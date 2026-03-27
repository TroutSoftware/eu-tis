# Kill Chain – Lumma Stealer via Fake CAPTCHA  


This document provides a structured, phase-by-phase overview of the attack chain used in the synthetic Lumma Stealer infection scenario. It follows the Cyber Kill Chain model and outlines attacker actions, telemetry, and key IOC artifacts associated with each phase.

---

## 1. Reconnaissance

### Attacker Activities
- Use of a compromised website to attract the victim.
- Multi-stage redirection chain toward attacker-controlled infrastructure.
- Hosting of a fake CAPTCHA page to perform social engineering.

### Key Artifacts (IOCs)
- Compromised entry domain: `astapowerproject[.]net`
- Redirectors:
  - `871549.eliteeyeview[.]co`
  - `myvantage.getitquickly[.]biz`
- Fake CAPTCHA host: `657.s3.fr-par.scw[.]cloud`

### Relevant Telemetry
- Web proxy / URL filtering logs  
- DNS queries for redirector domains

---

## 2. Weaponization

### Attacker Activities
- Preparation of an obfuscated PowerShell one-liner for initial staging.
- Hosting of malicious HTA/JavaScript executed through `mshta.exe`.
- Packaging of Lumma components in `afc.zip`, containing:
  - `AF1.exe`
  - `IconX.dll`
  - `dx0.dll`
  - `DirectGUI.dll`
  - `deci.com` (AutoIt-based script)

### Key Artifacts (IOCs)
- Shortener domain: `2no[.]co`
- PowerShell staging URL: `https://2no.co/2OArm3`
- HTA payload URL: `https://2no.co/2Od3Q3`

### Relevant Telemetry
- None on the victim side (weaponization is attacker-controlled)

---

## 3. Delivery

### Attacker Activities
- Victim reaches the compromised domain.
- Browser is redirected through the attacker’s infrastructure.
- The fake CAPTCHA instructs the victim to press **WIN+R** and paste a PowerShell command.

### Key Artifacts (IOCs)
- Fake CAPTCHA page: `657.s3.fr-par.scw[.]cloud`
- Redirectors: `2no[.]co`

### Relevant Telemetry
- Web proxy logs (full redirect chain)
- DNS queries

---

## 4. Exploitation

### Attacker Activities
- User executes the malicious PowerShell command via Windows Run dialog.
- PowerShell launches in hidden mode (`-WindowStyle Hidden -NoProfile`).
- Remote scripts are downloaded and executed in memory.

### Key Artifacts (IOCs)
- `powershell.exe` spawned by `explorer.exe`
- Obfuscated commands using:
  - `Invoke-RestMethod`
  - `iex`

### Relevant Telemetry
- Sysmon Event ID 1 (Process Create)
- Windows Event ID 4688
- PowerShell Operational 4104 (script block logging)

---

## 5. Installation

### Attacker Activities
- Download of the `afc.zip` archive from attacker hosting.
- Extraction of Lumma loader components.
- Execution of `AF1.exe` and AutoIt-based modules (`deci.com`).

### Key Artifacts (IOCs)
- Archive URL: `https://pub-24086c859ed94d628b911deba63401ab.r2.dev/afc.zip`
- File hashes (SHA1):
  - `afc.zip` – `5ceb5281b941699aacc2ea347494863cff583adf`
  - `AF1.exe` – `7bca3ceb680ad8cb1f3cd0d24d106a28c813ce3b`
  - `IconX.dll` – `cf290cd98b3779e1e6b58441505d4dd411cdb541`
  - `dx0.dll` – `3748ccd9f716e4668af8672e037b5729074e36c1`
  - `DirectGUI.dll` – `5e5f646f6b1f67519cabff1451aa3427eb46989f`

### Relevant Telemetry
- Sysmon Event ID 11 (File Create)
- Sysmon Event ID 7 (Image Load)
- Sysmon Event ID 1 (Process Execution)

---

## 6. Command and Control (C2)

### Attacker Activities
- Lumma establishes encrypted HTTPS connections to multiple C2 domains.
- Periodic beacons with stolen data.

### C2 Domains (IOCs)
- `blameaowi[.]run`
- `flowerexju[.]bet`
- `mzmedtipp[.]live`
- `easterxeen[.]run`
- `araucahkbm[.]live`
- `overcovtcg[.]top`
- `blackswmxc[.]top`
- `posseswsnc[.]top`
- `4featurlyin[.]top`

### C2 URLs (Examples)
- `https://blameaowi.run/twiu`
- `https://flowerexju.bet/lanz`
- `https://mzmedtipp.live/mnvzx`

### Relevant Telemetry
- Proxy logs (HTTPS sessions to rare domains)
- DNS logs
- Firewall logs (destination IP reputation)

---

## 7. Actions on Objectives (Credential Theft & Exfiltration)

### Attacker Activities
- Extraction of browser-stored credentials:
  - Chrome/Edge `Login Data`
  - `Web Data` SQLite databases
- System profiling and firewall discovery.
- Exfiltration of stolen data via HTTPS POST requests to C2 endpoints.

### Key Indicators
- Suspicious access to browser credential databases.
- AutoIt script execution (`deci.com`).
- HTTPS POST requests to attacker C2 URLs.

### Relevant Telemetry
- Sysmon Event ID 10 (File Access – credential DBs)
- Proxy logs (POST requests to C2 domains)
- PowerShell logs (if fallback scripts executed)

---

## Summary

This kill chain describes the complete flow of a Lumma Stealer infection delivered through a fake CAPTCHA mechanism. It includes:

- Social engineering  
- PowerShell and mshta-based execution  
- Multi-stage payload delivery  
- C2 communication  
- Credential theft  
- Data exfiltration  



