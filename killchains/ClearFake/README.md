# ClearFake Campaign

This folder contains a synthetic killchain scenario documenting the **ClearFake campaign**, where malicious JavaScript injected into compromised legitimate websites redirects victims to fake browser update or verification pages, leading to user-assisted execution of commands and the delivery of downstream payloads such as Amadey. ClearFake operates as a modular delivery framework rather than a standalone malware, enabling dynamic deployment of different payload families.

The scenario is designed for:

- SOC analyst training (alert triage, timeline reconstruction)
- Detection engineering (Sigma rules, behavioral detection)
- Purple-team exercises and table-top simulations
- Threat intelligence sharing in a structured, reproducible format

All artefacts are intended to be used in a **controlled lab or analytical environment**.

---

## Internal context

This scenario is based on publicly documented threat intelligence regarding the **ClearFake campaign** observed in the wild. The attack chain was reconstructed to highlight the transition from browser-based activity to endpoint compromise through social engineering and living-off-the-land techniques.

---

## Scenario Summary

1. A user visits a legitimate but compromised website.
2. Malicious ClearFake JavaScript executes in the browser and retrieves next-stage configuration data from remote resources (e.g., web services or smart contract-based infrastructure such as Binance Smart Chain).
3. The user is redirected to a fake browser update or verification page.
4. The page instructs the user to manually execute provided commands.
5. The executed commands invoke `cmd.exe` and `PowerShell` to retrieve payloads.
6. Downstream malware (e.g., Amadey):
   - Performs host and group discovery.
   - Executes anti-analysis checks (e.g., WMI temperature queries).
   - Establishes persistence via scheduled tasks.
   - Communicates with command-and-control infrastructure over HTTP/HTTPS.

The full logical sequence of the intrusion is documented in `killchain.md`.

---

## Repository Contents

This repository contains all components required to document, analyze, and detect the ClearFake campaign. The structure follows **EU-TIS recommendations** and includes full attack-chain documentation, threat intelligence artifacts, and detection content.

### **Documentation**
- **killchain.md** – Detailed step-by-step attack chain following the Cyber Kill Chain model.  
- **mitre_mapping.md** – MITRE ATT&CK techniques mapped to each phase of the intrusion.  
- **attack_flow/** – ATT&CK Flow representation of the scenario (JSON format).  

### **Threat Intelligence Artifacts**
- **metadata.json** – Full STIX 2.1 bundle containing:
  - Campaign report
  - Malware objects (ClearFake as delivery framework, Amadey as downstream payload)
  - MITRE ATT&CK attack patterns
  - Indicators of Compromise
  - Explicit relationships between all objects

### **Detection Rules**
- **detection/sigma/**  
  - Sigma detection rule(s) focused on behavioral detection of user-assisted execution, encoded PowerShell, and related activity.  
- **detection/yara/**  
  - YARA rule(s) for identifying ClearFake loader and downstream payload artifacts based on execution patterns, obfuscation, and anti-analysis behavior.


---
