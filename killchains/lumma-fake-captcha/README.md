# Fake CAPTCHA led to Lumma Stealer

This folder contains a synthetic killchain scenario where a user is tricked into executing a PowerShell command via a fake CAPTCHA page, leading to the download and execution of a Lumma Stealer–like infostealer, browser credential theft, and exfiltration over HTTPS.

The scenario is designed for:

- SOC analyst training (alert triage, timeline reconstruction)
- Detection engineering (Sigma / KQL / AQL rules)
- Purple-team exercises and table-top simulations
- Threat intelligence sharing in a structured, reproducible format

All artefacts are intended to be generated in a **controlled lab environment**. The payload behaviour can be simulated with inert binaries that only mimic process names, paths, and network connections.

---

## Internal context

This scenario is based on threat intelligence about Lumma Stealer campaigns observed in the wild and was reconstructed by the SOC team as an internal purple-team style exercise.

## Scenario Summary

1. A user visits a legitimate website whose traffic is abused to redirect through an ad/redirect chain.
2. The user lands on a fake CAPTCHA page hosted on cloud object storage.
3. The page instructs the user to press `Win + R`, paste a PowerShell command, and press `Enter`.
4. The PowerShell script and an additional `mshta.exe` call:
   - Download a ZIP archive (`afc.zip`) from cloud storage.
   - Extract a loader (`AF1.exe`, `deci.com`) and supporting DLLs.
5. The loader:
   - Accesses browser credential databases (Chrome / Edge).
   - Performs basic host and firewall discovery.
   - Exfiltrates collected data via HTTPS to Lumma-style C2 domains.

The full logical flow is documented in `killchain.md`.

---


## Repository Contents

This repository contains all components required to document, reproduce, and analyze the synthetic Lumma Stealer infection scenario delivered via a fake CAPTCHA mechanism. The structure follows EU-TIS recommendations and includes threat intelligence artifacts, detection rules, and full attack-chain documentation.

### **Documentation**
- **killchain.md** – Detailed step-by-step attack chain following the Cyber Kill Chain model.  
- **mitre_mapping.md** – MITRE ATT&CK techniques mapped to each phase of the intrusion.  
- **attack_flow/** – ATT&CK Flow representation of the scenario (JSON format).  


### **Threat Intelligence Artifacts**
- **metadata.json** – Full STIX 2.1 bundle containing indicators, malware object, ATT&CK patterns, and report metadata.  

### **Detection Rules**
- **sigma/**  
  - Sigma detection rule(s) for SIEM/log-based detection.  
- **yara/**  
  - YARA rule(s) for binary or memory-based detection of Lumma components.


### **Telemetry Samples**
- **logs/** – Representative Sysmon, PowerShell, and proxy log samples aligned to the kill chain phases (optional but recommended).






