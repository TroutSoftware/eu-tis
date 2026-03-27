# MITRE ATT&CK Mapping – ClearFake Campaign

This document maps the main steps of the ClearFake infection chain to MITRE ATT&CK tactics and techniques.

---

## Summary Table

| Killchain Phase             | Tactic                    | Technique ID | Technique Name |
|-----------------------------|---------------------------|--------------|----------------|
| Initial Access              | Initial Access            | T1189        | Drive-by Compromise |
| Execution                   | Execution                 | T1059.007    | Command and Scripting Interpreter: JavaScript |
| Stage Retrieval             | Command and Control       | T1102        | Web Service |
| User-Assisted Execution     | Execution                 | T1204        | User Execution |
| Stage 1 Execution           | Execution                 | T1059.003    | Command and Scripting Interpreter: Windows Command Shell |
| Stage 2 Execution           | Execution                 | T1059.001    | Command and Scripting Interpreter: PowerShell |
| Payload Delivery            | Command and Control       | T1105        | Ingress Tool Transfer |
| Obfuscation                 | Defense Evasion           | T1027.010    | Obfuscated Files or Information: Command Obfuscation |
| Masquerading                | Defense Evasion           | T1036        | Masquerading |
| Environment Checks          | Defense Evasion           | T1497.001    | Virtualization/Sandbox Evasion: System Checks |
| Environment Checks          | Discovery                 | T1047        | Windows Management Instrumentation |
| Local Discovery             | Discovery                 | T1069.001    | Permission Groups Discovery: Local Groups |
| Credential Access           | Credential Access         | T1555.003    | Credentials from Web Browsers |
| Command and Control         | Command and Control       | T1071.001    | Application Layer Protocol: Web Protocols |
| Persistence                 | Persistence               | T1053.005    | Scheduled Task |

---

## Detailed Mapping by Phase

### 1. Initial Access – Compromised Website (ClearFake Injection)

**Observed behaviour**

- Victims browse legitimate but compromised websites.
- Malicious JavaScript associated with the ClearFake framework is injected into the site.
- The compromised site functions as a watering-hole style distribution point.

**ATT&CK**

- **Tactic:** Initial Access – *TA0001*  
- **Technique:** **T1189 – Drive-by Compromise**

---

### 2. Browser-Based Execution – ClearFake JavaScript

**Observed behaviour**

- Malicious JavaScript executes automatically within the victim’s browser.
- The ClearFake framework profiles the victim environment and prepares staged delivery logic.
- Victims are redirected to attacker-controlled verification or fake browser update pages.

**ATT&CK**

- **Tactic:** Execution – *TA0002*  
- **Technique:** **T1059.007 – Command and Scripting Interpreter: JavaScript**

---

### 2.1 Stage Retrieval – Smart Contract / Web Service

**Observed behaviour**

- The injected JavaScript retrieves staged configuration data from remote resources.
- In some cases, this includes interaction with decentralized platforms such as Binance Smart Chain (BSC) smart contracts.
- The retrieved data may include URLs or command sequences used for subsequent payload delivery.
- This mechanism enables dynamic updates to payload delivery without modifying the compromised website.

**ATT&CK**

- **Tactic:** Command and Control – *TA0011*  
- **Technique:** **T1102 – Web Service**

---

### 3. User-Assisted Execution – Manual Command Execution

**Observed behaviour**

- The fake update or verification page instructs the user to manually execute commands.
- Users copy and run obfuscated commands using built-in Windows utilities.
- Execution depends entirely on user interaction.

**ATT&CK**

- **Tactic:** Execution – *TA0002*  
- **Technique:** **T1204 – User Execution**

---

### 4. Stage 1 Execution – Windows Command Shell

**Observed behaviour**

- The user-executed command invokes the Windows command shell.
- `cmd.exe` is used to initiate follow-on malicious activity.

**ATT&CK**

- **Tactic:** Execution – *TA0002*  
- **Technique:** **T1059.003 – Command and Scripting Interpreter: Windows Command Shell**

---

### 5. Stage 2 Execution – PowerShell Payload Retrieval

**Observed behaviour**

- PowerShell is executed with encoded commands to retrieve and execute payloads.
- Commands are obfuscated to evade detection.

**ATT&CK**

- **Tactic:** Execution – *TA0002*  
- **Technique:** **T1059.001 – Command and Scripting Interpreter: PowerShell**

---

### 6. Payload Delivery – Secondary Malware Deployment

**Observed behaviour**

- The ClearFake framework retrieves and delivers secondary malware families.
- Observed payloads include Amadey, SocGholish, RaccoonStealer, StealC, HijackLoader, SystemBC, and LummaStealer.
- Subsequent malicious activity (credential theft, persistence, C2) is performed by the delivered payloads.

**ATT&CK**

- **Tactic:** Command and Control – *TA0011*  
- **Technique:** **T1105 – Ingress Tool Transfer**

---

### 7. Obfuscation and Masquerading

**Observed behaviour**

- Commands and scripts are obfuscated to evade detection.
- Payloads masquerade as legitimate software components.

**ATT&CK**

- **Tactic:** Defense Evasion – *TA0005*  
- **Technique:** **T1027.010 – Command Obfuscation**
- **Technique:** **T1036 – Masquerading**

---

### 8. Environment and Sandbox Checks

**Observed behaviour**

- Payloads perform system and virtualization checks prior to execution.
- WMI queries and timing delays are used to evade sandbox detection.

**ATT&CK**

- **Tactic:** Defense Evasion – *TA0005*  
- **Technique:** **T1497.001 – System Checks**

- **Tactic:** Discovery – *TA0007*  
- **Technique:** **T1047 – Windows Management Instrumentation**

---

### 9. Local Discovery

**Observed behaviour**

- The malware enumerates local users and groups.

**ATT&CK**

- **Tactic:** Discovery – *TA0007*  
- **Technique:** **T1069.001 – Local Groups**

---

### 10. Credential Access – Browser Data Collection

**Observed behaviour**

- Downstream payloads extract stored browser credentials and session data.

**ATT&CK**

- **Tactic:** Credential Access – *TA0006*  
- **Technique:** **T1555.003 – Credentials from Web Browsers**

---

### 11. Command and Control over Web Protocols

**Observed behaviour**

- The compromised host communicates with attacker infrastructure over HTTP/HTTPS.

**ATT&CK**

- **Tactic:** Command and Control – *TA0011*  
- **Technique:** **T1071.001 – Web Protocols**

---

### 12. Persistence (Observed in Downstream Payloads)

**Observed behaviour**

- Secondary payloads establish persistence using scheduled tasks.

**ATT&CK**

- **Tactic:** Persistence – *TA0003*  
- **Technique:** **T1053.005 – Scheduled Task**
