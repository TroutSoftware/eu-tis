## ClearFake Campaign – Fake Browser Update Infection Chain


This kill chain documents a ClearFake campaign leveraging fake browser update prompts delivered via compromised websites to deploy a modular delivery framework and downstream malware payloads. The scenario relies on social engineering and user execution rather than software exploitation.

ClearFake does not represent a standalone malware family but operates as a delivery framework that stages and distributes secondary payloads. The infection chain highlights the transition from browser-based activity to endpoint compromise, followed by payload-specific post-exploitation behavior.

---

## 1. Reconnaissance

### Attacker Activities
- Identification of legitimate, high-traffic websites suitable for compromise.
- Injection of malicious JavaScript through compromised sites or third-party resources.
- Preparation of browser-themed social engineering lures.

### Key Artifacts
- Compromised websites serving injected JavaScript.
- External JavaScript resources loaded at page view.


### Relevant Telemetry
- Web and proxy logs showing unexpected external JavaScript resources loaded by browsers.
- DNS queries associated with JavaScript delivery infrastructure.

---

## 2. Weaponization

### Attacker Activities
- Development of obfuscated JavaScript used to present fake browser update or verification prompts.
- Configuration of staged delivery mechanisms, including the use of remote resources such as web services or smart contract-based infrastructure (e.g., Binance Smart Chain) to dynamically host and retrieve next-stage instructions.
- Preparation of malware loaders and secondary payloads.
- Configuration of loader execution and command-and-control infrastructure.

### Key Artifacts
- Obfuscated JavaScript payloads.
- Malware loader binaries.
- Secondary payloads and plugins.


### Relevant Telemetry
- Web responses delivering obfuscated JavaScript.
- File reputation hits associated with known malware components.

---

## 3. Delivery

### Attacker Activities
- Delivery of fake browser update prompts via injected JavaScript on compromised websites.
- Retrieval of next-stage configuration data via remote staging mechanisms, including web services or smart contract-based infrastructure leveraged by injected JavaScript.
- Redirection or forced download of malicious update packages.

### Key Artifacts
- Fake browser update download URLs.
- Script, installer, or executable payloads delivered to the victim.


### Relevant Telemetry
- Browser download events.
- Proxy and firewall logs showing downloads from external infrastructure.

---

## 4. Exploitation

### Attacker Activities
- User execution of attacker-provided commands via fake update or verification prompts.
- Transition from browser-based execution to native endpoint execution.
- Initial command execution without exploitation of software vulnerabilities.

### Key Artifacts
- Obfuscated command-line instructions provided to the user.
- Loader execution commands.


### Relevant Telemetry
- Windows Security Event ID 4688 (process creation).
- Sysmon Event ID 1 (process creation).

---

## 5. Installation

### Attacker Activities
- Deployment of secondary malware families delivered by the ClearFake framework (e.g., Amadey, SocGholish, RaccoonStealer, StealC, HijackLoader, SystemBC, LummaStealer).
- Execution of payload-specific components using scripting engines (e.g., PowerShell).
- Establishment of persistence mechanisms depending on the delivered payload.
- Subsequent persistence, discovery, and credential access activities are performed by the delivered payloads rather than the ClearFake framework itself.

### Key Artifacts
- Malware files written to user-writable directories.
- Scheduled tasks and persistence-related commands.


### Relevant Telemetry
- Sysmon Event ID 11 (file creation).
- Scheduled task creation events.
- PowerShell Script Block Logging (Event ID 4104), where enabled.

---

## 6. Command and Control

### Attacker Activities
- Delivered malware communicates with attacker-controlled infrastructure.
- Periodic beaconing and data exchange over web protocols.
- Use of legitimate services or compromised infrastructure to blend with normal traffic.

### Key Artifacts
- C2 domains, URLs, and IP addresses.


### Relevant Telemetry
- DNS queries to external infrastructure.
- Proxy and firewall logs showing outbound HTTP/HTTPS connections.
- Repeated beaconing behavior.

---

## 7. Actions on Objectives

### Attacker Activities
- Delivery and execution of additional payloads depending on campaign objectives.
- Credential access, local discovery, and system reconnaissance.
- Potential preparation for follow-on activity such as lateral movement or ransomware deployment.

### Key Artifacts
- Secondary payload binaries.
- Additional download activity following initial compromise.


### Relevant Telemetry
- File creation and execution events following C2 communication.
- Increased outbound network activity.
