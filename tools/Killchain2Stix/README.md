# KILLCHAIN2STIX                                                                          
                                                                     
## What is a killchain and what is a STIX2 ? 

### Killchain

The cyber kill chain is the process by which perpetrators carry out cyberattacks.

https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

### STIX

Structured Threat Information Expression (STIX) is a language and serialization format used to exchange cyber threat intelligence (CTI).
Contributing and ingesting CTI becomes a lot easier. With STIX, all aspects of suspicion, compromise and attribution can be represented clearly with objects and descriptive relationships. STIX information can be visually represented for an analyst or stored as JSON to be quickly machine readible. STIX's openness allows for integration into existing tools and products or utilized for your specific analyst or network needs.

https://oasis-open.github.io/cti-documentation/stix/intro

## What is this script for ? 

This script idea comes from the Europeean Cybersecurity project named "SOCCER" (Security Operation Centres Capacity Building for European Resilience) which aims to :

- Develop and implement cutting-edge technologies for secure data access (Security Hub) and the sharing of threat intelligence signals (TIS) across European entities, enhancing the capacity to monitor and detect cyber threats.
- Interconnect and strengthen advanced Security Operation Centres (SOCs) ecosystems in Germany, Hungary, and Romania, with the goal of enhancing cybersecurity resilience at both national and EU levels.

We help this project in part by making these threat intelligence signals of attacks and attackers which are composed by artefacts such as :

- Samples
    - Poc or Malware
    - Pcaps
-  Rules (against the compromission)
    - Snort
    - Yara
    - Audit.d
- Killchain.md 
- Report.pdf (about the attack or the attacker)

The script help to build a Stix2 report based on the above elements in a fast and correct way.

## how it works ? 

### Requirements 

first you need to create a virtual environment 
and install stix2 in it 

```
python3 -m venv myenv
source myenv/bin/activate
pip install stix2 
```

### Use the script 

To properly use the script, once you are in your virtual environment with stix installed you need to copy the script into your TIS folder well structured (you have the "Folder_for_test_exemple" as reference)


```
.
├── detection
│   ├── auditd
│   │   ├── process_monitoring.log
│   │   └── syscall_trace.log
│   ├── snort
│   │   ├── network_ids.rules
│   │   └── snort_alerts.rules
│   └── yara
│       ├── malware_rules.yar
│       └── string_match.yar
├── killchain.md
├── Report.pdf
└── samples
    ├── bin
    │   ├── malware_sample2.py
    │   ├── malware_sample3.sh
    │   ├── malware_sample4.bin
    │   └── malware_sample.exe
    └── pcap
        └── network_capture.pcap
```


Once the script into the folder you launch the script :


It going to take the "killchain.md" file, and if the syntax is correct create a STIX file with the correct killchain and artefacts

python3 Killchain2stix.py --output exemple_name_report.json 
```


It going to take the "killchain.md" file, and if the syntax is correct create a STIX file with the correct killchain and artefacts
