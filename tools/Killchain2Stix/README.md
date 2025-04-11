
▗▖ ▗▖▄ █ █ ▗▞▀▘▐▌▗▞▀▜▌▄ ▄▄▄▄      ▗▄▄▄▖▄▄▄       ▗▄▄▖ ■  ▄ ▄   ▄     
▐▌▗▞▘▄ █ █ ▝▚▄▖▐▌▝▚▄▟▌▄ █   █       █ █   █     ▐▌ ▗▄▟▙▄▖▄  ▀▄▀      
▐▛▚▖ █ █ █     ▐▛▀▚▖  █ █   █       █ ▀▄▄▄▀      ▝▀▚▖▐▌  █ ▄▀ ▀▄     
▐▌ ▐▌█ █ █     ▐▌ ▐▌  █             █           ▗▄▄▞▘▐▌  █           
                                                     ▐▌              
                                                                     
                                                                     
## What is a killchain and what is a STIX2 ? 

### Killchain

The cyber kill chain is the process by which perpetrators carry out cyberattacks.

https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

### STIX

Structured Threat Information Expression (STIX) is a language and serialization format used to exchange cyber threat intelligence (CTI).
Contributing and ingesting CTI becomes a lot easier. With STIX, all aspects of suspicion, compromise and attribution can be represented clearly with objects and descriptive relationships. STIX information can be visually represented for an analyst or stored as JSON to be quickly machine readible. STIX's openness allows for integration into existing tools and products or utilized for your specific analyst or network needs.

https://oasis-open.github.io/cti-documentation/stix/intro

## What is this script for ? 

It is used to do STIX report from my basics source in a fast and correct way, simply.

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

```
python3 Killchain2stix.py --output exemple_name_report.json 
```


It going to take the "killchain.md" file, and if the syntax is correct create a STIX file with the correct killchain and artefacts
