# STIX Report Generator Script with Artifact Parsing (with file input and CLI args)

import os
import sys
import argparse
from datetime import datetime, timezone
from stix2 import (Indicator, Malware, Relationship, Bundle, AttackPattern, KillChainPhase)

# Constants for kill chain
MITRE = "mitre-killchain"

# Create Kill Chain Phase helper
def create_killchain_phase(phase_name):
    return KillChainPhase(
        kill_chain_name=MITRE,
        phase_name=phase_name.lower().replace(" ", "-")
    )

# Create Attack Pattern helper
def create_attack_pattern(tid, name, description, phase):
    return AttackPattern(
        name=name,
        external_references=[{
            "source_name": "mitre-attack",
            "external_id": tid,
            "url": f"https://attack.mitre.org/techniques/{tid}/"
        }],
        description=description,
        kill_chain_phases=[create_killchain_phase(phase)]
    )

# Create Indicator from pattern text
def create_indicator(pattern_text, name):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return Indicator(
        name=name,
        pattern_type="stix",
        pattern=pattern_text,
        valid_from=now
    )

# Parse kill chain file (markdown style)
def parse_killchain_file(filepath):
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading killchain file: {e}", file=sys.stderr)
        return []

    entries = []
    for line in lines:
        if line.strip().startswith("|") and not line.strip().startswith("| ---"):
            parts = [p.strip() for p in line.strip("|\n").split("|")]
            if len(parts) == 4 and parts[1]:
                entries.append({
                    "tactic": parts[0],
                    "tech_id": parts[1],
                    "tech_name": parts[2],
                    "context": parts[3]
                })
    return entries

# Parse YARA rules into Indicators
def parse_yara_rules(yara_dir):
    indicators = []
    for filename in os.listdir(yara_dir):
        if filename.endswith(".yar"):
            with open(os.path.join(yara_dir, filename)) as f:
                content = f.read()
                pattern = f"[x-yara:rule_text = '{content[:100].replace("'", "\'")}...']"
                indicators.append(create_indicator(pattern, f"YARA Rule from {filename}"))
    return indicators

# Parse Snort rules into Indicators
def parse_snort_rules(snort_dir):
    indicators = []
    for filename in os.listdir(snort_dir):
        if filename.endswith(".snort"):
            with open(os.path.join(snort_dir, filename)) as f:
                for line in f:
                    if line.strip() and not line.strip().startswith("#"):
                        pattern = f"[x-snort:rule = '{line.strip().replace("'", "\'")}']"
                        indicators.append(create_indicator(pattern, f"Snort Rule from {filename}"))
    return indicators

# Parse audit logs into Indicators
def parse_audit_logs(auditd_dir):
    indicators = []
    for filename in os.listdir(auditd_dir):
        if filename.endswith(".rules"):
            with open(os.path.join(auditd_dir, filename)) as f:
                for line in f:
                    if "execve" in line or "syscall" in line:
                        pattern = f"[x-auditd:log_entry = '{line.strip().replace("'", "\'")}']"
                        indicators.append(create_indicator(pattern, f"Auditd rule from {filename}"))
    return indicators


# Reference executable samples as Indicators
def parse_bin_samples(samples_dir):
    indicators = []
    for filename in os.listdir(samples_dir):
        if filename.endswith((".py", ".exe", ".bin", ".sh")):
            pattern = f"[file:name = '{filename}']"
            indicators.append(create_indicator(pattern, f"Executable sample: {filename}"))
    return indicators

# Reference PCAP files as Indicators 
def parse_pcap_samples(pcaps_dir):
    indicators = []
    for filename in os.listdir(pcaps_dir):
        if filename.endswith(".pcap"):
            pattern = f"[file:name = '{filename}']"
            indicators.append(create_indicator(pattern, f"PCAP file: {filename}"))
    return indicators


# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a STIX bundle from killchain and detection artifacts")
    parser.add_argument("--output", default="stix_report.json", help="Path to output STIX JSON file")
    args = parser.parse_args()

    try:
        base_path = os.getcwd()
        yara_dir = os.path.join(base_path, "detection", "yara")
        snort_dir = os.path.join(base_path, "detection", "snort")
        auditd_dir = os.path.join(base_path, "detection", "auditd")
        samples_dir = os.path.join(base_path, "samples", "bin")
        pcaps_dir = os.path.join(base_path, "samples", "pcap")

        killchain_file = os.path.join(base_path, "killchain.md")

        attack_patterns = []
        killchain_entries = parse_killchain_file(killchain_file)
        for entry in killchain_entries:
            ap = create_attack_pattern(
                tid=entry["tech_id"],
                name=entry["tech_name"],
                description=entry["context"],
                phase=entry["tactic"]
            )
            attack_patterns.append(ap)

        indicators = []
        indicators += parse_yara_rules(yara_dir)
        indicators += parse_snort_rules(snort_dir)
        indicators += parse_audit_logs(auditd_dir)
        indicators += parse_bin_samples(samples_dir)
        indicators += parse_pcap_samples(pcaps_dir)

        relationships = []
        if indicators and attack_patterns:
            relationships.append(Relationship(indicators[0], "indicates", attack_patterns[0]))

        stix_bundle = Bundle(*attack_patterns, *indicators, *relationships)
        with open(args.output, "w") as f:
            f.write(stix_bundle.serialize(pretty=True))

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
