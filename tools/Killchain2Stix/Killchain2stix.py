import os
import sys
import json
import argparse
from datetime import datetime, timezone
from stix2 import Indicator, Malware, Relationship, Bundle, AttackPattern, KillChainPhase

MITRE = "mitre-killchain"

# Parse kill chain markdown
def parse_killchain_file(filepath):
    entries = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip().startswith("|") and not line.strip().startswith("| ---"):
                    parts = [p.strip() for p in line.strip("|\n").split("|")]
                    if len(parts) == 4 and parts[1]:
                        entries.append({
                            "tactic": parts[0],
                            "tech_id": parts[1],
                            "tech_name": parts[2],
                            "context": parts[3]
                        })
    except Exception as e:
        print(f"Error reading killchain file: {e}", file=sys.stderr)
    return entries

# Parse YARA rules
def parse_yara_rules(yara_dir):
    indicators = []
    for filename in os.listdir(yara_dir):
        if filename.endswith((".yar", ".yara")):
            with open(os.path.join(yara_dir, filename)) as f:
                content = f.read()
                indicators.append(Indicator(
                    name=f"YARA Rule from {filename}",
                    pattern=content,
                    pattern_type="yara",
                    valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                ))
    return indicators

# Parse Snort rules
def parse_snort_rules(snort_dir):
    indicators = []
    for filename in os.listdir(snort_dir):
        if filename.endswith((".snort", ".rules")):
            with open(os.path.join(snort_dir, filename)) as f:
                for line in f:
                    rule = line.strip()
                    if rule and not rule.startswith("#"):
                        indicators.append(Indicator(
                            name=f"Snort Rule from {filename}",
                            pattern=rule,
                            pattern_type="snort",
                            valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                        ))
    return indicators

# Parse audit logs
def parse_audit_logs(auditd_dir):
    indicators = []
    for filename in os.listdir(auditd_dir):
        if filename.endswith((".rules", ".log")):
            with open(os.path.join(auditd_dir, filename)) as f:
                for line in f:
                    if "execve" in line or "syscall" in line:
                        pattern = f"[x-auditd:log_entry = {json.dumps(line.strip())}]"
                        indicators.append(Indicator(
                            name=f"Auditd rule from {filename}",
                            pattern=pattern,
                            pattern_type="stix",
                            valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                        ))
    return indicators

# Parse binary samples
def parse_bin_samples(samples_dir):
    indicators = []
    for filename in os.listdir(samples_dir):
        if filename.endswith((".py", ".exe", ".bin", ".sh")):
            pattern = f"[file:name = '{filename}']"
            indicators.append(Indicator(
                name=f"Executable sample: {filename}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=datetime.now(timezone.utc).replace(microsecond=0)
            ))
    return indicators

# Parse PCAPs
def parse_pcap_samples(pcaps_dir):
    indicators = []
    for filename in os.listdir(pcaps_dir):
        if filename.endswith(".pcap"):
            pattern = f"[file:name = '{filename}']"
            indicators.append(Indicator(
                name=f"PCAP file: {filename}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=datetime.now(timezone.utc).replace(microsecond=0)
            ))
    return indicators

# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a STIX bundle from killchain and detection artifacts")
    parser.add_argument("--output", default="stix_report.json", help="Path to output STIX JSON file")
    args = parser.parse_args()

    base_path = os.getcwd()
    yara_dir = os.path.join(base_path, "detection", "yara")
    snort_dir = os.path.join(base_path, "detection", "snort")
    auditd_dir = os.path.join(base_path, "detection", "auditd")
    samples_dir = os.path.join(base_path, "samples", "bin")
    pcaps_dir = os.path.join(base_path, "samples", "pcap")
    killchain_file = os.path.join(base_path, "killchain.md")

    # Parse killchain entries
    attack_patterns = []
    for entry in parse_killchain_file(killchain_file):
        attack_patterns.append(AttackPattern(
            name=entry["tech_name"],
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": entry["tech_id"],
                "url": f"https://attack.mitre.org/techniques/{entry['tech_id']}/"
            }],
            description=entry["context"],
            kill_chain_phases=[KillChainPhase(
                kill_chain_name=MITRE,
                phase_name=entry["tactic"].lower().replace(" ", "-")
            )]
        ))

    # Parse artifacts
    indicators = (
        parse_yara_rules(yara_dir) +
        parse_snort_rules(snort_dir) +
        parse_audit_logs(auditd_dir) +
        parse_bin_samples(samples_dir) +
        parse_pcap_samples(pcaps_dir)
    )

    # Optional relationship
    relationships = []
    for ind in indicators:
        relationships.append(Relationship(
            source_ref=ind.id,
            relationship_type="indicates",
            target_ref=attack_patterns[0].id
        ))

    # Output STIX bundle
    stix_bundle = Bundle(*attack_patterns, *indicators, *relationships)
    with open(args.output, "w") as f:
        f.write(stix_bundle.serialize(pretty=True))
