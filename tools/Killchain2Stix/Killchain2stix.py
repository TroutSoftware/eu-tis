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
    seen_tech_ids = set()  # Pour éviter les doublons
    try:
        with open(filepath, 'r') as f:
            line_num = 0
            for line in f:
                line_num += 1
                # Ignorer les lignes vides, les en-têtes et les séparateurs
                if (not line.strip() or
                    line.strip().startswith("| ---") or
                    line.strip().startswith("| Tactic") or
                    line.strip().startswith("| Phase")):
                    continue

                # Parser les lignes de données
                if line.strip().startswith("|"):
                    parts = [p.strip() for p in line.strip("|\n").split("|")]

                    # Debug: afficher les parties parsées
                    print(f"DEBUG Line {line_num}: {len(parts)} parts: {parts}", file=sys.stderr)

                    # Vérifier que nous avons au moins 4 parties et un tech_id valide
                    if len(parts) >= 4 and len(parts[1].strip()) > 0:
                        tech_id = parts[1].strip()

                        # Éviter les doublons basés sur tech_id + tactic
                        unique_key = f"{parts[0].strip()}_{tech_id}"
                        if unique_key not in seen_tech_ids:
                            seen_tech_ids.add(unique_key)
                            entries.append({
                                "tactic": parts[0].strip(),
                                "tech_id": tech_id,
                                "tech_name": parts[2].strip(),
                                "context": parts[3].strip() if len(parts) > 3 else ""
                            })
                            print(f"DEBUG: Added entry: {tech_id} - {parts[2].strip()}", file=sys.stderr)
                        else:
                            print(f"DEBUG: Skipped duplicate: {unique_key}", file=sys.stderr)
                    else:
                        print(f"DEBUG: Ignored invalid line {line_num}: {parts}", file=sys.stderr)
    except Exception as e:
        print(f"Error reading killchain file: {e}", file=sys.stderr)

    print(f"DEBUG: Total entries parsed: {len(entries)}", file=sys.stderr)
    return entries

# Parse YARA rules
def parse_yara_rules(yara_dir):
    indicators = []
    try:
        if not os.path.exists(yara_dir):
            return indicators
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
    except Exception as e:
        print(f"Error reading YARA directory: {e}", file=sys.stderr)
    return indicators

# Parse Snort rules
def parse_snort_rules(snort_dir):
    indicators = []
    try:
        if not os.path.exists(snort_dir):
            return indicators
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
    except Exception as e:
        print(f"Error reading Snort directory: {e}", file=sys.stderr)
    return indicators

# Parse audit logs
def parse_audit_logs(auditd_dir):
    indicators = []
    try:
        if not os.path.exists(auditd_dir):
            return indicators
        for filename in os.listdir(auditd_dir):
            if filename.endswith((".rules", ".log")):
                with open(os.path.join(auditd_dir, filename)) as f:
                    for line_num, line in enumerate(f, 1):
                        try:
                            # Traiter les lignes auditd sans JSON strict
                            if "execve" in line or "syscall" in line or line.strip().startswith("-a"):
                                # Échapper les caractères problématiques pour STIX
                                escaped_line = line.strip().replace('"', '\\"').replace('\n', '\\n')
                                pattern = f"[x-auditd:log_entry = \"{escaped_line}\"]"
                                indicators.append(Indicator(
                                    name=f"Auditd rule from {filename}",
                                    pattern=pattern,
                                    pattern_type="stix",
                                    pattern_version="2.1",
                                    valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                                ))
                        except Exception as line_error:
                            print(f"Warning: Skipped invalid auditd line {line_num} in {filename}: {line_error}", file=sys.stderr)
                            continue
    except Exception as e:
        print(f"Error reading Auditd directory: {e}", file=sys.stderr)
    return indicators

# Parse fanotify rules
def parse_fanotify_rules(fanotify_dir):
    indicators = []
    try:
        if not os.path.exists(fanotify_dir):
            return indicators
        for filename in os.listdir(fanotify_dir):
            if filename.endswith(".py"):
                pattern = f"[file:name = '{filename}']"
                indicators.append(Indicator(
                    name=f"Fanotify rule from {filename}",
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                ))
    except Exception as e:
        print(f"Error reading Fanotify directory: {e}", file=sys.stderr)
    return indicators

# Parse binary samples
def parse_bin_samples(samples_dir):
    indicators = []
    try:
        if not os.path.exists(samples_dir):
            return indicators
        for filename in os.listdir(samples_dir):
            if filename.endswith((".py", ".exe", ".bin", ".sh")):
                pattern = f"[file:name = '{filename}']"
                indicators.append(Indicator(
                    name=f"Executable sample: {filename}",
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                ))
    except Exception as e:
        print(f"Error reading samples directory: {e}", file=sys.stderr)
    return indicators

# Parse PCAPs
def parse_pcap_samples(pcaps_dir):
    indicators = []
    try:
        if not os.path.exists(pcaps_dir):
            return indicators
        for filename in os.listdir(pcaps_dir):
            if filename.endswith(".pcap"):
                pattern = f"[file:name = '{filename}']"
                indicators.append(Indicator(
                    name=f"PCAP file: {filename}",
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                ))
    except Exception as e:
        print(f"Error reading PCAP directory: {e}", file=sys.stderr)
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
    fanotify_dir = os.path.join(base_path, "detection", "fainotify")
    samples_dir = os.path.join(base_path, "samples", "bin")
    pcaps_dir = os.path.join(base_path, "samples", "pcap")
    killchain_file = os.path.join(base_path, "killchain.md")

    # Parse killchain entries - avec fallback vers le parent
    attack_patterns = []

    # Essayer d'abord dans le dossier courant
    if os.path.exists(killchain_file):
        print(f"DEBUG: Found killchain.md in current directory: {killchain_file}", file=sys.stderr)
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
    else:
        # Fallback: essayer dans le dossier parent (cas Sophos)
        parent_killchain = os.path.join(os.path.dirname(base_path), "killchain.md")
        if os.path.exists(parent_killchain):
            print(f"DEBUG: Found killchain.md in parent directory: {parent_killchain}", file=sys.stderr)
            for entry in parse_killchain_file(parent_killchain):
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
        else:
            print(f"Warning: killchain file not found in current or parent directory", file=sys.stderr)
            print(f"  Tried: {killchain_file}", file=sys.stderr)
            print(f"  Tried: {parent_killchain}", file=sys.stderr)

    # Parse artifacts
    indicators = (
        parse_yara_rules(yara_dir) +
        parse_snort_rules(snort_dir) +
        parse_audit_logs(auditd_dir) +
        parse_fanotify_rules(fanotify_dir) +
        parse_bin_samples(samples_dir) +
        parse_pcap_samples(pcaps_dir)
    )

    # Optional relationship - seulement si on a des attack patterns
    relationships = []
    if attack_patterns and indicators:
        for ind in indicators:
            relationships.append(Relationship(
                source_ref=ind.id,
                relationship_type="indicates",
                target_ref=attack_patterns[0].id
            ))
    elif not attack_patterns:
        print("Warning: No attack patterns found, skipping relationships", file=sys.stderr)
    elif not indicators:
        print("Warning: No indicators found, skipping relationships", file=sys.stderr)

    # Output STIX bundle
    stix_bundle = Bundle(*attack_patterns, *indicators, *relationships)
    with open(args.output, "w") as f:
        f.write(stix_bundle.serialize(pretty=True))
