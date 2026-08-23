#!/usr/bin/env python3

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
INPUT_PATH = REPO_ROOT / "infra_outputs.json"
OUTPUT_PATH = REPO_ROOT / "ansible" / "inventory" / "inventory.yml"


def main() -> None:
    payload = json.loads(INPUT_PATH.read_text())
    hosts = payload["hosts"]["value"]

    groups = {}
    all_hosts = {}

    for hostname, metadata in sorted(hosts.items()):
        ipv4 = metadata["ipv4"]
        all_hosts[hostname] = {"ansible_host": ipv4}
        for group in metadata["ansible_groups"]:
            groups.setdefault(group, {})
            groups[group][hostname] = {"ansible_host": ipv4}

    lines = ["all:", "  hosts:"]
    for hostname, hostvars in all_hosts.items():
        lines.append(f"    {hostname}:")
        lines.append(f"      ansible_host: {hostvars['ansible_host']}")

    lines.append("  children:")
    for group_name in sorted(groups):
        lines.append(f"    {group_name}:")
        lines.append("      hosts:")
        for hostname, hostvars in sorted(groups[group_name].items()):
            lines.append(f"        {hostname}:")
            lines.append(f"          ansible_host: {hostvars['ansible_host']}")

    OUTPUT_PATH.write_text("\n".join(lines) + "\n")
    print(f"Wrote inventory to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
