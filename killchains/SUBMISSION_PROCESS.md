# Submission Process for `killchains`

This document explains how to submit content for the `killchains` area of the repository.

There are two different submission types:

1. `Attack-Flow`
2. CTI bundle folders: `Products`, `Techniques`, and `Threat-actors`

## 1. `Attack-Flow` submissions

`Attack-Flow` is reserved for TTP killchain content built with MITRE tools:

- Use MITRE ATT&CK as the framework reference.
- Build the flow with MITRE ATT&CK Flow Builder.
- Submit the editable `.afb` file.
- Submit an exported image such as `.png` for quick review.

Expected structure:

```text
Attack-Flow/
  <topic>/
    <attack-flow>.afb
    <attack-flow>.png
```

Examples already present in the repository:

```text
Attack-Flow/Generalities_in_ICS_attacks/Generalities in ICS attacks #1.afb
Attack-Flow/Generalities_in_ICS_attacks/Generalities in ICS attacks #1.png
```

Use `Attack-Flow` only when the submission is an ATT&CK-based flow or killchain created with MITRE ATT&CK Flow Builder.

## 2. CTI bundle submissions in the other folders

The other folders are for CTI bundles such as:

- `Products`
- `Techniques`
- `Threat-actors`

These submissions should be organized by subject, then by detection content, then by tool, then by rules or related files.

Expected structure:

```text
<category>/
  <subject>/
    detection/
      <tool>/
        <rule-or-artifact>
```

Typical examples:

```text
Products/CVE-2024-12728/detection/snort/brut-force.snort
Techniques/T1071_004_Application_Layer_Protocol_DNS/detection/snort/DNS-tunneling.snort
Threat-actors/Clearfake/detection/sigma/sigma_clearfake_campaign.yml
```

Possible tools under `detection/` include:

- `snort`
- `sigma`
- `yara`
- `auditd`
- other detection tooling when relevant

Use these folders when the submission is a CTI detection bundle and not an ATT&CK Flow Builder killchain.

## 3. Git submission workflow for contributors using a fork

When contributing, the contributor should work from a fork of the official repository:

- Official repository: `https://github.com/TroutSoftware/eu-tis/`

Recommended workflow:

1. Fork the official repository on GitHub.
2. Clone your fork locally.
3. Add the official repository as `upstream`.
4. Create an issue on the official repository describing the change you want to submit.
5. Update your local `main` branch with the latest changes before starting work.
6. Create your own branch from `main`.
7. Make your changes in the correct folder.
8. Commit your work with a clear message.
9. Push the branch to your fork.
10. Open a pull request from your fork branch to the official repository.
11. After the work is merged, delete the branch locally and on your fork.

Example commands:

```bash
git clone https://github.com/<your-user>/eu-tis.git
cd eu-tis
git remote add upstream https://github.com/TroutSoftware/eu-tis.git

git checkout main
git pull upstream main
git push origin main

git checkout -b issue-123-attack-flow-update

# make your changes
git add killchains/
git commit -m "Add new attack flow and detection content"

git push -u origin issue-123-attack-flow-update
```

Then open the pull request:

- Source: your fork branch
- Target: `TroutSoftware/eu-tis` on `main`

## 4. Important reminders

- Always create or reference an issue on the official repository before submitting.
- Always `git pull` to get the latest updates before creating your branch.
- Keep `Attack-Flow` content separate from CTI bundle content.
- Put CTI bundle files under the correct subject and detection tool.
- Push changes to your fork, not directly to the official repository.
- Open the pull request against the official repository.

After the pull request is merged, clean up your branch:

```bash
git checkout main
git pull upstream main
git branch -d issue-123-attack-flow-update
git push origin --delete issue-123-attack-flow-update
```
