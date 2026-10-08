## EU-TIS                                                                                                                    

Hello and welcome 👋 to our support platform for threat intelligence signals sharing.

The TIS archive is created under the assistance of the European Commission-EU DIGITAL EUROPE 🇪🇺 programme, collecting full killchains of known tactics, techniques and procedures seen in the wild. The killchains are particularly useful for training exercises such at [tabletop exercises](https://www.cisa.gov/sites/default/files/publications/Cybersecurity-Tabletop-Exercise-Tips_508c.pdf), where participants from multiple teams in the organisation collaborate on a virtual situation.

The archives are available at a different web site, please open an issue if you need access for research and defense purposes.

## Submission guidelines

New killchains are always welcomed to the archive.

For confidentiality and IP reasons, we do not accept recording or artifacts without clear provenance: instead, a synthetic environment should be created, the attack performed on this environment, and the artifacts collected during the reproduction. Artifacts must be shared under a Creative Commons - Attribution license, including code and documentation.

If you want to contribute, please open an issue in the issue tracker with our “killchain submission” template.
Then submit a PR with the artifacts required to reproduce the killchain (including scripts, configuration templates, …). We will then provide you with a link to upload the resulting artifacts.

The contribution workflow and required directory structure are documented in
[`killchains/SUBMISSION_PROCESS.md`](killchains/SUBMISSION_PROCESS.md). If
anything is unclear, ask for guidance in the related issue.

The mandatory creation and validation requirements for killchains, ATT&CK Flow
files, and detection rules are defined in
[`killchains/AGENTS.md`](killchains/AGENTS.md). It also defines the read-only,
structured report that must be produced when reviewing or validating a
submission.

### Validate a submission with an agent

From an agent working in the repository, use the following prompt and replace
the example path with the submission to review:

```text
Perform a read-only submission validation of:

/home/user/wk/eu-tis/killchains/Attack-Flow/Groups-Malware/Lotus_Blossom

Follow killchains/AGENTS.md. Do not modify any files.
Perform the lightweight internet-assisted MITRE ATT&CK mapping and attribution
checks defined in AGENTS.md, and return the required structured validation
report. Clearly identify every check that could not be completed.
```

The validation step must not change the submission. After reviewing the
report, corrections can be requested separately with:

```text
Fix only the blockers identified in the previous validation report.
Follow killchains/AGENTS.md and do not apply optional suggestions.
Re-run the relevant validations and report every file changed.
```
