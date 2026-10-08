# Instructions for `killchains/`

## Scope and authority

This file applies to everything below `killchains/`. Read the repository
`README.md` and `killchains/SUBMISSION_PROCESS.md` before reviewing or changing
content here.

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are used
as requirement levels. A failed MUST or REQUIRED item is a merge blocker for
new or modified content. Historical files do not waive these requirements and
must not be copied blindly. Do not refactor unrelated historical submissions
as part of a focused change.

## Purpose and safety boundary

Content in this tree is defensive cyber-threat intelligence intended for
research, detection engineering, and collaborative training exercises.

- Every submission MUST have clear provenance and MUST reference its official
  EU-TIS issue.
- Claims about an incident, actor, CVE, or observed TTP MUST be supported by
  cited sources. Clearly distinguish observed behavior from inference,
  hypotheses, and exercise-only additions.
- Do not add credentials, personal data, customer data, production addresses,
  or confidential incident material.
- Recordings, packet captures, malware, logs, and similar artifacts MUST come
  from a documented synthetic reproduction environment unless their lawful
  redistribution and provenance are explicit. Follow the artifact and
  Creative Commons Attribution requirements in the root `README.md`.
- Do not weaken or remove a control merely to make an attack simulation work.
  Keep dangerous samples and executable exploit material out of a change
  unless the issue explicitly authorizes them and safe handling is documented.

## Select the correct submission type

There are two distinct layouts. Do not mix them.

### ATT&CK Flow Builder killchains

Use `Attack-Flow/` only for flows created with the MITRE ATT&CK Flow Builder:

```text
Attack-Flow/
  <collection>/                 # when applicable
    <topic>/
      <flow-name>.afb
      <flow-name>.png
```

Current collections include `Groups-Malware`, `Renowned_attack`, and
`Generalities_in_ICS_attacks`. Place a new topic beside the closest existing
peer. Additional documentation may live in the topic directory, but it does
not replace either required flow file.

### Detection/CTI bundles

Use exactly one subject category and put each detection artifact under its
tool directory:

```text
Products/<CVE-or-product>/detection/<tool>/<artifact>
Techniques/<ATT&CK-technique>/detection/<tool>/<artifact>
Threat-actors/<actor-or-malware>/detection/<tool>/<artifact>
```

Use lowercase tool directory names such as `snort`, `yara`, `sigma`, `auditd`,
`sysmon`, or `fainotify`. A rule MUST detect behavior relevant to its parent
subject; a generic or unrelated rule belongs elsewhere.

## Required Attack Flow content

Create and edit flows with the official ATT&CK Flow Builder at
<https://center-for-threat-informed-defense.github.io/attack-flow/ui/>. The
Builder's editable export is the source of truth.

Every new or modified flow MUST meet all of these gates:

1. Include both an importable `.afb` export and a current, readable `.png`
   export of the same revision. New pairs MUST use the same basename. A JSON
   summary, Markdown reconstruction, or screenshot alone is not a substitute.
2. Keep the `.afb` as valid JSON in a schema emitted by the official Builder.
   Do not hand-convert it to an invented or simplified schema, reformat it for
   style alone, or remove IDs and layout data used by the Builder.
3. Populate flow metadata: a precise name, a concise description, author or
   contributing organization, scope, creation/update information, and
   external references. References MUST include the EU-TIS issue and the
   sources supporting the flow's material claims.
4. Model the complete relevant sequence, including meaningful alternate paths
   and conditions. Connectors MUST express causal/temporal order and must not
   leave accidental orphan nodes.
5. Map action nodes to the correct MITRE ATT&CK tactic and technique or
   sub-technique for the applicable Enterprise, Mobile, or ICS domain. Verify
   IDs and names against ATT&CK. If an action intentionally has no mapping,
   explain why in its description.
6. Give each action a short, scenario-specific description that explains what
   happened, on which asset or identity, and why the mapping applies. Do not
   merely restate the technique name.
7. Represent relevant assets, identities, and supporting context explicitly.
   Use confidence and time fields when the sources support them; do not invent
   exact times, attribution, tooling, or certainty.
8. Keep the exported diagram suitable for review and tabletop use: no clipped
   nodes, illegible text, unexplained abbreviations, overlapping objects, or
   ambiguous connector paths.

When an existing `.afb` and `.png` have legacy naming differences, confirm
that they are the same flow and revision. Fix the pair when the flow itself is
being substantially revised, but do not create noisy rename-only changes in
an unrelated pull request.

## Required detection content

Every detection contribution MUST:

- explain the behavior it detects and identify the relevant ATT&CK technique,
  CVE, actor, or killchain step;
- cite the EU-TIS issue and authoritative technical source(s) in rule metadata,
  comments, or adjacent documentation;
- state its supported engine and version when syntax or semantics differ by
  version;
- keep site-specific networks, paths, thresholds, and similar tuning values
  configurable where the rule format permits;
- document important data-source, logging, inspector, privilege, and deployment
  prerequisites;
- be syntax-checked with the target engine and, where fixtures exist, tested
  against both expected malicious/synthetic input and benign input;
- avoid claiming that an alert proves compromise when it detects only a weak
  indicator or anomaly; and
- contain no placeholder IDs, copied metadata, duplicate identifiers, secrets,
  or unexplained dead rules.

### Snort 3

New Snort submissions MUST use the repository's two-file convention:

```text
detection/snort/<name>.snort          # Snort 3 Lua configuration
detection/snort/<name>-detect.snort   # rules included by that configuration
```

The configuration MUST enable the required inspectors/binders, define named
network variables, include the rule file by its correct relative path, and
define every custom classification used by its rules. Rule headers SHOULD use
those variables rather than embedding exercise IP addresses.

Each rule MUST have:

- a specific `msg`;
- an EU-TIS issue `reference:url` and a `reference:cve` when applicable;
- a `classtype` that resolves in the accompanying configuration;
- a repository-wide unique local `sid` and an integer `rev` (increment `rev`
  whenever detection logic changes); and
- constrained protocol, direction, ports, flow/state, content, and threshold
  logic appropriate to the behavior.

Before accepting a Snort change, check every `include`, variable, and
classification; search all of `killchains/` for SID collisions; run a Snort 3
configuration test; and replay a relevant synthetic PCAP when one is legally
available. Record the exact commands and outcomes in the pull request. Do not
approve a rule solely because its text parses: assess obvious evasion paths
and false-positive impact.

### YARA

YARA rules MUST have a unique valid rule name and metadata containing at least
description, author, date, and issue/source reference. Prefer durable,
behavior-specific strings over a single hash or common plaintext string. Use
file-size/offset/count constraints where appropriate, and compile the rule
with the supported YARA version. Test matching and non-matching synthetic
fixtures when available.

### Sigma

Sigma rules MUST contain a unique UUID, title, status, description, author,
date, references, log source, detection and condition, false-positive notes,
level, and applicable ATT&CK tags. Validate the YAML and Sigma schema, and
confirm that selected fields exist in the stated log source.

### auditd and host rules

Audit rules MUST document the intended rules file, required privileges,
watched path or syscall, permissions/filters, and stable key. Validate with
the target audit tooling when available and assess event volume. Host scripts
such as fanotify detectors MUST document runtime dependencies, privileges,
configuration points, and a safe stop/cleanup procedure.

## Validation for changes and reviews

Run the checks relevant to the changed files. At minimum:

```bash
# All changed AFB exports must parse as JSON.
jq empty path/to/flow.afb

# Confirm that each new AFB has its PNG peer and inspect the image.
file path/to/flow.png

# Look for duplicate Snort SIDs across the tree.
rg -n --glob '*.snort' 'sid\s*:' killchains/
```

Also import every changed `.afb` into the official Builder and confirm that it
renders without missing objects, then compare it with the committed PNG. Use
the native validator or dry-run mode for every changed rule format. If a
required engine is unavailable, say exactly which check was not run; do not
report it as passing.

Keep generated caches, editor files, transient logs, unapproved binaries, and
local test output out of the repository.

### Lightweight ATT&CK mapping validation

For every added or modified action node, perform a lightweight mapping review.
Internet research is supporting evidence for this review; it is not permission
to add new claims or silently rewrite the submitted flow.

1. Compare the submitted technique ID, technique name, tactic, sub-technique
   parent, ATT&CK domain, and revoked/deprecated status with current official
   MITRE ATT&CK data.
2. Compare the scenario-specific action description with the official
   technique definition. Check whether a more precise sub-technique exists and
   whether the mapping describes the behavior rather than merely the
   attacker's presumed objective.
3. Check the submission's cited sources for evidence that the behavior was
   used in the named incident or by the named actor. Prefer MITRE ATT&CK, CISA,
   government advisories, original incident reporting, and named security
   vendor research over aggregators and unattributed summaries.
4. Check basic flow plausibility: required preceding access, privileges,
   assets, or execution steps; causal order; branch conditions; and whether
   observed and inferred steps are distinguished.
5. Do not treat absence from public reporting as proof that an action did not
   occur. Do not treat a single secondary source as certain attribution.
6. Record the URLs consulted, access date, and ATT&CK version when available.
   Keep quotations minimal and distinguish source statements from reviewer
   inference.

Classify each reviewed mapping as exactly one of:

- **Confirmed by cited evidence**: the ID/name/domain are valid, the behavior
  fits, and a cited source supports its use in this scenario.
- **Valid but imprecise**: the mapping is structurally valid, but another
  technique or sub-technique describes the submitted behavior more precisely.
- **Plausible but unsupported**: the behavior could fit the mapping, but the
  reviewed sources do not support its use or attribution in this scenario.
- **Invalid**: the ID/name pair, tactic, parent, domain, or behavior is
  incompatible with current ATT&CK data.
- **Not validated**: evidence, network access, tooling, or available context
  was insufficient. State what is missing.

An agent MUST NOT mark semantic fit or actor attribution as certain based only
on a syntactically valid ATT&CK ID. When internet access is unavailable, still
perform local structural and logical checks and report the external validation
gap.

## Review protocol

Requests to "review", "validate", "audit", or "check" a submission are
read-only by default. They authorize reading files, inspecting images, running
non-mutating validation commands, and consulting public sources. They do not
authorize edits, generated files in the submission, commits, pushes, or pull
requests. Modify content only when the user explicitly asks to fix, update, or
implement changes. Temporary validation output MUST stay outside the
submission and be removed after use.

When asked to review a change, inspect the diff and the related files needed
to verify it. Treat the following as merge blockers:

- wrong category or directory layout;
- missing official issue/provenance or unsupported material claims;
- an Attack Flow missing either its `.afb` or corresponding `.png`;
- invalid/unimportable AFB, stale image, broken or misleading flow logic;
- invalid ATT&CK/CVE mapping or observed behavior presented as fact without a
  source;
- detection syntax errors, broken includes, undefined variables or
  classifications, duplicate IDs/SIDs, or absent required metadata;
- rules unrelated to the parent subject or so broad that they are misleading;
- exposed secrets, personal/confidential data, or artifacts without a clear
  right to redistribute; and
- missing validation evidence for the changed artifact type.

### Required validation report

Return a structured report for every submission validation. Do not replace the
report with file edits. Use the following sections in this order, retaining a
section even when it has no findings:

1. **Overall result**

   Use exactly one result: `PASS`, `PASS WITH WARNINGS`, or `FAIL`. Give a
   short reason and counts of blockers, warnings, and suggestions. `FAIL`
   means at least one mandatory gate or merge-blocking requirement failed.

2. **Submission inventory**

   List the reviewed `.afb`, `.png`, documentation, detection rules, and other
   artifacts. Note missing expected files and files intentionally excluded
   from the review.

3. **Mandatory requirement matrix**

   Use a table with `Requirement`, `Result`, and `Evidence` columns. Use
   `Pass`, `Fail`, or `Not tested` for each result. Cover at least placement,
   AFB parse/import, matching and current PNG, flow metadata, issue reference,
   external sources, ATT&CK mappings, flow connectivity, diagram readability,
   provenance, and relevant detection validation. A `Not tested` mandatory
   item is a validation gap, not a pass.

4. **ATT&CK mapping validation**

   Use a table with `Flow action`, `Submitted mapping`, `Classification`,
   `Rationale`, and `Evidence` columns. Apply one of the five classifications
   defined above to every action node. Identify invalid ID/name combinations,
   wrong tactics or domains, better sub-techniques, weak semantic matches, and
   unsupported incident or actor attribution.

5. **Flow logic and diagram quality**

   Report disconnected nodes, missing prerequisites, unexplained branches,
   implausible ordering, ambiguity between observed and inferred behavior,
   clipped content, overlaps, illegible text, and differences between the AFB
   and PNG.

6. **Findings**

   Lead with findings ordered by `Blocker`, `Warning`, then `Suggestion`.
   Number each finding, cite file and line or node name where practical,
   explain its impact, and state the smallest corrective action. If there are
   no findings at a severity, say `None`.

7. **Validation evidence and gaps**

   List commands and validators run with their outcomes, sources consulted
   with access dates, the ATT&CK version when known, assumptions, unavailable
   tools, failed checks, and anything requiring manual verification. Never
   imply that Builder import, visual comparison, rule execution, or internet
   research occurred when it did not.

8. **Final recommendation**

   Use exactly one recommendation: `Accept`, `Request changes`, or
   `Manual expert review required`, followed by a short justification and the
   next required action.

The report must separate mechanical validity from analytical confidence. For
example, an ID/name pair may pass structural validation while its application
to the described behavior remains imprecise or its attribution remains
unsupported. If there are no findings, say so explicitly and still document
residual risk and checks that could not be performed.
