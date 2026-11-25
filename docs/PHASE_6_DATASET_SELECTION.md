# Phase 6.1 — Dataset selection and compatibility review

Status: Updated with user-executed UAV-NIDD acquisition evidence; final public-dataset selection is pending.

## Acquisition update — 2026-11-25

UAV-NIDD has now been downloaded, checksum/ZIP checked and its three cases
initially inspected by the user. Its record Rights section was reported as
CC BY 4.0. The Access Point case is the preferred supplementary candidate for
further review; no public subset is training-approved. The GCS case has only
109 Benign class cells, and the UAV CSV has an unresolved tail-like anomaly.
See [the acquisition audit](PHASE_6_UAV_NIDD_AUDIT.md) and the version-2 source
registry for exact evidence and limitations. Other datasets' licence/acquisition
status remains unresolved. Source descriptions below reflect the initial review
unless explicitly superseded by that audit.
Review date: 2026-11-25.

Phase 5 source baseline: `4ddf66a9f66b8ee3bb2a542130a42cb76bc6cdcc`.
Current user-reported documentation baseline: `73a9446`.
This increment adds documentation only and does not replace the updated dataset table.

## Decision

Select project-owned ArduPilot SITL experiments as the primary experimental
source for the four-method deployment comparison. Existing recordings establish
the acquisition/persistence path, not a completed labelled training corpus.
New independent scenario runs and a versioned observation/feature contract are
required before training.

Keep public datasets as separate, conditional benchmark tracks. Prioritize
inspection of UAV-NIDD because its physical testbed and GCS-related scenarios
may be informative. Inspect SHADOW-GCS for MAVLink-specific relevance. Keep
UAVIDS-2025 as a potential independent flow benchmark. These priorities do not
mean the datasets have been approved, acquired or proven compatible.

Do not concatenate these sources or apply a flow model directly to telemetry
without demonstrating the same feature definitions, observation boundary,
units and labels. Unavailable features must not be filled with invented zeros.

## Requirements from the project

The uploaded master specification separates ML alerts from deterministic
mission authorization. The research methodology requires:

- Rules, Isolation Forest, Random Forest and hybrid evaluation on the same
  held-out SITL scenarios.
- Isolation Forest training on normal runs and Random Forest on labelled runs.
- Whole-run split groups, training-only preprocessing and validation-only
  threshold/model selection.
- Precision, recall, F1, normal-run false alerts, detection delay and resource use.
- Separate public benchmarks unless compatibility is demonstrable.

A public benchmark alone does not satisfy the main SITL comparison.
An ML alert must not bypass or replace signing, replay, TLS or mission policy.

## Source register

The table below summarizes initial publisher descriptions. The subsequent
UAV-NIDD case inspections and Rights confirmation are recorded in the acquisition
audit; full feature validation and run/session provenance remain open. Other
candidates have not been acquired.

| Source | Publisher-described content | Review outcome |
|---|---|---|
| UAV-NIDD | Physical testbed; benign and attack traffic; different UAV/AP/GCS cases | Acquired; AP preferred for review; UAV case quarantined; cases must remain separate |
| SHADOW-GCS | MAVLink relay/MITM scenarios; laboratory provides a download link | Protocol-relevant candidate; raw formats and licence unresolved |
| UAVIDS-2025 | NS-3 flow dataset; 122,171 records, 22 feature columns and five classes | Separate flow benchmark only; grouping and feature compatibility unresolved |
| SENTINEL SITL | Recorder CSV/run metadata and accepted gateway/database telemetry | Primary source chosen; labelled multi-run corpus not yet prepared |

### UAV-NIDD

Official research-lab repository:
https://github.com/CyberSaR-KAUST/UAV-Intrusion-Detection-Dataset

CSV landing record, publisher-labelled version v1:
https://zenodo.org/records/15125851

Raw-traffic DOI linked by the research repository:
https://doi.org/10.6084/m9.figshare.25486462

Associated paper:
Hadi et al., “UAV-NIDD: A Dynamic Dataset for Cybersecurity and Intrusion
Detection in UAV Networks,” IEEE TNSE, 2025.
https://doi.org/10.1109/TNSE.2025.3553442

The lab documents UAV/AP/GCS feature counts of 45/51/85 and attack families
including scanning, flooding, replay, MITM and GPS-related attacks. These are
source descriptions, not verified CSV label strings or counts. The wording of
attack totals varies with taxonomy; the actual mapping must be recorded after
inspection. Access to documentation is not proof of permission to redistribute
the data. Update: the user has since confirmed CC BY 4.0 in the record Rights section; see the acquisition audit.

### SHADOW-GCS

Official laboratory landing page:
https://ocslab.hksecurity.net/Datasets/shadow-gcs-attack-dataset

Use its author-provided download link; do not substitute an unrelated mirror.
The page describes four UAV–GCS scenarios and gives a correction to a packet
count in its paper. Do not use the uncorrected paper total as a file-integrity
check. File-level labels and grouping have not been inspected.

Associated paper: Lee and Kim, “GALAXY: Generalized Attention-Based LSTM
Architecture with External Query for Intrusion Detection in UAV Communication,”
PRDC 2025.
https://doi.org/10.1109/PRDC67299.2025.00014

University publication record:
https://pure.korea.ac.kr/en/publications/galaxy-generalized-attention-based-lstm-architecture-with-externa/

The primary material establishes protocol relevance, not compatibility with a
strictly signed and mutually authenticated SENTINEL gateway. The dataset's
exact usage licence and downloadable-file contents remain unverified.

### UAVIDS-2025

Dataset landing record, publisher-labelled version v1:
https://zenodo.org/records/15336998

Author repository:
https://github.com/QingliZeng/UAV--IDS2025

Dataset DataPort DOI:
https://doi.org/10.21227/j5p4-zt27

Associated paper: Zeng, Bashir and Nait-Abdesselam, “UAVIDS-2025: A Benchmark
Dataset for Intrusion Detection in UAV Networks Using Machine Learning
Techniques,” IEEE CNS 2025.
https://doi.org/10.1109/CNS66487.2025.11194990

The author documents labels Normal Traffic, Blackhole Attack, Flooding Attack,
Sybil Attack and Wormhole Attack. Features concern flows, volume and performance,
including duration, packet rates, delay and loss. Their meanings cannot be
replaced by altitude, heartbeat or battery fields.

The repository warns that FlowID encodes class ordering, identifiers can be
scenario-specific, and duplicate flows can leak across random row splits.
Its listed columns do not establish an independent run/session group. A flow
identifier is not automatically a run identifier. Source-disjoint or
duplicate-disjoint splits, if used, must not be called run-disjoint.

The repository explicitly distinguishes its MIT code licence from dataset
terms on DataPort. Do not assign the code licence to the dataset.

## Access, licence and paper-review status

Public dataset and lab landing pages were reviewed. Some Zenodo requests were
rate-limited, machine-readable metadata exports were inaccessible, and DataPort
was inaccessible to the research tool. The SHADOW-GCS lab download destination
was reached, but file contents were not inspected. A reachable landing page
is not a verified successful dataset download.

At the initial metadata review, specific dataset licences had not been established.
The subsequent UAV-NIDD Rights confirmation is recorded in the acquisition audit;
licences for the other two public candidates remain unresolved. Generic repository defaults
and metadata licences are not substitutes for file usage terms. Save the
actual dataset licence/terms, version, citation and provenance before approving
a public source. Request clarification from the publisher if terms are absent;
no such request has been sent.

Publication metadata and available descriptions were reviewed. Full-text reading
of all three papers is not complete and is not claimed. Record capture setup,
label-generation method, sessions, experimental units and limitations from the
full papers before marking that checklist task complete.

## Findings from the merged source archive

Archive: `SENTINEL-UAV-Phase-6-Baseline.zip`.
SHA-256: `cfc9c6c5c65bda6f50fca096565a4eba4a952f84a753549d244b48db28d21055`.
The archive Git comment matches the Phase 5 completion commit. It contains
tracked source/documentation, not the private database or raw experiment CSVs.

| Existing source | Available information | Phase 6 implication |
|---|---|---|
| simulator/telemetry_collector.py | run_id, scenario, elapsed_s, receive UTC, message type/size and applicable normalized telemetry; run.json includes simulator revision and link events | Suitable provenance foundation; scenario text alone is not a verified attack label |
| gateways/live_gateway.py | normalized signed-gateway records with record_id, UAV/source IDs, captured_at, boot timestamp and values | Per-record IDs identify records, not independent runs |
| database/migrations.py | history rows with capture/receive times, source and validation status | telemetry_records has no run_id column |
| database/security_schema_v8.py | event time, producer, category, outcome and optional actor/UAV | Security events also lack an explicit run grouping field |

A database training export therefore needs a verified record-to-run manifest or
additional provenance capture. Do not guess run IDs from UUIDs, row order,
filenames, time proximity or arbitrary time blocks. Any proposed join must
check uniqueness and ambiguity. Keep uncertain historic exports out of grouped
model evaluation until provenance is established.

The existing collector receives filtered telemetry. Database records describe
accepted messages, not every rejected MAVLink packet. Models trained only on
accepted records cannot be claimed to observe all signing/replay attempts.
Security-event sources require their documented producer configuration.

Old trial output included wall-clock warnings. Within-run timing features should
use suitable monotonic observations where available, with clock-quality checks;
wall-clock time must not silently be treated as a perfect ordering source.

## Acquisition and provenance contract

Keep originals under their existing datasets/raw/<candidate>/ directories and
project captures under datasets/sitl_generated/. Write derived tables separately
under datasets/processed/. Raw data is already ignored by the tracked .gitignore.
The new small source registry belongs under docs/evidence/phase6/.

For every acquired file record:

- Publisher URL, download URL, release/version and acquisition timestamp.
- Applicable dataset licence and required citation.
- Original relative path, byte size and locally computed SHA-256.
- Format, columns, units, missing-value conventions and label mapping.
- Label provenance and verified capture/run/session identifiers.
- Extraction/tool versions and any file-to-parent-capture relationships.

Preserve originals. A publisher checksum is not a locally verified checksum.
A versioned metadata record does not prove that a downloaded mirror is identical.
No dataset is to be committed to Git merely because it is downloadable.

## Primary SITL corpus requirements

Prepare multiple independent normal and controlled anomaly/attack-scenario runs
in an isolated local test environment. Keep security enforcement enabled unless
a deliberately separate experimental condition explicitly records its changes.
Do not infer a successful compromise from an attempted or rejected injection.

The scenario manifest must independently describe the scenario, seed, run and
parent-capture IDs, intervention start/end and the meaning of ground truth.
A run containing an intervention is not necessarily malicious at every instant.
Define labels for observation windows and ambiguous boundary windows before
training. Retain unknown labels rather than invent normal/attack truth.

Choose the observation boundary explicitly: accepted-stream behavioural detection
and rejected-attempt monitoring have different inputs and claims. If an upstream
observer is needed, design bounded metadata logging without forwarding rejected
traffic or weakening gateway checks. Define feature availability for each rule;
unsupported cryptographic/replay checks cannot be fabricated from a flow CSV.

Candidate timing/rate/count features are provisional until feature engineering.
Only past and current observations may form a prediction window. Exclude direct
labels, scenario names, absolute identities and label-revealing outcomes. If
security-validation indicators are legitimate inputs, report behavioural-only
ablations so ML gains are not confused with existing deterministic rejection.

## Split and comparison requirements

Assign whole verified runs and their derived copies/windows to one split only.
Related parent captures/replays must not cross splits. Check duplicates and
near-duplicates across partitions. Preserve enough independent normal and attack
runs for meaningful validation/test coverage; row volume cannot replace runs.

Fit imputers/encoders/scalers/selection only on training data. Train Isolation
Forest on confirmed normal training data. Use validation data for thresholds,
contamination experiments, RF tuning and hybrid fusion choices. Evaluate final
selected models once on the untouched test partition. Keep all four methods on
the same eligible held-out scenario observations and disclose any unsupported
rules or coverage differences.

Report per-class and macro metrics, normal false-alert burden, event detection
delay and prediction/resource cost. ROC/PR metrics need usable scores and both
classes; mark inapplicable cases explicitly. Report public-dataset findings
separately from project generalization.

## Stage 6.1 checklist state

| Task | Evidence and remaining work |
|---|---|
| Research UAV-NIDD | Official descriptions and user-run initial case profiles recorded; full-paper/provenance review pending |
| Research SHADOW-GCS | Official lab and publication descriptions reviewed; files pending |
| Research UAVIDS-2025 | Publisher/author descriptions reviewed; files pending |
| Official download links | UAV-NIDD transfer and published-checksum consistency recorded; other transfers unverified |
| Dataset documentation and papers | Available descriptions reviewed; full-paper review incomplete |
| Licence/permissions | UAV-NIDD Rights reported CC BY 4.0 by user; other candidates unresolved |
| Normal/attack labels | UAV-NIDD case values profiled; AP target semantics and ground-truth provenance still pending |
| Feature/category comparison | Preliminary compatibility analysis recorded; EDA pending |
| Primary/supplementary selection | SITL remains primary; UAV-NIDD AP preferred for further review, not yet approved for modelling |
| Selection report | Initial report delivered; final approval gates remain open |

Do not mark all 10 tasks complete or advance to final acquisition/training on
this report alone. This increment changes no model, database schema or gateway
behaviour and requires no SITL rerun or regression run.
