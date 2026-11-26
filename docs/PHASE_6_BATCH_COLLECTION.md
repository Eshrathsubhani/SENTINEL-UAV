# Phase 6 paired collection helper

Status: code and unit tests implemented; new helper live validation pending.
Existing manual captures remain preserved. No trained models or completion claim.

## Why this increment

Recovery group recovery-MMI5dS8U has stable monotonic and UTC source timing.
Normal run 2854348c0303488f98a5b9d83579bf39 accounts for 1,157 source records:
1,151 acknowledged and six queue drops. Interruption run
28816745acaf4d6db6d8f314e8bf0fcf accounts for 1,161 source records:
967 acknowledged and 194 suppressed. Hash/record-ID checks passed; zero backward
source clock steps were reported for either run. The reported UTC-minus-monotonic
spans were approximately -0.000123 and -0.000088 seconds, respectively.
These are user-run checks; their JSON evidence should be committed unchanged.

Six queue drops are an operational observation, not proof of an attack or a
clean normal baseline. Never relabel them based only on a detector decision.

## Explicit queue-drop policy

Feature extraction remains strict by default. Optional --allow-queue-drops
accepts only matched, uniquely accounted source queue-drop events. The source
observation remains in source features and is absent from ACK feedback features.
Manifest counts and disjoint outcomes must balance. Unacknowledged/stale losses
remain rejected because their receiving-side semantics need a separate policy.
The selected queue policy and forwarding counts are recorded in the contract.
This does not approve the data or hide loss as missing input.

## Collection helper

Run scripts.phase6_collect_pair in Ubuntu/WSL using the SENTINEL interpreter,
not the ArduPilot Python environment. It uses the default local simulator
system ID 1, UDP 14551, GCS TCP 18443 and registered UAV identity.
Pass TLS directory, persistent signing key/state, native identity database,
and parent-group name explicitly. It never changes signing keys or resets state.

Before running:

1. Commit relevant source using Windows Git.
2. Stop the manual GCS and any UAV collector, leaving their completed files intact.
3. Start a fresh disarmed SITL session and configure existing signing in MAVProxy.
4. Keep that simulator terminal running. Do not share the signing setup output.
5. Run the helper from the repository directory in another Ubuntu terminal.

The helper checks files, free GCS TCP and collector UDP ports, committed source,
and exactly one running arducopter process. It starts its own GCS, waits for its
readiness log, captures 90 seconds normal then 90 seconds with suppression
[30,45), checks hashes and per-record accounting against GCS JSONL, and writes
clock diagnostics into session_manifest.json. It stops only its owned GCS at
completion/error. SITL stays running. Read the client/server logs on failure.
No automatic vehicle arming, flight or command dispatch occurs.

Existing output groups are never overwritten. Interrupted/failed sessions are
kept and marked error_or_interrupted; use a new group only after review and a
fresh simulator process. A new UUID is not proof of independent data.

## Grouping and leakage

Normal and interruption captures from the same simulator process share one
parent group. A fingerprint combines Linux boot ID, PID and process start tick.
The helper refuses reuse of that fingerprint under another group in the same
output root. Do not bypass this check with another root or relabel old pilots.
This detects process reuse, not statistical independence: shared seeds,
configuration, environment and repeated interventions still limit generalization.
Derivative/replayed records retain the original parent group.

The initial collection target remains five fresh sessions, each with both
scenarios: three training groups, one validation group and one held-out test
group. Freeze actual membership before preprocessing. It is a feasibility
corpus for controlled communication-fault detection, not a comprehensive UAV
attack benchmark. Further independent variation and scenarios remain necessary.
Do not split paired runs or their windows across dataset partitions.

## Scientific review remains required

The helper checks process health, files, linkage and clock diagnostics, but
session status collected_pending_scientific_review always has
training_approved=false. Review actual intervention evidence, startup effects,
queue pressure, normal/fault semantics and timing before labels/splits.
UTC-minus-monotonic span agreement does not independently calibrate physical
clock accuracy. Preserve source data and never repair timestamps silently.

At least review zero backward clock steps and any nontrivial span differences;
no training threshold is silently inferred from this pilot. No attack labels,
scalers, fitted models or test metrics are created by this helper.

## Validation

Nineteen targeted unit tests pass: 13 feature-extractor tests and six helper
checks for names, group/process reuse, restart fingerprints, readiness,
occupied UDP ports and owned-process cleanup. These do not substitute for a
real simulator/GCS run of the new orchestration. Existing local full-suite
verification is required before committing the patch.
