# Phase 6 capture harness: provenance and forwarding interruption

Status: implemented with automated tests; new live SITL validation pending.
This does not complete Phase 6 or establish a labelled training corpus.

## Supported scope

The existing `gateways.live_gateway uav` command accepts optional flags:

- `--experiment-parent-group`: stable grouping identifier.
- `--source-revision`: declared project revision (use the committed hash).
- `--simulator-revision`: declared ArduPilot revision (required for experiments).
- `--interrupt-at`: start in monotonic seconds from collector start.
- `--interrupt-for`: positive interruption duration in seconds.

Identifiers use 1–128 letters, digits, underscores, periods or hyphens.
Both interruption flags must be provided together, ending before collection
ends. Omit both for a normal candidate run. Declared revisions do not verify
a clean checkout; record any local modifications separately.

Experiments require UAV mode, registry records, a signing key and persistent
signing state. They reject command-database to prevent vehicle command dispatch.
Existing commands without experiment flags retain their current behavior.
No database migration or telemetry schema change is needed.

Use the loopback GCS with its identity-database option and existing TLS checks.
UAV flags cannot verify GCS settings; record and review the GCS launch settings.

## Evidence

A fresh run ID names the directory containing telemetry.csv and run.json.
Additional files are experiment_manifest.json and experiment_events.jsonl.
The manifest records parent group, declared versions, selected configuration,
planned intervention, status, forwarding counts and SHA-256 artifact hashes.
Events contain ordered monotonic/UTC timestamps and record IDs, not secrets.

A source_record event links a record ID to CSV receive timestamp, message type,
system and component. Record IDs join GCS JSONL/database records. During export,
reject ambiguous CSV matches rather than silently assigning duplicate keys.
Hashes cover CSV, run.json and events at finalization, not the manifest itself.
They detect changes, not malicious administrator tampering.

## Interruption behavior

The half-open interval [start, start + duration) suppresses new forwarding
enqueues after source recording and MAVLink verification. Source CSV continues;
existing queued records can drain. Signed input, TLS, replay and registry
checks are not weakened. No synthetic accepted GCS data is inserted.

The planned interval is logged independently of detector decisions. Observed
start/end events occur on the first eligible source record inside/outside the
interval, not precise scheduler wake-up times. Individual suppression events
identify actual affected records. No source observations during an interval
means no observed suppression effect, not successful validation.

An acknowledged event means the existing transport returned an ACK.
Unacknowledged does not prove GCS persistence failed: an ACK can be lost.
Queue and staleness drops have separate events. Worker failures abort the run.

## Scientific acceptance

Categories are normal_candidate and controlled_communication_fault.
A deliberate interruption is a controlled fault, not a confirmed cyberattack.
Every manifest keeps label_status=requires_run_review.

collector_returned alone does not establish an acceptable run. Inspect run.json
stop_reason, heartbeat coverage, signing rejections, forwarding outcomes and
GCS evidence. Interrupted or incomplete runs must not be silently labelled normal.

Only the four supported accepted source message types are logged here.
Rejected frame monitoring remains separate. Export and hash GCS/security evidence
with explicit run associations before using it for experimental ground truth.
A new run ID does not prove independence: replayed/derived or related records
retain their shared parent group, which must remain in a single split.

## Next validation

1. Pass the complete automated suite before committing.
2. Verify current certificates, strict signing and GCS registry configuration.
3. Capture a stationary normal candidate with no interruption flags.
4. Capture a stationary controlled interruption longer than the heartbeat timeout,
   with sufficient baseline and recovery time.
5. Join record IDs to GCS evidence and verify loss/recovery with source continuity.

Use the WSL-native identity database established in Phase 5. Never run competing
collectors on the same UDP receiver port. Do not start flights for this validation.

Delay/rate injection, automatic labelling, feature windows, split manifests,
model training and evaluation remain pending. This is the provenance and
forwarding-interruption increment only; new live evidence is still required.
