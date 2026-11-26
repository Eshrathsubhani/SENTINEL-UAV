# Phase 6 diagnostic feature extraction

Status: implemented and tested; no model training or dataset acceptance implied.
The raw recordings and manifests remain unchanged.

## Observation contract

The standard-library-only module `scripts.phase6_extract_features` reads explicit
completed run directories. It verifies recorded artifact hashes, byte counts,
source CSV/run count agreement, unique linkage, monotonic ordering and
record-outcome accounting. Error/incomplete captures and ambiguous source joins
are rejected. It cannot verify GCS receipt or SQLite persistence by itself;
those require a separate record-ID/payload check.

The experiment manifest itself has no prior signed hash; its current SHA-256
is recorded in the export for provenance. Hash checks detect modifications
relative to the manifest, not malicious tampering by a local administrator.

Source CSV rows join events by original receive timestamp, message type,
vehicle/system ID and component ID. UTC strings are exact join keys only,
never the window clock, never sorted, and never model features.

Two separate tables preserve distinct observation boundaries:

- `source_features.csv`: monotonic CSV receive time after accepted source
  verification and collector filtering, before forwarding suppression.
- `forwarding_ack_features.csv`: sender-side monotonic ACK receipt events.
  These are forwarding-feedback observations, not exact GCS arrival timestamps.

Never pool the two scopes or claim that source-only traffic detects a
forwarding-only interruption. ACK feedback requires the existing secure
transport, but is not an authentication/authorization allow-deny feature.
Future model comparisons must choose one eligible observation scope and use
identical held-out observations for all methods.

## Windows and features

Default window width is five seconds, nonoverlapping, aligned at each run's
monotonic elapsed zero. Windows are half-open [start, end). Complete windows
only; empty windows are retained. The initial window includes startup/warm-up
and requires a documented policy before model training.

Collection may finish receiving a frame just after its configured duration,
and ACK processing may drain later. Observations outside complete windows are
excluded and counted explicitly per scope/run in the contract. A trailing
partial window is excluded with its duration recorded. Neither is silently
invented as a complete window.

| Feature | Meaning / unit |
|---|---|
| message_count | Observation count in this scope/window |
| message_rate_hz | Count divided by window seconds |
| heartbeat_count | HEARTBEAT observations |
| position_count | GLOBAL_POSITION_INT observations |
| system_status_count | SYS_STATUS observations |
| battery_status_count | BATTERY_STATUS observations |
| source_frame_bytes_mean | Mean original MAVLink frame size, not TLS/JSON bytes |
| interarrival_mean_s | Mean adjacent-observation gap within the window |
| interarrival_max_s | Maximum adjacent-observation gap within the window |
| heartbeat_age_at_end_s | Window end minus most recent heartbeat strictly before end |

Heartbeat history carries forward only within the same run and scope.
Unavailable means/ages are blank cells (missing), not zeros. Interarrival
features require at least two observations; they do not measure cross-window
gaps. No imputation, scaling, feature selection or model fitting occurs.

Run ID, parent-group ID, window index/start/end are metadata. The explicit
feature_order in feature_contract.json is the model-input allowlist; never
feed the entire CSV into a model without separating metadata. Scenario,
intervention schedule, suppressed counts, labels and absolute UTC timestamps
are not model inputs. No attack labels are generated.

## Output and safeguards

Specify --run once per selected run and --output as a NEW directory.
Existing outputs are never overwritten. A COMPLETE marker is written only
when both tables and feature_contract.json have been written successfully.
On filesystem failure, preserve any incomplete export for diagnosis and use
a new output path after fixing the problem; never consume it without COMPLETE.
The contract records Python version, extractor hash, ordered features, units,
input hashes, excluded observations, grouping and missing-value policies.
training_approved is always false: this is diagnostic feature generation only.

## Uploaded pilot evidence

The 25 November session includes two completed runs:

- Normal: a3c8e0a7f6484d1b9caf45ed6385e8a3; 1,161 source records,
  1,161 acknowledged, zero suppressed.
- Interruption: 78a05f5fca2e4236a96221b5259cce70; 1,169 source records,
  976 acknowledged, 193 suppressed during the planned [30,45) second interval.
- Failed attempt 91a8c81d3525409798aaf43789d6ecbd remains preserved and excluded.

Both completed runs share parent session-PtA9xOaW. They are not independent
train/test groups. At five seconds, they produce 36 rows per scope (18 per run).
In the interruption run, ACK windows [35,40) and [40,45) are empty. Window
[30,35) contains two ACKs from traffic already in flight. Source-window counts
for [30,35), [35,40), [40,45) are 65,65,63, confirming continued source capture.

The separate GCS cross-check confirmed all 976 acknowledged interruption IDs
were received and none of the 193 suppressed IDs appeared at the GCS.
Communication history showed heartbeat loss and recovery. These observations
validate a controlled fault, not classification of a genuine cyberattack.

The quality review found 2 UTC backward steps in the normal capture and 3 in
the interruption capture; monotonic source time had no backward steps.
After host synchronization and Ubuntu restart, a user-reported idle 60-second
check had zero backward UTC steps. This does not retrospectively fix old data
or establish simulator-load stability. Timing-sensitive scientific acceptance
remains pending, including review of the monotonic clock's physical stability.

## Validation and remaining work

Twelve targeted unit tests cover interval boundaries, empty windows,
within-run heartbeat history, excluded tail behavior, rejected tampering,
ambiguous joins, monotonic reversals, incomplete/duplicate runs, grouping,
metadata exclusion and protection of existing output directories.
The two explicit completed uploaded captures also passed diagnostic extraction.
This increment only adds new files and changes no gateway or database code.

Pending: stable simulator-load timing validation, independent labelled run
collection, scenario ground truth, reviewed feature extensions (including
telemetry dynamics), frozen group splits, training-only preprocessing, Rules,
Isolation Forest, Random Forest, Hybrid evaluation and Phase 6 completion.
