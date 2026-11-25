# Phase 6 SITL Experiment Plan

Status: Planned; recordings and model evaluation pending.

## Objective

Compare Rules-Based Detection, Isolation Forest, Random Forest and
Hybrid Detection using the same held-out, deployment-compatible SITL data.

Public UAV-NIDD analysis remains a separate supplementary experiment.
Its unresolved feature mapping must not be used for deployment claims.

## Initial scenarios

| Scenario | Ground-truth category | Interpretation |
|---|---|---|
| Stationary, disarmed | Normal | Baseline telemetry |
| Stable hover | Normal | Normal flight variation |
| Movement and landing | Normal | Normal operational transitions |
| Deliberate forwarding interruption | Communication disruption | Controlled fault, not automatically an attack |
| Deliberate forwarding delay | Timing anomaly | Controlled anomaly, not automatically an attack |
| Deliberate message-rate increase | Rate anomaly | Controlled anomaly with recorded injection settings |

Anomalies must be introduced through a documented local test harness.
Implementation and observation-boundary verification are required
before recording these scenarios.

## Observation boundary

Keep TLS, MAVLink signing, replay protection and authorization enabled.

Record separately:
- Source telemetry and collector receive times.
- Telemetry accepted by the GCS.
- Gateway rejection and security events.
- Independently recorded intervention start and end times.

A delayed or rejected message may never enter accepted telemetry.
Evaluate it only at an observation boundary where it is actually visible.
Do not manufacture accepted telemetry records for rejected messages.

## Run manifest

Record for every run:
- Unique run ID and parent experiment group ID.
- Scenario and normal/fault/anomaly category.
- Simulator, source-code and configuration versions.
- Vehicle identity and collection settings.
- Start and end timestamps.
- Intervention settings and independently recorded intervals.
- Paths and SHA-256 hashes of source recordings.
- Ground-truth provenance and any uncertain intervals.

Do not store private keys, passwords or session tokens in manifests.

## Collection target

Initial feasibility target: five independent runs per scenario.

This is a pilot target, not proof of adequate statistical coverage.
Expand collection if variation or class coverage is insufficient.

A replay, transformed copy or derivative of a recording retains its
original parent group. It does not count as an independent run.

## Splitting

Plan three training, one validation and one test run per scenario,
subject to feasibility and coverage checks.

All records and windows from a parent group stay in one split.
Freeze the split manifest before fitting preprocessing or models.

Fit preprocessing on training data only.
Train Isolation Forest on normal training data only.
Train Random Forest on labelled training data.
Choose thresholds and hyperparameters using validation data only.
Use the test split after final configuration selection.

## Feature preparation

Candidate features, subject to verified availability:
- Message counts and rates by message type.
- Inter-arrival timing and heartbeat gaps.
- Message sizes from source recordings.
- Position, speed and battery changes where available.

Document units, window duration and observation point for each feature.
Use monotonic elapsed time where available for timing calculations.
Do not create windows across run boundaries.

Exclude labels, intervention settings, scenario names, run IDs,
absolute timestamps, user identities and security decision outcomes
from model input.

Identifiers may support provenance and grouping without becoming features.

## Evaluation

Compare all methods on identical eligible held-out observations.
Report per-class precision, recall, F1 and confusion matrices.
Report false-positive and false-negative rates.
Measure inference latency, detection delay and resource usage.
Report ROC-AUC and PR-AUC only where scores and class coverage permit.

Document fault detection separately from confirmed attack detection.
Do not claim that synthetic timing or rate anomalies prove detection
of all real-world UAV attacks.

## Pending work

- Implement and verify the local intervention harness.
- Finalize the feature contract and ground-truth labelling rules.
- Collect independent runs and preserve original recordings.
- Validate provenance, grouping and split coverage.
- Train, tune, evaluate and save the four detection methods.