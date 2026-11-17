# Phase 4 validation

Phase 4 implements identity, user authentication, access control, and local
simulated command dispatch on top of the Phase 3 secure gateway.

## Acceptance evidence

| Validation | Result and evidence |
|---|---|
| Identity storage | Versioned SQLite schema four preserves users, sessions, UAV mappings, assignments, policies, snapshots, and audit events. Migration and persistence tests passed. |
| Authentication | Argon2id password hashes, login, expiration, logout, throttling, disabled accounts, and revocation tests passed. |
| UAV registry | Live SITL UAV registered as e52be85d214d471291bae1b8a320cae6 with system ID 1 and certificate URI urn:sentinel:uav:1. |
| Registry enforcement | Live trial 59474c69be6b40db8994e93a426927d4 accepted 225 signed frames and acknowledged all 223 queued records. Registry logs identified the registered UAV. |
| Protected telemetry | The assigned administrator retrieved HEARTBEAT and GLOBAL_POSITION_INT through the authenticated backend. Snapshots persisted after capture. Tests denied unassigned and revoked access. |
| Role and contextual rules | Tests covered Viewer command rejection, current roles, account/session state, UAV state, assignments, and default denial. |
| Mission authorization | Administrator configuration returned ALLOW. A stale stored position returned mission_stale_position. With signed telemetry arriving, mission.update returned ALLOW. Negative position and identity cases passed automated tests. |
| Status dispatch | Request e5abb03e83614c1da1fd102a31882835 reached sent with transport_write_completed. Tests covered denial before sending and rechecking after queuing. Simulator acknowledgement was not supplied. |
| Administration console | Screenshots confirmed Administrator management controls, operator1 and viewer1 creation and assignments, Operator telemetry with Telemetry/Audit navigation, and Viewer telemetry with Telemetry-only navigation. Automated app tests covered creation, logout, and revocation. |
| Audit access | Tests recorded denied administrative operations, role and lifecycle changes, and restricted Operator audit queries to their own actor ID. Viewer audit retrieval was denied. |
| Windows regression | 73 tests and 21 subtests passed in 27.29 seconds after the administration patch. |
| Authorization latency | See the marked measurement section below. |

The Operator screenshot establishes audit navigation visibility. Automated
backend tests establish the restriction to the Operator's own events.

## Live registry gateway timings

| Metric | Samples | Median | 95th percentile |
|---|---:|---:|---:|
| TLS handshake | 223 | 5.308 ms | 8.233 ms |
| Record acknowledgement round trip | 223 | 65.660 ms | 118.809 ms |

These are local Ubuntu WSL and ArduCopter SITL measurements. The acknowledgement
round trip includes transport, GCS validation and storage work, and the reply.
It is distinct from the isolated policy-decision timing below.

Evidence is under datasets/sitl_generated/phase4_registry_trial/,
phase4_protected_read_trial/, and phase4_command_trial/. Keep the original
JSONL, CSV, run metadata, and gateway logs.

## Authorization latency

Run from the repository root in Windows Command Prompt:

    python -m scripts.benchmark_authorization --samples 100 --output datasets/sitl_generated/phase4_validation/authorization_latency.json --report docs/PHASE_4_VALIDATION.md

The script uses a temporary synthetic identity database. It excludes application
passwords and session tokens from its output. It updates only this report's
marked measurement section and writes the requested JSON evidence file.

<!-- LATENCY_RESULTS_BEGIN -->

Measured at 2026-11-17T23:20:20.826964+00:00 on Windows-11-10.0.26300-SP0.
Python 3.12.2. Each case has 100 measured samples
after three warm-up decisions. All measured decisions matched their expected outcomes.

| Authorization case | Median | 95th percentile |
|---|---:|---:|
| assigned_operator | 6.177 ms | 9.466 ms |
| viewer_command_denied | 5.850 ms | 8.484 ms |
| unassigned_operator | 8.719 ms | 14.559 ms |
| revoked_user | 8.423 ms | 11.254 ms |
| suspended_uav | 7.462 ms | 8.911 ms |
| unsupported_action | 7.117 ms | 8.465 ms |
| unknown_uav | 7.368 ms | 8.678 ms |
| fresh_mission_update | 8.274 ms | 10.018 ms |
| stale_mission_update | 7.902 ms | 10.127 ms |

Timing includes session and policy lookup, SQLite connection and transaction
overhead, authorization evaluation, and the audit commit. Password hashing,
login, fixture preparation, UI rendering, and network transport are excluded.
The fixture uses synthetic local identities and a fixed test clock for reproducible
fresh and stale mission decisions. The temporary database is removed afterward.
Raw samples, environment details, source hashes, and Git provenance are saved
in the benchmark JSON evidence file.

<!-- LATENCY_RESULTS_END -->

## Scope and trust boundaries

The GCS authenticates the UAV gateway through mTLS and checks the registered
identity mapping. MAVLink signature verification happens at the trusted UAV
gateway. Its schema-three record attests which signing key verified the message.

Human telemetry access is enforced by the backend. Stored telemetry carries
timestamps and may remain available after a connection ends. Mission freshness
checks apply separately to designated mission updates.

Status commands use the private shared SQLite database as a local broker.
The dispatcher rechecks authorization before the signed send. A transport-write
success establishes transmission at that boundary. Simulator execution requires
separate acknowledgement evidence. Claimed requests are never retried automatically
after a crash.

The mission origin defines the centre of the inherited 100-metre square.
The two-second freshness limit and area are prototype parameters. Recovery
commands such as RTL require their own dispatch policy and remain outside the
status sender's allowlist.

Database files, credential files, and gateway processes are trusted local
components. Application authorization restricts backend operations. Filesystem
access must be restricted through the host account. Audit storage in this
prototype is not tamper resistant against a process with write access to SQLite.

## Closeout

Phase 4 was implemented, validated, and closed in commit `923ee5c`, which was
pushed to `origin/main`. The Windows suite passed with 73 tests and 21 subtests,
and all nine authorization benchmark cases produced their expected decisions.
The measured results are recorded above, with raw JSON evidence retained under
`datasets/sitl_generated/phase4_validation/`.

The next milestone is Phase 5 — Database and Secure Storage.
