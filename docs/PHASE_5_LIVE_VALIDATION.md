# Phase 5 — Live telemetry storage validation

Status: Live telemetry-storage milestone passed on supplied local SITL evidence. Phase 5 overall remains in progress.

Implementation baseline reported by the user: commit ad7b2d3, SQLite schema 7. Latest supplied Windows regression result: 121 tests and 45 subtests passed. The evidence below is transcribed from user-executed commands and logs; the reviewer did not independently open the user's live database.

## Trial identification

- Source: local ArduCopter SITL through strict MAVLink signing at the UAV gateway and mutually authenticated TLS 1.3 to the GCS gateway.
- Internal UAV ID: e52be85d214d471291bae1b8a320cae6.
- Registered certificate URI: urn:sentinel:uav:1.
- Evidence directory: datasets/sitl_generated/phase5_wsl_validation/20261124T180840Z/.
- Recorder run ID: 5d5736c7ff1448078b1ee16ec3852574.
- Configured collection limit: 900 seconds.
- Recorder stop reason: duration_reached.
- Scope: stationary simulated vehicle; the displayed heartbeat armed state was 0. This trial is not a physical flight or a wireless-network benchmark.

## Signed telemetry and forwarding

| Check | Observed result |
|---|---:|
| Signing verifier accepted frames | 11,694 |
| Reported signing rejections | None; rejected={} |
| Forwarding enqueued records | 11,694 |
| Forwarding acknowledged records | 11,694 |
| Queue drops | 0 |
| Stale queue drops | 0 |
| Unacknowledged records | 0 |
| Received JSONL records | 11,694 |
| Received payloads matching SQLite history | 11,694 |

The matching query compared each JSONL record against telemetry_records using record_id, internal UAV ID and the complete canonical JSON payload. Every received payload matched. This demonstrates persistence for the supplied trial; it does not establish a general guaranteed-delivery protocol or prove absence of duplicates under other retry conditions.

The stored source label is authenticated_uav_gateway and validation_status is gateway_attested. The GCS authenticates and checks the trusted gateway's registry/signing-key attestation. It does not independently reconstruct and verify a raw MAVLink signature from JSON.

## Message coverage

| Message | Source count | Stored values demonstrated |
|---|---:|---|
| HEARTBEAT | 900 | vehicle_type=2, base_mode=81, armed=0, flight_mode_code=0, autopilot_type=3 |
| GLOBAL_POSITION_INT | 3,598 | Coordinates, MSL/relative altitude, heading, north/east/down velocities and horizontal speed |
| SYS_STATUS | 3,598 | battery_remaining_pct=100, battery_voltage_v=12.6 |
| BATTERY_STATUS | 3,598 | battery_id=0, battery_remaining_pct=100, battery_voltage_v=12.6 |

Latest supplied position values: latitude -35.3632621 degrees, longitude 149.1652373 degrees, MSL altitude 584.09 m, relative altitude 0.003 m, heading 353.19 degrees, north velocity 0.01 m/s, east velocity -0.01 m/s and down velocity 0.0 m/s. Derived horizontal ground_speed_mps was 0.01414213562373095.

The mode is retained as its numeric autopilot-specific code with supporting metadata. This report does not add a decoded display name. The values above are examples from the latest received record per message type, not evidence that every sample had identical values.

## Authorized queries and heartbeat transitions

The user successfully ran the protected telemetry history CLI through Ubuntu against the WSL-local database. The response included stored position/speed records and a non-null next_cursor, demonstrating the paginated interface for this trial.

A protected communication-status query returned state=lost, reason=accepted_heartbeat_timeout, source=gcs_accepted_heartbeat and timeout_s=5.0. The reported heartbeat age at query time was 719.317177 seconds, consistent with querying after forwarding stopped.

Persisted transition sequence, ordered by event ID:

| Event ID | Event | Detection timestamp, UTC microseconds | Context |
|---|---|---:|---|
| 1 | heartbeat_received | 1795543028864453 | Earlier observation retained in the copied database |
| 2 | heartbeat_lost | 1795543318420810 | Earlier timeout retained in the copied database |
| 3 | heartbeat_recovered | 1795543990061043 | Fresh heartbeat accepted during this WSL-local run |
| 4 | heartbeat_lost | 1795544851073928 | Timeout following the end of forwarding |

The last accepted heartbeat receipt time was 1795544844821191 UTC microseconds. The final loss was detected 6.252737 seconds after that receipt, with a configured five-second threshold. Detection includes monitor scheduling and is not an exact outage-start measurement.

This sequence shows persisted loss and resumption across the earlier pause/migration and the new run, followed by timeout after normal producer completion. It is not a separate controlled wireless fault-injection experiment or a vehicle-failure diagnosis. The observation boundary includes the source, gateway, transport, acceptance checks and storage.

## Local latency measurements

| Gateway-reported metric | Retained samples | Median | 95th percentile |
|---|---:|---:|---:|
| TLS handshake | 4,096 | 5.143 ms | 7.294 ms |
| Record acknowledgement round trip | 4,096 | 20.239 ms | 32.581 ms |

The implementation retains a rolling window of timing samples; these values cover the final 4,096 retained samples, not all 11,694 records. The acknowledgement metric includes the client-observed processing/acknowledgement path; it is not isolated database insertion latency. Do not generalize these local WSL/SITL measurements to physical drones or wireless links.

Repeated MAVProxy timer-backwards warnings were observed and their cause remains unresolved. Gateway log wall-clock start/end timestamps also must not be substituted for a validated elapsed-duration measurement. Preserve the warnings and distinguish the configured 900-second collection limit from a separate wall-clock timing claim. Freshness behavior and benchmark clock assumptions require attention in the final reliability report.

## Filesystem correction and retained state

An earlier query from native Windows Python, while the WSL gateway used the same Windows-hosted database, failed at transaction commit with sqlite3.OperationalError: disk I/O error. The exact root cause was not proven. Concurrent cross-environment filesystem/locking behavior was treated as a suspected contributor, not a confirmed diagnosis.

After stopping database clients, the user preserved the database and any sidecars. A native Windows integrity check returned [('ok',)] and schema 7. A consistent SQLite backup snapshot was produced, copied into a private WSL directory and checked again. The copied database passed integrity checking and contained 2,077 telemetry rows before this WSL-local trial.

Operational database for this trial:

/home/eshra/.sentinel-phase5-data/identity.sqlite3

Original Windows database retained separately:

C:\Users\eshra\.sentinel-uav\identity.sqlite3

All subsequent gateway writes and database queries for this trial ran under Ubuntu using the WSL-local database. A Windows command prompt was used only to launch Ubuntu processes with wsl. The two database files are separate copies and are not automatically synchronized. Do not point a native Windows SQLite process at the WSL-local file or resume concurrent mixed-environment writes to the original file.

The earlier failed trial evidence was retained under datasets/sitl_generated/phase5_live_validation/20261124T160730Z/. Its records/state may be present in the copied baseline, but its logs must not be merged with the new trial's counts.

## Credentials and evidence retention

The original development CA and endpoint certificates expired. A replacement development CA and endpoint certificates were generated outside the repository and both purpose checks returned OK. The UAV URI and GCS DNS identity were retained. The new CA was explicitly supplied to both gateways.

The existing registered signing-key fingerprint was checked against the private setup file without printing key bytes, and the existing persistent replay-state database was reused. A signing setup command nevertheless exposed its passphrase when MAVProxy echoed the script. Retire that signing credential before subsequent trials or deployment; do not copy the passphrase into this report, Git or evidence shared with a mentor. Credential replacement and registry/replay-state handling must be deliberate, not achieved by deleting watermark databases.

Retain locally:

- gateway_client.log and gateway_server.log.
- gcs_received_telemetry.jsonl.
- The recorder run directory containing telemetry.csv and run.json.
- The authorized-query outputs and the database matching summary supplied in review.
- A consistent WSL-side backup of the trial database after stopping writers.

Keep private keys, setup files, credential/replay databases and identity databases out of Git. Inspect any shared logs for secret-bearing command echoes. This document contains no signing secret or private-key contents.

## Acceptance and remaining scope

Passed on supplied evidence: accepted signed telemetry forwarding, matching JSONL-to-database payload persistence, all four message types, battery/mode/speed field coverage, authorized history/status interfaces and persisted heartbeat loss/resumption observations.

Still required for overall Phase 5: centralized security events and complete audit coverage; mission lifecycle/history and telemetry links; incident records, notes and resolution; retention; operational backup/restore and concurrency tests; required backend/HTTP interfaces; isolated storage performance/reliability evidence; final schema/API/runbook documentation and checklist review. SQLite encryption at rest is not implemented or claimed.
