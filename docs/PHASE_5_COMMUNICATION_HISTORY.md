# Phase 5.3B2 — GCS heartbeat-path history and status

Status: Implemented and locally verified. Windows verification and live SITL trial pending.
Baseline: supplied source plus the Phase 5 patches through user commit 0b6429b.

## Observation boundary

This feature observes fresh accepted HEARTBEAT records at the GCS registry guard. It records continuity of the end-to-end heartbeat path from the source through the trusted UAV gateway to the GCS. It cannot identify whether an outage originates in SITL, MAVLink UDP, signing rejection, the UAV gateway, TLS transport, the GCS or storage. A timeout is not proof of a physical vehicle failure.

The collector still writes its own local heartbeat loss/recovery observations into run.json. Those collector-side observations and the GCS-side database observations have different observation points. This patch does not forward the collector's run.json events or present them as signed MAVLink messages.

## Schema 7

- communication_state stores one last accepted fresh heartbeat observation per registered UAV: capture and GCS receipt times, timeout, state and registry credential identifiers.
- communication_events stores first heartbeat, loss and recovery transitions with an increasing integer event ID, UTC detection timestamp, internal UAV foreign key, explicit source gcs_accepted_heartbeat, reason and optional associated telemetry record foreign key.
- The telemetry record reference uses ON DELETE SET NULL so later approved retention can preserve a communication event without its original telemetry payload.
- Migration adds the two tables and their query index atomically. It preserves existing history and identity records. It does not infer current connectivity from old snapshots or reconstruct past outages.

## State and freshness rules

| Returned state | Meaning |
|---|---|
| unknown | No fresh heartbeat has been observed since migration, the server clock moved backwards relative to the observation, or current registry credentials differ from that observation |
| connected | A fresh advancing heartbeat was accepted within its configured receipt timeout |
| lost | A previously observed heartbeat exceeded the timeout |

The default timeout is five seconds. The GCS gateway's existing --heartbeat-timeout option configures new observations; supported guard range is 0.001–3600 seconds. The stored timeout belongs to the most recent accepted observation and survives restart. A changed timeout applies on the next fresh heartbeat.

A heartbeat refreshes state only when its capture time advances and its age at receipt is nonnegative and strictly below the timeout. Future/stale capture times may remain in accepted telemetry history but do not establish fresh connectivity. Synchronize source/gateway clocks; the state deliberately stays conservative when clocks disagree.

Duplicate record IDs do not refresh receipt time or create new transitions. Older or equal capture times under new IDs do not refresh status. Position and battery traffic do not substitute for heartbeats. Registry credential/status checks still apply before every ingestion.

- First observation creates heartbeat_received.
- Reaching the timeout boundary creates heartbeat_lost once.
- A fresh heartbeat after loss creates heartbeat_recovered.
- A gap discovered only when a new heartbeat arrives creates loss then recovery in sequence.

Normal successive heartbeats update state without adding a transition event for every sample. Event IDs disambiguate equal detection timestamps.

## Monitor, restart and transactions

The registry-protected GCS loop checks expiry between connections, including listener timeouts. Checks also run during an authorized communication-status read and before a fresh heartbeat replaces an expired observation. No separate scheduler or database timer runs while all services are stopped.

Persisted state survives gateway restart. The next monitor check, authorized read or fresh heartbeat detects any intervening gap. occurred_at_us is the time the gap was detected, not an exact outage-start timestamp. Listener/socket/database scheduling can delay detection; no hard real-time bound is claimed.

Heartbeat history, snapshot, ingestion audit and associated communication changes share one transaction. If an event write fails, the acceptance transaction rolls back and the GCS sends no success acknowledgement. Monitor errors propagate rather than silently claiming that status was updated.

SQLite role authorization remains in backend services. Repository helpers and the monitor are trusted internal entry points, not public user APIs. Ordinary users have no supported operation to edit communication events. OS/database-file administrators remain trusted; these tables are not tamper-proof.

## Authorized interface

PolicyEngine.communication_status(token, uav_id, limit=100, before=None) uses status.read. It checks current session, account, role, active UAV and explicit assignment, including for Administrator. Assigned Viewers may read this UAV's communication-health history; this grants no access to administrative or authentication audit records.

Response includes current state/reason, observation source, last receipt time, heartbeat age, configured timeout, newest-first events and next_before. Page size is 1–1000. next_before is a two-integer position [occurred_at_us,event_id] for the same UAV. Every page is separately authorized. Pagination is a live view, not a frozen export snapshot.

Windows example:

```bat
python -m security.authorization.policy_engine --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3" --uav-id e52be85d214d471291bae1b8a320cae6 --action status.read --read-communication --limit 10
```

Default username is admin; the password is prompted and must not be pasted into logs/chat. Add --username for another account. Immediately after migration, unknown with an empty events list is expected until a fresh heartbeat is accepted. This command is a backend CLI, not a Vercel HTTP integration. The existing Streamlit app is not automatically changed to display this response.

## Validation

New tests verify initial unknown status despite cached snapshots, normal heartbeats without event spam, timeout boundaries and deduplication, listener-independent freshness checks, restart/gap recovery, duplicates, stale/future/nonadvancing captures, battery traffic during heartbeat loss, revoked/unassigned/inactive access, Viewer reads, clock rollback, changed credentials, stable pagination, transactional rollback, rejected credentials, populated schema-6 migration and failed schema-7 rollback.

mTLS integration tests verify heartbeat evidence is stored for an accepted record and a communication-storage failure yields no success acknowledgement or partial telemetry write.

Local available-source result: 119 tests and 45 subtests passed. Two UI tests cannot run because the original review archive omitted phase4_access_app.py. Expected complete Windows result: 121 tests and 45 subtests; record actual results separately.

Stop running gateway processes before applying code changes. Test first, then take a fresh online SQLite backup with integrity verification before running the initializer. Expected schema is 7. Do not commit database files, backups, signing state or credentials.

## Remaining Phase 5 work

A fresh signed SITL run must still validate battery/mode/speed history and GCS heartbeat interruption/recovery. Central security-event storage, mission links/history, incidents, full audit coverage, retention, operational backup/restore, concurrency/performance evidence, HTTP interfaces and the final Phase 5 report remain pending. This patch does not close Phase 5.
