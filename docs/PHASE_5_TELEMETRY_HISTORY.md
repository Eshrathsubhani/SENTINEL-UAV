# Phase 5.3A — Accepted telemetry history

Status: Implemented for the existing HEARTBEAT and GLOBAL_POSITION_INT gateway records. Windows validation pending.

## Scope

Schema version 5 adds telemetry_records and an index on UAV, capture time and record ID. It preserves the existing identity tables, latest snapshots, sessions, assignments, policy and command state. Migration does not reconstruct historical telemetry from latest snapshots.

Each history row stores record ID, internal UAV ID, capture and GCS receipt times as integer UTC microseconds, message type, system/component IDs, source, validation status and complete validated JSON payload. Position payloads include latitude/longitude, MSL/relative altitude and velocity. Heartbeats include armed state and vehicle type. Unknown fields are not fabricated.

Source is authenticated_uav_gateway. Validation status is gateway_attested: the GCS validates the authenticated gateway identity and its signing-key attestation against the registry. It does not independently reverify a MAVLink signature from the JSON payload. This history label does not claim physical flight evidence or additional application-level replay verification.

The registry guard validates complete bounded records, including direct Python callers, and checks current UAV identity/status before inserting accepted history. History, snapshot and ingestion-decision writes share a transaction. A SQLite storage failure rolls them back and the GCS sends no success acknowledgement.

A repeated record ID with identical content is idempotent; changed content or a different UAV under that ID is rejected. Snapshot timestamps are not refreshed by a duplicate. Older capture times remain in history without replacing newer snapshots. This storage deduplication does not replace MAVLink signing replay protection. JSONL evidence written by the optional callback is separate from the SQLite transaction and can contain retry duplicates.

## Access and query behavior

PolicyEngine.read_history(token, uav_id, start, end, limit=100, cursor=None) enforces telemetry.read using current session, account, role, active UAV and explicit assignment in the same transaction as retrieval and decision audit. All existing roles retain their prior access restrictions.

Timestamps require an explicit timezone. Range is [start, end), with dates from 1970 onward. Page size is 1–1000. Results sort by capture timestamp then record ID. Use the returned next_cursor for the same range/UAV; NULL means no next page. Concurrent insertion of older samples can change later results: this is ordinary keyset pagination, not a frozen multi-request export snapshot.

Example, from Windows Command Prompt:

```bat
python -m security.authorization.policy_engine --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3" --uav-id e52be85d214d471291bae1b8a320cae6 --action telemetry.read --read-history --from-time "2026-11-01T00:00:00+00:00" --to-time "2026-12-01T00:00:00+00:00" --limit 100
```

The CLI prompts for the account password; default username is admin. Add --username for another account. Results include telemetry and next_cursor. This is a Python service/CLI interface, not an HTTP endpoint or a Vercel integration.

Immediately after migration, an empty history result is expected. New records are added when the updated registry-protected GCS gateway accepts incoming telemetry. Existing snapshots remain available through the original --read-telemetry option.

## Validation

New tests cover record persistence across service restarts, compatible latest-snapshot reads, duplicate/conflicting IDs, delayed sample ordering, equal-timestamp pagination, half-open ranges, assignment/account/UAV-state changes, Viewer reads, invalid inputs, parameterized resource IDs, atomic rollback and an mTLS storage-failure/no-acknowledgement exchange.

Legacy schema-upgrade fixtures now remove the version-5 history table when simulating a genuine earlier schema. Direct registry test fixtures now use complete valid gateway records rather than truncated dictionaries. Mission tests retain their deliberate post-ingestion snapshot-corruption checks.

Run the full Windows suite, initialize the existing database and check the diff. Expected full Windows count: 92 tests and 28 subtests; the exact result must be recorded after execution. Local available-source verification excludes only two UI tests whose root app file was not included in the supplied archive.

## Remaining Stage 5.3 and later work

- Extend the signed producer, record schema and validators for battery and flight mode; define speed units and normalized retrieval.
- Persist heartbeat loss/recovery and communication-state events; derive current status from freshness.
- Add missions and authorized mission association; this migration does not yet add mission_id.
- Add central security-event storage, incidents, retention, tested backup/restore and HTTP interfaces in their planned stages.
- Collect a fresh SITL history trial before claiming live end-to-end Phase 5 validation.

This patch does not complete Phase 5 or the full Stage 5.3 checklist. Database files remain unencrypted SQLite protected by operating-system access controls.
