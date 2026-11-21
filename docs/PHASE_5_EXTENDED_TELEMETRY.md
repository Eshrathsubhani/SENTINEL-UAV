# Phase 5.3B1 — Battery, mode codes and horizontal speed

Status: Implemented and locally tested; Windows verification and fresh SITL evidence pending.

## Changes

The strict signing receiver and collector callback now accept SYS_STATUS and BATTERY_STATUS in addition to HEARTBEAT and GLOBAL_POSITION_INT. Each forwarded battery frame still passes the signing verifier before reaching the collector. Other message types remain outside this gateway allowlist.

live_record handles batteries separately from position messages; it never reads position velocity attributes from a battery frame. The JSON validator permits only the corresponding battery fields, validates finite numeric ranges and rejects malformed or inconsistent heartbeat/speed fields.

Database schema 6 widens telemetry_records.message_type to include the battery messages. The migration rebuilds the table in the existing atomic migration transaction, copies every existing row unchanged and recreates its query index. Earlier migrations remain unchanged. Migration failure restores the original table and schema version. Authentication, assignment checks, history queries and acceptance-before-acknowledgement behavior remain in force.

## Data representation

| Source | Fields stored in the JSON payload | Interpretation |
|---|---|---|
| SYS_STATUS | battery_remaining_pct, battery_voltage_v | Battery percentage and voltage; absent if unavailable |
| BATTERY_STATUS | battery_id, battery_remaining_pct, battery_voltage_v | Per-battery identifier plus measured/estimated values |
| HEARTBEAT | vehicle_type, armed, base_mode, autopilot_type, flight_mode_code when supplied | Numeric mode code is autopilot-specific, valid only with the custom-mode flag |
| GLOBAL_POSITION_INT | Existing position/velocity fields plus ground_speed_mps | Horizontal speed hypot(vx,vy)/100; vertical velocity is excluded |

The CSV records armed state, base mode, autopilot type, flight-mode code and groundspeed as well. Battery values were already normalized in the collector CSV; this patch connects them to signed forwarding and persistent history.

Unknown battery values are blank in CSV and omitted in forwarded JSON. Never substitute a zero percentage or voltage for an unknown value. BATTERY_STATUS extension cells are ignored unless all ten base cells are present, following the protocol definition. Pack voltage may be split over several base entries for high-voltage packs.

Flight-mode codes are stored exactly, with autopilot and base-mode metadata where available. This patch does not invent a human-readable mode name. A future presentation layer can map supported autopilot/vehicle codes to labels and show unknown codes explicitly.

The record envelope remains JSON schema 2 for the unsigned development gateway and schema 3 for the registry-attested gateway. This is an additive payload extension: the new receiver accepts original heartbeat and position payloads. An old receiver rejects the new metadata/message types. Upgrade both endpoints and the database before running the extended producer. JSON record schema and SQLite schema version are independent.

History retains all batteries by their record IDs and payload battery_id. The existing snapshot key is still (UAV, message type), so a BATTERY_STATUS snapshot represents the most recently captured battery message for that UAV, not a separate latest row per battery. Query history for per-battery analysis.

The source/validation labels remain authenticated_uav_gateway and gateway_attested. GCS trusts signing attestation from the authenticated UAV gateway rather than reverifying a raw MAVLink frame from JSON. Physical flight and wireless performance are not claimed.

## Windows steps

1. Stop any running gateway processes before changing their code or migrating the database.
2. Apply this patch over commit 4a08811 once.
3. Run the complete test suite.
4. Take a fresh online SQLite backup with an integrity check before migration.
5. Run the existing identity_database initializer; expected schema is 6.
6. Check git diff --check and inspect the changed files before committing.

No SITL session is required for automated validation. After the remaining communication-event work, collect a fresh SITL run that demonstrates battery/mode/speed history through the authenticated gateway. Availability depends on which messages SITL actually emits; missing source data must remain unknown.

## Tests

Ten new unit tests exercise battery units/unknown sentinels, extension-cell handling, raw mode flags, horizontal speed, malformed payload rejection, the collector callback, real signed battery frames (including duplicate, wrong-key and unsigned rejection), populated version-5 migration and rollback after a failed rebuild.

A new mTLS integration test sends each battery message type through the registry guard and verifies its persisted JSON history and acknowledgement. Existing tests continue covering earlier schemas, permissions, snapshots, mission freshness and denied identities. Legacy version assertions now expect 6, without weakening the historical version-4 fixture checks.

Expected full Windows suite: 103 tests and 36 subtests. Record the actual Windows result separately. The local source archive omits phase4_access_app.py, so its two UI tests cannot be run locally; all other available tests must pass.

## References

- MAVLink battery fields and invalid sentinels: https://mavlink.io/en/messages/common.html#BATTERY_STATUS
- MAVLink position units: https://mavlink.io/en/messages/common.html#GLOBAL_POSITION_INT
- Heartbeat mode fields: https://mavlink.io/en/messages/minimal.html#HEARTBEAT

## Remaining work

Heartbeat loss/recovery events and persisted communication status are not added by this patch. They remain the next Stage 5.3B subtask. Mission links, centralized security events, incident management, backup/restore tooling, HTTP interfaces and final Phase 5 validation also remain pending.
