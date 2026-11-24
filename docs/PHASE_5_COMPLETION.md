# Phase 5 — Database Management and Secure Storage

Status: Implementation and reported validation complete.
Final acceptance: Pending mentor review.
Implementation baseline: commit 0f40894, database schema 10.

## Objective

Provide persistent storage for UAV telemetry, identities, missions,
security events, incidents and audit history, with authorized access,
transactional operations and verified recovery procedures.

## Implementation checklist

| Stage | Delivered work |
|---|---|
| 5.1 Architecture | Database architecture, relationships, migration plan, retention and backup requirements |
| 5.2 Setup | Shared SQLite connections, initialization, versioned migrations, foreign keys and transactions |
| 5.3 Telemetry | Accepted telemetry history, battery/mode/speed fields, communication history and authorized time-range retrieval |
| 5.4 Security events | Central event storage, source projections, signing/replay/freshness/TLS/credential producers and filtered retrieval |
| 5.5 UAVs and missions | Existing UAV registry/assignments, mission lifecycle history and telemetry associations |
| 5.6 Audit | Identity changes, authorization decisions, supported administrative mutations, mission/incident actions and maintenance events |
| 5.7 Incidents | Classification, severity, evidence links, investigation notes, resolution and history |
| 5.8 Reliability | Parameterized SQL, service authorization, validation, rollback, managed backup/restore and concurrency checks |
| 5.9 Interfaces | Python services and command-line interfaces with applicable filtering, pagination and error handling |
| 5.10 Validation | Automated regression, live persistence evidence, backup/restore checks and local performance measurements |
| 5.11 Documentation | Architecture and feature documents, reliability evidence, recovery/retention instructions and this report |

The retention policy preserves research evidence through mentor review
and final submission. Automatic deletion is not enabled.

## Database schema reference

Canonical definitions are database/schema_v1.py, database/migrations.py,
database/security_schema_v8.py, database/mission_schema_v9.py and
database/incident_schema_v10.py.

| Data group | Tables |
|---|---|
| Identity and permissions | users, roles, permissions, role_permissions, sessions, login_attempts |
| UAV registry | uavs, uav_assignments |
| Policy and commands | policies, command_requests |
| Telemetry | telemetry_snapshots, telemetry_records |
| Communication | communication_state, communication_events |
| Audit/security | identity_events, authorization_events, security_events |
| Missions | missions, mission_events, mission_telemetry |
| Incidents | incidents, incident_event_links, incident_notes, incident_history |

Foreign keys maintain resource relationships. Composite foreign keys
prevent telemetry from being associated with a different UAV's mission.
A unique partial index permits one active mission per UAV.
Incident evidence links prevent deletion of referenced security events.

Mission and incident relationship diagrams are included in their
respective feature documents.

## Backend interfaces

| Interface | Purpose |
|---|---|
| AuthService | Authentication, sessions and administrator transactions |
| UAVRegistry / AccessAdministration | Registry, assignments and identity administration |
| RegistryGuard | Validate registered gateway identity and persist accepted telemetry |
| PolicyEngine | Authorized telemetry/history and communication queries |
| SecurityEventService | Authorized event filtering and pagination |
| MissionService | Mission records, transitions, history and linked telemetry |
| IncidentService | Cases, evidence, notes, classification and resolution |
| scripts.phase5_storage_tools | Administrator backup and restore to a new file |

Public-facing resource services check current identity and permissions.
Resource operations also enforce their documented assignment and UAV
status rules. Incident management uses the administrator audit boundary.

Repository helpers are internal and must not be exposed directly as
unauthenticated endpoints.

These interfaces are Python/CLI interfaces. Phase 5 does not claim a
deployed HTTP API or integration with the Vercel frontend.

## Audit coverage

Supported identity and administration operations record actor, action,
time and result through identity/authorization events.

Central projections cover identity, authorization, communication,
command-state and policy events. Mission and incident services append
their action histories and central events transactionally.

Maintenance operations require administrator authentication and append
completion events. Filesystem copying and the database audit commit are
separate operations, not one distributed transaction.

Gateway security-event persistence depends on the documented event
database and credential-audit options being configured. The earlier
live trial predates the centralized event-writing increment.

Ordinary application users cannot edit audit histories through supported
interfaces. This is not tamper-proof storage against an operating-system
owner or an external SQLite administrator.

The interface inventory identifies relevant code locations. It is not
an independent security audit or certification.

## Final automated regression

Windows Python 3.12.2:

190 tests and 99 subtests passed in 63.69 seconds.

The maintenance tests cover:
- Verified backup and unchanged source
- Session revocation only in the restored copy
- Refusal to overwrite an existing destination
- Missing/corrupt source handling
- Unsupported schema and foreign-key corruption rejection
- Partial-file cleanup after verification failure
- Viewer denial through the maintenance CLI

The final combined run includes the corrected Windows connection cleanup.

## Live telemetry persistence

The recorded Phase 5 WSL trial reported:
- 11,694 accepted signed frames
- 11,694 enqueued and acknowledged records
- Zero reported signing rejections
- Zero queue drops, stale drops or unacknowledged records
- All 11,694 received JSONL payloads matched their database records

Message counts:
- HEARTBEAT: 900
- GLOBAL_POSITION_INT: 3,598
- SYS_STATUS: 3,598
- BATTERY_STATUS: 3,598

The trial covered local ArduCopter SITL and the secure gateway path.
It was not a real-world wireless benchmark.

Mission-to-telemetry association was verified with automated gateway
tests, rather than a new live SITL mission trial.

See PHASE_5_LIVE_VALIDATION.md for the complete trial context.

## Functional persistence checks

Schema 9:
A planned mission was created and retrieved from a fresh process.

Schema 10:
A labelled functional-test incident progressed from Open to Investigating
to Resolved. One note and all four lifecycle history entries persisted.

The manual incident was not a detected attack. Evidence linking and
access boundaries were covered by automated tests.

## Backup and restore

The schema-10 backup passed integrity and foreign-key checks.
A separate restored copy matched its backup using SQLite iterdump
comparison.

Managed backup and restore subsequently passed on disposable copies.
Managed restore revoked existing sessions in the restored copy.

The active database was not overwritten or switched during these checks.
An additional off-device backup has not been verified.

Identity-database recovery does not restore TLS credentials, signing
keys, replay-state databases, the separate credential-audit database
or external experiment files. Those require separate preservation.

See PHASE_5_STORAGE_OPERATIONS.md for recovery and retention procedures.

## Local read performance

Environment: WSL, Python 3.12.3, SQLite 3.45.1.
Dataset: 13,771 telemetry records, 14,440 security events,
one mission and one incident.

Each query used 20 warmups and 200 measured samples.

| Query | Returned rows | Median ms | p95 ms |
|---|---:|---:|---:|
| Telemetry history | 100 | 0.173710 | 0.267291 |
| Security events | 100 | 0.194107 | 0.246464 |
| Mission history | 1 | 0.012858 | 0.015115 |
| Resolved incidents | 1 | 0.012520 | 0.014186 |

These are cached local reads excluding connection setup and authorization.
The small mission/incident datasets do not establish performance at scale.

## Concurrent access

A disposable restored copy completed:
- Two synthetic counter writers
- Four telemetry readers
- 100 operations per worker
- 600 total operations
- 200 committed counter updates

Elapsed time: 2.042629 seconds.

Telemetry row count remained unchanged. Integrity and foreign-key checks
passed. Maximum observed operation latency was 1,438.960597 ms.

The contention delay is material. This test does not establish
production throughput or real-time guarantees.

Evidence:
- evidence/phase5/database-read-benchmark-20261124T210511362736Z.json
- evidence/phase5/database-concurrency-20261124T210957789000Z.json

## Security and research limits

- Database-file encryption at rest is not implemented.
- TLS protects transport; it does not encrypt SQLite files.
- Backup checksums are not digital signatures.
- Private database and credential files remain outside Git.
- Previously exposed trial signing credentials require replacement
  before further live use.
- Windows and WSL must not concurrently open the same active database
  through different SQLite environments.
- Full-scale stress, wireless performance, automatic threat detection
  and flight-controller mission execution are not established here.

## Acceptance

The implementation and reported checks are ready for mentor review.
Mentor approval is not implied by passing tests.

Review should confirm checklist coverage, documented limitations and
the suitability of the retained evidence before final acceptance.