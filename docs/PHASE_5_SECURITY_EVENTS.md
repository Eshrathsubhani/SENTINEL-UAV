# Phase 5: Central security events and audit storage

Status: Implemented in this patch; deployment verification is pending until the
Windows regression suite and schema-8 initialization complete.

## Scope

This increment adds a searchable security-event database and connects the existing
identity, authorization, communication and administrative audit sources. It also
adds structured gateway signing, replay, freshness, TLS and credential events.
It does not close all of Phase 5. Mission history, incidents, managed recovery,
retention and final performance/acceptance work remain separate increments.

The earlier live storage trial is recorded in PHASE_5_LIVE_VALIDATION.md. Its
11,694 matched records and latency measurements predate this increment. They are
not performance measurements of the new event-writing path.

## Schema 8

`security_events` is the central append table. Its fields are:

| Field | Meaning |
|---|---|
| event_id | Local increasing primary key |
| producer, producer_event_id | Unique source identity for retry detection |
| occurred_at_us | UTC event time in integer microseconds |
| ingested_at_us | Database insertion time; current SQLite clock has second precision |
| category, event | Event classification and action name |
| severity | info, low, medium, high or critical |
| outcome | info, success, failure, allow or deny |
| actor_id | Known user ID; null for unattended gateway events |
| uav_id | Optional foreign key to the registered UAV |
| target_id | Optional action target |
| details_json | Bounded structured metadata |

Indexes cover time, actor, UAV and category. Source identifiers are not user
session tokens. Only event metadata is copied: passwords, session token hashes,
private keys, signature bytes, certificate PEM contents and telemetry payloads
are not copied to this table by the provided producers.

Migration 8 preserves source tables and backfills identity, authorization and
communication events. Existing command rows receive a current-state snapshot;
this does not reconstruct earlier command transitions. Policy changes are
recorded prospectively. Source times with second precision remain second
precision even though the representation is microseconds.

Source-table insert triggers project events in the same transaction. A rollback
removes both the source mutation and its projection. Command status/reason
changes and policy inserts/updates also generate events. Reinitializing an
already migrated database does not repeat the backfill.

## Producers and semantics

| Source | Events |
|---|---|
| Identity service | Login success/failure, logout, user and role changes, UAV registration/status and assignments |
| Authorization service | Current allow/deny decisions, including mission checks and protected telemetry access |
| Communication repository | Accepted heartbeat receipt, loss and recovery |
| Command dispatcher | Current request state and subsequent transitions; sent means transport write completed |
| Policy table | Creation/update with policy version; actor is null because that table does not contain an actor |
| Signed receiver | Parser rejection, unsigned/invalid signature, replay/out-of-order, freshness failure and closing summary |
| GCS TLS listener | Connection opening, authenticated peer, handshake/identity rejection, record rejection and acknowledgement failure |
| Credential audit database | Activation, retirement and rotation of configured credential types |

Policy authorization decisions carry their known actor separately; no actor is
invented for a low-level policy trigger. These events describe application
operations, not every SQL statement or changes made by an operating-system
owner using an external SQLite client.

A failed authorized administration transaction rolls back. The service then
attempts a separate failure event containing the actor, action and exception
class, without exception text. If the database itself is unavailable, that
failure event cannot be guaranteed; a fixed console error is emitted.

Credential events retain their durable source database. Startup exports that
role's history with stable source event IDs. Repeating the export is idempotent;
an export failure can be retried at the next startup without losing the source.
Credential fingerprints are not included in central events. Local retirement
still does not mean certificate revocation.

Signing and TLS callbacks persist synchronously. A configured event-storage
failure propagates and prevents further normal receive processing; an
unaudited peer is not acknowledged as accepted. A failure after an existing
record transaction commits does not undo that earlier durable transaction.
There is no distributed transaction across SQLite, replay state and JSONL.
Historical signing/TLS console logs are not automatically imported.

## Access and retrieval

`backend.security.event_service.SecurityEventService.query` checks the current
session, account status and permissions on every call:

- Administrator: all events through `audit.read`.
- Operator: events whose actor ID is that operator, through `audit.read_own`.
- Viewer, revoked account or invalid session: denied.

Gateway events with no user actor are therefore visible to administrators, not
all operators. Each retrieval allow/deny is itself audited. Supported interfaces
offer no user-facing event update or delete operation. SQLite has no independent
application-user permissions: private file access and the service boundary are
required. This is not tamper-proof storage against the operating-system owner,
and database encryption at rest is not implemented here.

The Python service/CLI supports category, severity, UAV, half-open UTC time range
and keyset pagination. The default page size is 100 and maximum is 1,000.
`next_before` is `[occurred_at_us,event_id]`; pass it unchanged as `before` in
Python or JSON through `--before` in the CLI. Queries use bound SQL parameters.
These are backend interfaces, not a newly deployed HTTP API or Vercel backend.

## Deployment for this project

Keep the active database on the WSL Linux filesystem:
`/home/eshra/.sentinel-phase5-data/identity.sqlite3`.
Stop running gateway processes, create an SQLite backup and initialize schema 8
using the WSL Python environment. Do not open the same active file concurrently
with native Windows SQLite. The Windows database is a separate older copy.
Windows pytest uses temporary test databases and can still run normally.

For future gateway runs:

- GCS automatically uses `--identity-database` as its central event database.
- UAV signing events require
  `--security-event-database /home/eshra/.sentinel-phase5-data/identity.sqlite3`.
- Both roles retain `--credential-audit-db` to enable credential source history
  and its central export.

The explicit event option can also be used on GCS. This local prototype writes
the same Linux-host database from trusted local processes. It does not implement
remote UAV-to-GCS security-event transport. Test credentials previously exposed
in a transcript must be replaced before another live trial.

After migrating, run this from Windows Command Prompt as one line:

```bat
wsl -d Ubuntu --cd /mnt/c/Users/eshra/Downloads/SENTINEL-UAV/SENTINEL-UAV /home/eshra/.venvs/sentinel-uav-phase2/bin/python -m backend.security.event_service --database /home/eshra/.sentinel-phase5-data/identity.sqlite3 --limit 5
```

Enter the administrator password at the prompt. Existing identity/authorization/
communication events should be queryable immediately after migration. New TLS
and signing events appear when the updated gateway producers run.

## Validation

New automated checks cover schema-7 upgrade/backfill and rollback, atomic source
projections, producer retry/conflict behavior, secret-field rejection, current
role/account enforcement, operator isolation, filtering/pagination, failure
auditing, credential export recovery, and signed-receiver event classification.
Real loopback TLS tests exercise successful authentication, missing certificate,
wrong identity, registry denial, evidence-write failure and event-storage failure.

The available source archive omits `phase4_access_app.py`. Local regression
verification therefore excludes its two UI integration tests. Run the complete
`python -m pytest -q` suite in the Windows repository, where the application file
is present. Record that result before marking this increment deployed.
