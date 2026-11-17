# Phase 4 threat model

Protect user authentication, sessions, UAV identity mappings, telemetry,
mission policies, assignments, command requests, and audit records.

| Threat | Implemented control and evidence |
|---|---|
| Incorrect password or unknown account | Argon2id verification, generic credential failure, persistent login throttling, and tests. |
| Expired or revoked session | Current session lookup on protected calls, explicit invalidation, and restart tests. |
| Viewer command attempt | Backend command permission check at enqueue and dispatch, with denial tests. |
| Operator privilege escalation | Administrator checks within mutation transactions, denied-operation auditing, and tests. |
| Access to an unassigned UAV | Explicit assignment checks, restricted resource discovery, and protected read tests. |
| Unregistered or inactive UAV telemetry | mTLS identity verification and registry status/mapping checks before persistence and acknowledgement. |
| Wrong system or key mapping | Registry comparisons against the authenticated gateway's telemetry attestation. |
| Stale or outside-area mission position | Existing deterministic policy applied to accepted stored GPS with capture and receipt times. |
| Permission removal after queuing | Dispatch rechecks current state under the SQLite transaction lock. |
| Duplicate send after interruption | Committed request claim before send and no automatic retries. |
| Unauthorized audit browsing | Administrator/Operator/Viewer backend scoping tests. |

The trusted local operating-system account controls the database, private
credentials, and gateway processes. A malicious process with equivalent file
permissions could modify data or bypass application services. Host isolation
and stronger audit integrity are future deployment concerns.

A compromised trusted UAV gateway could misrepresent its signing attestation.
The GCS verifies its mTLS identity and mapping, and relies on that gateway for
raw MAVLink signature verification. This boundary is explicit in the protocol.

Status-request transport success can have an uncertain simulator outcome if an
acknowledgement is absent. Claimed requests remain dispatching after a crash and
require inspection. This prototype does not provide exactly-once execution.

Phase 3 signing, replay, certificate, and TLS controls remain part of the
communication threat model. All measured live runs used local ArduCopter SITL.
