# Phase 4 authorized status dispatch

The first allowlisted command requests SYS_STATUS using MAV_CMD_REQUEST_MESSAGE.
It reads simulator status and has no flight-motion parameters. The Operator and
Administrator roles require an explicit assignment. Viewers cannot enqueue it.

CommandService checks the current session, role, UAV state, and assignment before
writing a request. The private SQLite database acts as the local command broker.
It stores the existing session token hash. It never stores bearer tokens.

The UAV gateway is enabled with --command-database pointing to the same identity
database. It requires --registry-records and strict MAVLink signing. Each accepted
heartbeat triggers one pending request check. The dispatcher rechecks the
session, role, assignment, UAV state, request expiry, and the gateway identity
and key mapping immediately before calling the sender.

Checks and sending hold the same SQLite write lock, preventing a concurrent
revocation commit between the final check and transmission. Commands expire
after thirty seconds. The CLI waits up to fifteen seconds and logs out afterward.
A timed-out request is then rejected on any later dispatch because its session
has been invalidated.

The request is claimed and committed before attempting transmission. A crash
can leave it dispatching with an uncertain transport outcome. Claimed requests
are never retried automatically. Explicit failures become failed. Success is
recorded as sent, meaning the local transport write completed. This status
does not assert a simulator COMMAND_ACK or guarantee command execution.

MAVLink uses a dedicated outgoing source 254:191 and signing link ID 31 through
the existing loopback UDP receiver. Gateway state and trusted local filesystem
access form the command-broker trust boundary. Telemetry continues over mTLS.
This milestone's command broker uses SQLite shared by the local Windows and
WSL processes. A remote command deployment would need an authenticated command
transport with equivalent enforcement.

The existing mission.update action continues to apply geolocation and freshness
rules to mission changes. The status-read request has its own permission and
assignment checks. RTL transport is outside this sender's allowlist.

Upgrade the identity database to schema four before running the gateway:

    python -m database.identity_database --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3"

With the UAV gateway running and --command-database enabled, request status:

    python -m backend.commands.status_request --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3" --uav-id UAV_ID

The gateway's Ubuntu environment needs argon2-cffi as well as the existing
pymavlink and cryptography dependencies. Keep requests, snapshots, and local
credentials outside Git.

Tests prove allowed transmission, blocked Viewer and unassigned requests,
rechecking after assignment removal and logout, expiry, credential mismatch,
transport errors, no automatic retries, schema migration, and the exact signed
SYS_STATUS command arguments. Live transport validation remains necessary.
