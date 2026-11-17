# Phase 4 gateway registry enforcement

Start the GCS gateway with --identity-database pointing to the existing identity
SQLite database. In this mode the GCS accepts schema version three, which carries
the signing-key fingerprint attested by the trusted UAV gateway. The normal mTLS
handshake and certificate URI checks remain mandatory. Every accepted record
must match an active registry entry by certificate URI, system ID, and key ID.

The UAV gateway emits schema three with --registry-records. This flag requires
strict MAVLink signing. Its fingerprint comes from the loaded verifier key.
Only telemetry accepted by SignedTelemetryReceiver reaches the producer.

The GCS relies on the authenticated UAV gateway's signing attestation. The GCS
does not reverify the original MAVLink packet signature. The UAV gateway is part
of the trusted computing boundary and its local signing key must be protected.

Registry decisions are evaluated per record, committed to authorization_events,
and applied before the record callback, persistence, and acknowledgement.
Current UAV suspension and revocation take effect on subsequent checks. A
database error prevents acknowledgement and stops the live GCS process so it
cannot continue accepting records without its registry.

The existing schema two mode remains for Phase 3 baseline experiments.
A deployment uses --identity-database to enable the protected GCS path. Omitting
that option starts the earlier baseline mode. Registry-enabled GCS rejects the
baseline producer's records.

Integration tests exercise the normal mTLS receive path, successful persistence,
unknown and revoked UAVs, mismatched system and key identifiers, and rejection
of legacy records. Human session and assignment enforcement occurs separately
in the backend's protected resource handlers, which are the next milestone.

For the live trial, both gateways run under Ubuntu WSL. The identity database
created by Windows is accessible at:

    /mnt/c/Users/eshra/.sentinel-uav/identity.sqlite3

The new raw signing key is:

    ~/.sentinel-phase3/mavlink-phase4.key

Before the trial, provision SITL with the matching command kept in the private
mavlink-phase4.setup file. Use a fresh evidence directory and retain the signing
state between restarts. On the GCS add --identity-database with the Windows
database path. On the UAV add --registry-records alongside --signing-key-file
and --signing-state.

These flags enforce registered telemetry ingestion. They do not grant a human
operator telemetry access or execute a flight command.
