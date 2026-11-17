# Phase 4 UAV registry and assignments

This milestone adds administrator-managed UAV records with explicit certificate
URI, MAVLink system ID, and signing-key fingerprint mappings. Registration starts
in pending status. Administrators can activate, suspend, or permanently revoke a
record. Active users of any role require explicit UAV assignments.

Each management change validates the current administrator session and role
within the same SQLite write transaction. Registration, status changes, assignment,
and unassignment produce identity events. Duplicate assignments are idempotent.
Duplicate MAVLink system IDs and certificate identities are rejected.

The key identifier is the SHA-256 hexadecimal fingerprint of the raw 32-byte
signing key, matching the Phase 3 verifier. It identifies the key. Credential
provisioning remains a separate operation. Use a fresh development signing key
for future trials. Record the certificate URI actually provisioned for the UAV.

The Python API is UAVRegistry.register, set_status, assign, unassign, and list_uavs.
The CLI prompts for the administrator password and revokes its temporary login
session when the operation finishes. No session token is printed.

Example to inspect the registry from Windows Command Prompt:

    python -m security.identity.uav_registry --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3" list

Example registration with a locally obtained fingerprint:

    python -m security.identity.uav_registry --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3" register --name "SITL UAV 1" --system-id 1 --certificate-identity urn:sentinel:uav:1 --signing-key-id FINGERPRINT

Replace FINGERPRINT with the 64 hexadecimal character key identifier. Use the
returned UAV ID with the set-status command and --status active. The assign
command requires --user-id and --uav-id.

This milestone stores assignments and identity mappings. The upcoming RBAC/ABAC
service will enforce resource access using them. Phase 3 gateway lookup and
rejection of unregistered or inactive UAVs are pending integration. An active
registry record alone does not establish a communication credential's authenticity.
