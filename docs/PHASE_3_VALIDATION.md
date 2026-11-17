# Phase 3 validation

The telemetry path runs from local ArduCopter SITL through strict MAVLink 2 signing at the UAV gateway and TLS 1.3 with mutual authentication to the GCS gateway. The live trial covered signed `HEARTBEAT` and `GLOBAL_POSITION_INT` records.

| Validation | Result |
|---|---|
| Live mTLS forwarding and GCS restart | Phase 3.2 passed. Forwarding resumed after the listener restarted. The recovery trial acknowledged 776 of 897 enqueued records and reported 121 unacknowledged. |
| Strict signed telemetry | The 45-second stationary trial accepted 225 frames with no reported signing rejections. The first heartbeat arrived after 0.3 s. |
| GCS receipt | Both message types were logged. All 224 enqueued records were acknowledged with zero queue drops, stale drops, or unacknowledged records. Signing acceptance and forwarding are counted at different stages. |
| Strict rejection and freshness | Windows tests passed for unsigned, modified, wrong-key, stale, duplicate, and out-of-order frames. Duplicate rejection persisted after reopening the same SQLite signing state. |
| Credential replacement | Windows tests passed for rejection of the retired signing key and for CA replacement with reissued certificates. The updated trust bundle rejected the old CA's client credential. Individual certificate revocation under a retained CA is outside this trial. |
| Credential audit | The gateway records durable activation, rotation, and retirement events. Tests passed for signing and TLS credential changes, unchanged restarts, and CA replacement. |
| Windows regression | PASS. After applying the credential audit patch, 20 tests and 12 subtests passed in 1.21 seconds on Windows with Python 3.12.2. |

## Signed SITL measurements

| Metric | Samples | Median | 95th percentile |
|---|---:|---:|---:|
| TLS handshake | 224 | 1.300 ms | 2.840 ms |
| Record acknowledgement round trip | 224 | 1.435 ms | 2.639 ms |

The TLS metric excludes TCP setup. The acknowledgement round trip includes record transmission, GCS validation and file flushing, and the return acknowledgement. These measurements describe the loopback SITL setup. GCS-only processing latency was not measured separately.

The evidence is under `datasets/sitl_generated/phase3_signed_trial/`. The run ID is `dbd7b78c79dc4d8d9bf964d3d8236f14`. Retain the gateway logs, received JSONL, and the recorder's CSV and run metadata.

## Credential audit operation

Set `--credential-audit-db "$HOME/.sentinel-phase3/credential-audit.sqlite3"` on both gateway commands to record changes. Create the database under a private directory with `umask 077` and retain it across restarts. Use a separate database per deployment. The shared database distinguishes the UAV and GCS roles.

The first successful load of a credential records activation. A subsequent configuration change records retirement of the previous credential and rotation to its replacement. An unchanged restart produces no additional event. Retirement records removal or replacement in that role's local configuration. Replacing the CA trust bundle removes trust in the previous CA when the new bundle omits it. Certificate revocation requires a separate enforcement mechanism.

The console events contain the role and credential type. The private database keeps credential fingerprints for change detection, including hashes of the configured TLS PEM file contents. Keep the database and local test credentials out of Git. Retire the signing credential used in the completed local trial before further use.