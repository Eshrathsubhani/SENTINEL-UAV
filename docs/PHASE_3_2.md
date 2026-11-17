# Phase 3.2: Live SITL telemetry over mTLS

Use three Ubuntu WSL terminals. Run each command from its indicated shell.
The existing Windows test environment can run the automated suite. Ubuntu
needs `cryptography` and `pymavlink` for this exercise. OpenSSL generates the
development certificates outside the project directory.

In Ubuntu, install the gateway dependency once in the existing environment:

```bash
~/.venvs/sentinel-uav-phase2/bin/python -m pip install cryptography
```
## One-time development credentials

Run in Ubuntu. Use a fresh directory and protect the test keys.

```bash
umask 077
mkdir -p ~/.sentinel-phase3
cd ~/.sentinel-phase3
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 7 -subj /CN=Sentinel-Dev-CA -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout ca.key -out ca.pem
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -subj /CN=gcs.sentinel.test -addext 'subjectAltName=DNS:gcs.sentinel.test' -addext 'extendedKeyUsage=serverAuth' -keyout gcs.key -out gcs.csr
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -subj /CN=Sentinel-UAV-1 -addext 'subjectAltName=URI:urn:sentinel:uav:1' -addext 'extendedKeyUsage=clientAuth' -keyout uav.key -out uav.csr
openssl x509 -req -in gcs.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 7 -copy_extensions copy -out gcs.pem
openssl x509 -req -in uav.csr -CA ca.pem -CAkey ca.key -CAserial ca.srl -days 7 -copy_extensions copy -out uav.pem
```

## Terminal 1: SITL

```bash
cd ~/ardupilot
Tools/autotest/sim_vehicle.py -v ArduCopter -f quad --out=127.0.0.1:14551
```

Keep SITL stationary. The UAV gateway runs the existing collector internally.
Leave any standalone Phase 2 collector off during this run so only one
receiver uses UDP port 14551.

## Terminal 2: GCS

Run from the repository root. Start with a fresh evidence directory for a new
trial. Reuse that directory when restarting the GCS during the same trial.

```bash
cd /mnt/c/Users/eshra/Downloads/SENTINEL-UAV/SENTINEL-UAV
evidence=datasets/sitl_generated/phase3_live_gateway
mkdir -p "$evidence"
~/.venvs/sentinel-uav-phase2/bin/python -m gateways.live_gateway gcs --ca-file ~/.sentinel-phase3/ca.pem --cert-file ~/.sentinel-phase3/gcs.pem --key-file ~/.sentinel-phase3/gcs.key --received "$evidence/gcs_received_telemetry.jsonl" 2>&1 | tee -a "$evidence/gateway_server.log"
```

## Terminal 3: UAV collector and sender

```bash
cd /mnt/c/Users/eshra/Downloads/SENTINEL-UAV/SENTINEL-UAV
evidence=datasets/sitl_generated/phase3_live_gateway
revision=$(git -C ~/ardupilot rev-parse HEAD)
set -o pipefail
MAVLINK20=1 ~/.venvs/sentinel-uav-phase2/bin/python -m gateways.live_gateway uav --ca-file ~/.sentinel-phase3/ca.pem --cert-file ~/.sentinel-phase3/uav.pem --key-file ~/.sentinel-phase3/uav.key --simulator-revision "$revision" --seconds 120 --output "$evidence" 2>&1 | tee "$evidence/gateway_client.log"
```

Once Terminal 2 shows both message types, stop the GCS with Ctrl+C in
Terminal 2. Keep SITL and the UAV process running. Wait for
`forwarding_unavailable` in Terminal 3, then rerun the GCS command on TCP
port 18443. Look for `forwarding_resumed` and both types again. Let the UAV
capture finish, then stop the GCS.

## Evidence and acceptance

The capture directory printed by the UAV contains `telemetry.csv` and
`run.json`. Keep these originals. The GCS JSONL and both gateway logs are in
the parent evidence directory. Record stop and restart timing and the client
summary counts in the validation report.

- Verify multiple `HEARTBEAT` and `GLOBAL_POSITION_INT` records before and
  after restart, with `urn:sentinel:uav:1` on accepted records.
- Join GCS `captured_at` and `message_type` to the source CSV
  `received_at_utc` and `message_type`. Compare coordinate and altitude values.
- The worker uses a 32-record queue and drops records older than 3 seconds
  before sending. Failed attempts are counted as unacknowledged. It accepts
  fresh records after reconnecting, without replaying failed records.
- The GCS flushes accepted records before sending an ACK. A lost ACK can
  leave a record in the JSONL even when the sender reports it unacknowledged.
  A flush alone does not guarantee durability across machine failures.
- Each connection carries one bounded JSON Lines record. Schema version 2
  includes the authenticated UAV identity, UUID record ID, system/component
  IDs and UTC capture timestamp. `source_boot_ms` is boot-relative for
  position and null for a heartbeat. Armed is recorded as 0 or 1.
- This milestone validates the authenticated gateway connection. MAVLink
  signing and replay checks are separate milestones.
  ## Live validation results

**Result:** PASS
**Run ID:** `19ccdebcbbc24ed689b0deb081649eae`

The GCS received 776 of 897 eligible SITL records over mutual TLS 1.3:
156 HEARTBEAT records and 620 GLOBAL_POSITION_INT records. All received
records matched the source CSV by receive timestamp and message type.

Both message types arrived before and after the GCS restarted on TCP port
18443. Forwarding resumed 24.26 seconds after the first connection refusal.
The UAV collector reported 121 unacknowledged records, zero queue drops,
and zero stale drops.

Evidence: `datasets/sitl_generated/phase3_recovery_trial/`.
