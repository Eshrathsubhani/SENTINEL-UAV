# Phase 3 closeout: MAVLink signing and replay policy

The signed configuration protects the SITL-to-UAV gateway hop for
`HEARTBEAT` and `GLOBAL_POSITION_INT`. The existing TLS 1.3 and mTLS controls
protect the separate UAV-to-GCS hop. The replay state is scoped to the
signing key and MAVLink system, component, and link IDs. Keep the SQLite
file across gateway restarts. The strict mode requires a valid signature and
a timestamp within 60 seconds of the receiver's UTC clock. The accepted
timestamp has to increase per stream. The receiver logs the first rejection
in each category and records aggregate counts at the end of the run.

Pymavlink parses the messages and checks packet integrity. The gateway
verifies the signature against the preserved raw frame before advancing
the replay watermark. Treat the two telemetry message types as the scope
of the signed configuration. The unsigned Phase 3.2 configuration remains
available for baseline comparison.

## 1. Run the Windows suite

At the repository root in Windows Command Prompt with the project
environment active:

```cmd
python -m pytest -q
```

Expect 19 tests to pass, plus subtests. In particular, the pymavlink parser
compatibility test must run for release acceptance.

## 2. Provision the development signing key in Ubuntu

Use the existing isolated, loopback-only ArduCopter SITL instance. Keep
whether each trial is signed in the run notes. Keep development signing
credentials out of Git, screenshots and
evidence logs. MAVProxy provisions the shared key over its SITL connection.

In an Ubuntu shell at a `$` prompt, generate a fresh, random test passphrase
and a raw key file. The printed line is for your local MAVProxy console.

```bash
umask 077
mkdir -p ~/.sentinel-phase3
passphrase=$(openssl rand -hex 32)
printf '%s' "$passphrase" |
  openssl dgst -sha256 -binary > ~/.sentinel-phase3/mavlink-signing.key
printf 'signing setup %s\n' "$passphrase"
unset passphrase
```

Start SITL in the left Ubuntu pane with MAVLink 2 enabled. If it is already
running, stop it first to avoid a duplicate port:

```bash
cd ~/ardupilot
MAVLINK20=1 Tools/autotest/sim_vehicle.py -v ArduCopter -f quad --out=127.0.0.1:14551
```

In the MAVProxy prompt, enter `module load signing`, then enter the
`signing setup` line printed by the private Ubuntu shell. Confirm MAVProxy
has a link to the SITL vehicle. Keep the simulated vehicle stationary.

## 3. Run a signed capture and collect measurements

Use the Phase 3.2 runbook's GCS block in the middle pane. Set both panes'
`evidence` variable to a fresh directory under
`datasets/sitl_generated/phase3_signed_trial`. Keep the listener running for
the full signed trial. In the right pane, run:

```bash
cd /mnt/c/Users/eshra/Downloads/SENTINEL-UAV/SENTINEL-UAV
evidence=datasets/sitl_generated/phase3_signed_trial
revision=$(git -C ~/ardupilot rev-parse HEAD)
set -o pipefail
MAVLINK20=1 ~/.venvs/sentinel-uav-phase2/bin/python -m gateways.live_gateway uav \
  --ca-file ~/.sentinel-phase3/ca.pem \
  --cert-file ~/.sentinel-phase3/uav.pem \
  --key-file ~/.sentinel-phase3/uav.key \
  --signing-key-file ~/.sentinel-phase3/mavlink-signing.key \
  --signing-state ~/.sentinel-phase3/mavlink-replay.sqlite3 \
  --simulator-revision "$revision" --seconds 45 --output "$evidence" \
  2>&1 | tee "$evidence/gateway_client.log"
```

Expect `mavlink_signing_required`, then `heartbeat_received`. The GCS logs
should show both message types. A zero accepted count, an unsigned stream,
or a timestamp rejection is a validation failure. Preserve the output for
debugging. Keep the state file and key outside the evidence directory.

Record the accepted and rejected signing counts, forwarding counts, and the
two `forwarding_latency` lines. TLS handshake time excludes TCP connection
setup. Record ACK round-trip time includes send, GCS validation and file
flush, and the reply. The latency logger summarizes up to the most recent
4096 successful samples using nearest-rank p50 and p95 in milliseconds.

## 4. Closeout evidence

- Verify both message types are present in the signed GCS JSONL and match
  the corresponding signed source CSV rows by UTC capture time and type.
- Save the signed run ID and the terminal summary. Record the certificate
  rotation test, which verifies that replacement-CA credentials work and
  an old-CA client credential is refused by the restarted server.
- Save the strict signing, expired/wrong certificate, rotation, and replay
  test results. The signing-key rotation uses replacement of the configured
  key and gateway restart. CA rotation requires restarting both endpoints
  with replacement certificates and trust configuration. Existing TLS
  sessions use the credentials established for those sessions.
- Preserve the Phase 3.2 recovery results. Report the signed trial latency
  with its configuration and sample count.
- Mark Phase 3 complete in PROJECT_STATUS.md after the signed run is verified,
  then commit only the source, tests, and documentation. Keep generated
  credentials, SQLite state, and recordings out of Git.

## References

- [MAVLink 2 signing specification](https://mavlink.io/en/guide/message_signing.html)
- [MAVProxy packet signing](https://ardupilot.org/mavproxy/docs/modules/signing.html)
