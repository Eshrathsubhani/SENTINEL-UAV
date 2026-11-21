"""Record live SITL telemetry and relay accepted frames over loopback mTLS."""

import argparse
from collections import deque
from hashlib import sha256
import json
import logging
from math import ceil
from pathlib import Path
from queue import Empty, Full, Queue
import socket
import sqlite3
from threading import Event, Thread
from time import monotonic
from uuid import uuid4

from backend.commands.status_request import MAVLinkStatusSender, StatusDispatcher
from gateways.gcs_gateway import open_listener, receive_telemetry
from gateways.uav_gateway import send_telemetry
from security.credential_audit import audit_credentials
from security.identity.gateway_registry import RegistryGuard
from security.mavlink_signing import SignedTelemetryReceiver, SigningVerifier
from security.tls_context import client_context, server_context
from simulator.mavlink_adapter import normalize, open_receiver
from simulator.telemetry_collector import collect

LOGGER = logging.getLogger(__name__)
RECORD_MAX_AGE_S = 3.0


def live_record(message, received_at, uav_identity, signing_key_id=None):
    kind = message.get_type()
    system_id = message.get_srcSystem()
    if kind == "HEARTBEAT":
        # MAV_MODE_FLAG_SAFETY_ARMED is bit 7.
        values = {"vehicle_type": message.type, **normalize(message)}
        values["armed"] = int(bool(message.base_mode & 128))
    elif kind == "GLOBAL_POSITION_INT":
        values = {key: value for key, value in normalize(message).items() if value is not None}
        values.update(velocity_north_mps=message.vx / 100,
                      velocity_east_mps=message.vy / 100,
                      velocity_down_mps=message.vz / 100)
    elif kind in {"SYS_STATUS", "BATTERY_STATUS"}:
        values = {key: value for key, value in normalize(message).items() if value is not None}
    else:
        raise ValueError("Unsupported live telemetry message type")
    record = {
        "schema_version": 2, "record_id": uuid4().hex, "uav_identity": uav_identity,
        "vehicle_id": str(system_id), "system_id": system_id,
        "component_id": message.get_srcComponent(), "message_type": kind,
        "captured_at": received_at, "source_boot_ms": getattr(message, "time_boot_ms", None),
        "values": values,
    }

    if signing_key_id is not None:
        record["schema_version"] = 3
        record["signing_key_id"] = signing_key_id
    return record


def record_credential_config(args, signing_key_id=None):
    if args.credential_audit_db is None:
        return
    credentials = {
        kind: sha256(Path(path).read_bytes()).hexdigest()
        for kind, path in (("tls_certificate", args.cert_file), ("tls_trust_bundle", args.ca_file))
    }
    if signing_key_id is not None:
        credentials["mavlink_signing_key"] = signing_key_id
    audit_credentials(args.credential_audit_db, args.role, credentials)


def run_uav(args, context):
    pending = Queue(maxsize=32)
    done = Event()
    stats = dict(enqueued=0, queue_drops=0, stale_drops=0, unacknowledged=0, acknowledged=0)
    timings = deque(maxlen=4096)

    dispatcher = None

    def enqueue(message, received_at):
        if dispatcher is not None and message.get_type() == "HEARTBEAT":
            dispatcher.dispatch_one()
        record = live_record(
            message, received_at, args.uav_identity,
            verifier.key_id if args.registry_records else None,
        )
        try:
            pending.put_nowait((monotonic(), record))
        except Full:
            stats["queue_drops"] += 1
        else:
            stats["enqueued"] += 1

    def forward():
        disconnected = False
        while not done.is_set() or not pending.empty():
            try:
                enqueued_at, record = pending.get(timeout=0.2)
            except Empty:
                continue
            if monotonic() - enqueued_at >= RECORD_MAX_AGE_S:
                stats["stale_drops"] += 1
                continue
            try:
                timing = send_telemetry(context, args.tls_port, args.server_name, record, timeout=1.5)
            except (OSError, ValueError) as error:
                stats["unacknowledged"] += 1
                if not disconnected:
                    LOGGER.warning("forwarding_unavailable reason=%s", type(error).__name__)
                disconnected = True
            else:
                if disconnected:
                    LOGGER.info("forwarding_resumed")
                disconnected = False
                stats["acknowledged"] += 1
                timings.append(timing)

    receiver = open_receiver(args.port)
    connection = receiver
    if args.signing_key_file is not None:
        try:
            verifier = SigningVerifier(args.signing_key_file.read_bytes(), args.signing_state)
        except (OSError, ValueError, sqlite3.Error):
            receiver.close()
            raise
        receiver = SignedTelemetryReceiver(receiver, verifier, args.system_id)
        LOGGER.info("mavlink_signing_required system_id=%d", args.system_id)
    else:
        LOGGER.info("mavlink_signing_disabled")
    try:
        record_credential_config(args, verifier.key_id if args.signing_key_file else None)
        if args.command_database is not None:
            sender = MAVLinkStatusSender(connection, verifier.key)
            dispatcher = StatusDispatcher(
                args.command_database, system_id=args.system_id, identity=args.uav_identity,
                signing_key_id=verifier.key_id, sender=sender,
            )
    except (OSError, sqlite3.Error):
        receiver.close()
        raise
    worker = Thread(target=forward, name="telemetry-sender")
    worker.start()
    try:
        return collect(receiver, args.output / uuid4().hex, args, on_live_telemetry=enqueue)
    finally:
        done.set()
        worker.join()
        receiver.close()
        LOGGER.info("forwarding_summary %s", json.dumps(stats, sort_keys=True))
        if timings:
            for label, samples in zip(("tls_handshake", "record_ack_round_trip"), zip(*timings)):
                ordered = sorted(samples)
                p50, p95 = (ordered[ceil(len(ordered) * fraction) - 1]
                            for fraction in (0.50, 0.95))
                LOGGER.info("forwarding_latency metric=%s samples=%d p50_ms=%.3f p95_ms=%.3f",
                            label, len(ordered), p50, p95)


def run_gcs(args, context):
    guard = RegistryGuard(args.identity_database, heartbeat_timeout=args.heartbeat_timeout) if args.identity_database is not None else None
    args.received.parent.mkdir(parents=True, exist_ok=True)
    with open_listener(args.tls_port) as listener, args.received.open("a", encoding="utf-8") as output:
        record_credential_config(args)
        if guard is not None:
            LOGGER.info("gcs_registry_required schema_version=3")
        LOGGER.info("gcs_listening port=%d", args.tls_port)

        def persist(record):
            output.write(json.dumps(record, allow_nan=False) + "\n")
            output.flush()
            LOGGER.info("record_appended type=%s id=%s",
                        record["message_type"], record["record_id"])

        while True:
            if guard is not None:
                guard.check_heartbeat_timeouts()
            try:
                receive_telemetry(listener, context, args.uav_identity, timeout=1.5,
                                  on_record=persist, required_schema=3 if guard else 2, record_guard=guard)
            except socket.timeout:
                continue


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("uav", "gcs"))
    for name in ("ca", "cert", "key"):
        parser.add_argument("--" + name + "-file", required=True)
    parser.add_argument("--uav-identity", default="urn:sentinel:uav:1")
    parser.add_argument("--server-name", default="gcs.sentinel.test")
    parser.add_argument("--tls-port", type=int, default=18443)
    parser.add_argument("--port", type=int, default=14551)
    parser.add_argument("--system-id", type=int, default=1)
    parser.add_argument("--seconds", type=int, default=90)
    parser.add_argument("--heartbeat-timeout", type=int, default=5)
    parser.add_argument("--scenario", default="phase3_live_gateway")
    parser.add_argument("--simulator-revision")
    parser.add_argument("--output", type=Path, default=Path("datasets/sitl_generated"))
    parser.add_argument("--received", type=Path,
                        default=Path("datasets/sitl_generated/phase3_live_gateway/gcs_received_telemetry.jsonl"))
    parser.add_argument("--signing-key-file", type=Path)
    parser.add_argument("--signing-state", type=Path)
    parser.add_argument("--credential-audit-db", type=Path)
    parser.add_argument("--identity-database", type=Path)
    parser.add_argument("--registry-records", action="store_true")
    parser.add_argument("--command-database", type=Path)
    args = parser.parse_args()
    if (args.signing_key_file is None) != (args.signing_state is None):
        parser.error("Signing requires both a raw key file and a persistent state path.")
    if args.role == "gcs" and args.signing_key_file is not None:
        parser.error("MAVLink signing is configured on the UAV gateway.")
    if args.registry_records and (args.role != "uav" or args.signing_key_file is None):
        parser.error("--registry-records requires UAV mode with strict signing.")
    if args.command_database is not None and not (
            args.role == "uav" and args.registry_records and args.signing_key_file is not None):
        parser.error("--command-database requires registry records and strict signing in UAV mode.")
    if args.identity_database is not None and args.role != "gcs":
        parser.error("--identity-database is a GCS registry enforcement option.")
    if not (1 <= args.tls_port <= 65535 and 1 <= args.port <= 65535
            and 1 <= args.system_id <= 255 and args.seconds > 0 and args.heartbeat_timeout > 0):
        parser.error("Port, system ID, duration and heartbeat timeout must be in range.")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    credentials = dict(ca_file=args.ca_file, cert_file=args.cert_file, key_file=args.key_file)
    try:
        if args.role == "gcs":
            return run_gcs(args, server_context(**credentials))
        return run_uav(args, client_context(**credentials))
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        LOGGER.error("gateway_start_or_run_failed reason=%s errno=%s",
                     type(error).__name__, getattr(error, "errno", None))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
