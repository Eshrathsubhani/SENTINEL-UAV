"""Accept a single telemetry record from an authorized UAV over mutual TLS."""

import logging
import socket
import sqlite3

from gateways.telemetry_record import RECORD_ACCEPTED, receive_record

LOGGER = logging.getLogger(__name__)


def open_listener(port=0):
    return socket.create_server(("127.0.0.1", port))


def receive_telemetry(listener, context, allowed_uav_identity, *, timeout=3.0,
                      on_record=None, required_schema=None, record_guard=None, on_event=None):
    """Return the accepted record or None when the connection is rejected."""
    listener.settimeout(timeout)
    connection, _ = listener.accept()
    if on_event is not None:
        try:
            on_event("tls", "connection_opened")
        except Exception:
            connection.close()
            raise
    with connection:
        connection.settimeout(timeout)
        try:
            secured = context.wrap_socket(connection, server_side=True)
        except OSError as error:
            if on_event is not None:
                on_event("tls", "handshake_failed", severity="medium", outcome="deny",
                         details={"reason": type(error).__name__,
                                  "verify_code": getattr(error, "verify_code", None), "errno": error.errno})
            LOGGER.warning(
                "gateway_connection_rejected category=tls_handshake reason=%s verify_code=%s errno=%s",
                getattr(error, "reason", None) or type(error).__name__,
                getattr(error, "verify_code", None),
                error.errno,
            )
            return None

        with secured:
            peer = secured.getpeercert()
            identities = {value for kind, value in peer.get("subjectAltName", ()) if kind == "URI"}
            if allowed_uav_identity not in identities:
                if on_event is not None:
                    on_event("tls", "peer_identity_rejected", severity="medium", outcome="deny",
                             details={"reason": "peer_identity_mismatch"})
                LOGGER.warning("gateway_connection_rejected category=peer_identity")
                return None

            if on_event is not None:
                on_event("tls", "peer_authenticated", outcome="success",
                         details={"tls_version": secured.version(), "peer_role": "uav"})
            try:
                record = receive_record(secured, timeout)
                if required_schema is not None and record["schema_version"] != required_schema:
                    raise ValueError("Unexpected telemetry schema")
                if record["schema_version"] in (2, 3) and record["uav_identity"] != allowed_uav_identity:
                    raise ValueError("Record identity does not match the authenticated UAV")
                if record_guard is not None:
                    record_guard(record, allowed_uav_identity)
            except (OSError, ValueError, RecursionError, sqlite3.Error) as error:
                if on_event is not None:
                    on_event("storage" if isinstance(error, sqlite3.Error) else "authorization",
                             "telemetry_rejected", severity="high" if isinstance(error, sqlite3.Error) else "medium",
                             outcome="deny", details={"reason": type(error).__name__})
                LOGGER.warning("gateway_connection_rejected category=telemetry_record")
                return None

            if on_record is not None:
                try:
                    on_record(record)
                except OSError as error:
                    if on_event is not None:
                        on_event("storage", "evidence_write_failed", severity="high", outcome="failure",
                                 details={"reason": type(error).__name__})
                    LOGGER.error("gateway_record_rejected category=storage")
                    return None

            secured.settimeout(timeout)
            try:
                secured.sendall(RECORD_ACCEPTED)
            except OSError as error:
                if on_event is not None:
                    on_event("tls", "acknowledgement_failed", severity="medium", outcome="failure",
                             details={"reason": type(error).__name__})
                LOGGER.warning("gateway_acknowledgment_failed")
                return None

            LOGGER.info("gateway_record_accepted peer_role=uav tls_version=%s", secured.version())
            return record
