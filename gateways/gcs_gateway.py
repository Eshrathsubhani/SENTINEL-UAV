"""Accept a single telemetry record from an authorized UAV over mutual TLS."""

import logging
import socket

from gateways.telemetry_record import RECORD_ACCEPTED, receive_record

LOGGER = logging.getLogger(__name__)


def open_listener(port=0):
    return socket.create_server(("127.0.0.1", port))


def receive_telemetry(listener, context, allowed_uav_identity, *, timeout=3.0):
    """Return the accepted record or None when the connection is rejected."""
    listener.settimeout(timeout)
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(timeout)
        try:
            secured = context.wrap_socket(connection, server_side=True)
        except OSError as error:
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
                LOGGER.warning("gateway_connection_rejected category=peer_identity")
                return None

            try:
                record = receive_record(secured, timeout)
            except (OSError, ValueError, RecursionError):
                LOGGER.warning("gateway_connection_rejected category=telemetry_record")
                return None

            secured.settimeout(timeout)
            try:
                secured.sendall(RECORD_ACCEPTED)
            except OSError:
                LOGGER.warning("gateway_acknowledgment_failed")
                return None

            LOGGER.info("gateway_record_accepted peer_role=uav tls_version=%s", secured.version())
            return record
