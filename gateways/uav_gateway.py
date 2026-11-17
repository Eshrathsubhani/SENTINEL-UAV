"""Send a single telemetry record to the authenticated loopback GCS."""

from socket import create_connection
from time import perf_counter

from gateways.telemetry_record import RECORD_ACCEPTED, encode_record

LOOPBACK = "127.0.0.1"


def send_telemetry(context, port, server_name, record, *, timeout=3.0):
    payload = encode_record(record)
    with create_connection((LOOPBACK, port), timeout=timeout) as connection:
        handshake_started = perf_counter()
        with context.wrap_socket(connection, server_hostname=server_name) as secured:
            handshake_complete = perf_counter()
            secured.sendall(payload)
            if secured.recv(1) != RECORD_ACCEPTED:
                raise ConnectionError("GCS did not acknowledge the telemetry record")
            return ((handshake_complete - handshake_started) * 1000,
                    (perf_counter() - handshake_complete) * 1000)
