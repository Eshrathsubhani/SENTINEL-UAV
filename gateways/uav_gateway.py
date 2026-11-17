"""Send a single telemetry record to the authenticated loopback GCS."""

from socket import create_connection

from gateways.telemetry_record import RECORD_ACCEPTED, encode_record

LOOPBACK = "127.0.0.1"


def send_telemetry(context, port, server_name, record, *, timeout=3.0):
    payload = encode_record(record)
    with create_connection((LOOPBACK, port), timeout=timeout) as connection:
        with context.wrap_socket(connection, server_hostname=server_name) as secured:
            secured.sendall(payload)
            if secured.recv(1) != RECORD_ACCEPTED:
                raise ConnectionError("GCS did not acknowledge the telemetry record")
