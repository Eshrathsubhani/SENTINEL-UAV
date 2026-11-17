"""Framing for one bounded synthetic telemetry record per connection."""

from datetime import datetime
import json
from math import isfinite
from time import monotonic

MAX_RECORD_BYTES = 64 * 1024
RECORD_ACCEPTED = b"\x06"


def validate_record(record):
    if type(record) is not dict or set(record) != {
        "schema_version", "vehicle_id", "message_type", "captured_at", "values",
    }:
        raise ValueError("Invalid telemetry record fields")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise ValueError("Unsupported telemetry schema version")
    for key in ("vehicle_id", "message_type"):
        if not isinstance(record[key], str) or not record[key].strip():
            raise ValueError("Invalid telemetry identifier")
    captured_at = record["captured_at"]
    if not isinstance(captured_at, str) or datetime.fromisoformat(captured_at).tzinfo is None:
        raise ValueError("Capture timestamp must include a timezone")
    values = record["values"]
    if not isinstance(values, dict):
        raise ValueError("Invalid telemetry values")
    for key, value in values.items():
        if not isinstance(key, str) or type(value) not in (int, float):
            raise ValueError("Expected numeric telemetry values")
        if isinstance(value, float) and not isfinite(value):
            raise ValueError("Expected finite telemetry values")
    return record


def encode_record(record):
    payload = json.dumps(validate_record(record), allow_nan=False).encode("utf-8")
    if len(payload) > MAX_RECORD_BYTES:
        raise ValueError("Telemetry record exceeds the size limit")
    return payload + b"\n"


def receive_record(connection, timeout):
    deadline = monotonic() + timeout
    data = bytearray()
    while len(data) <= MAX_RECORD_BYTES:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("Telemetry record deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, MAX_RECORD_BYTES + 1 - len(data)))
        if not chunk:
            raise ValueError("Incomplete telemetry record")
        data.extend(chunk)
        separator = data.find(b"\n")
        if separator >= 0:
            return validate_record(json.loads(data[:separator].decode("utf-8")))
    raise ValueError("Telemetry record exceeds the size limit")
