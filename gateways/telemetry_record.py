"""Framing for one bounded telemetry record per connection."""

from datetime import datetime
import json
from math import isfinite
from time import monotonic

MAX_RECORD_BYTES = 64 * 1024
RECORD_ACCEPTED = b"\x06"


def validate_record(record):
    if type(record) is not dict or type(record.get("schema_version")) is not int:
        raise ValueError("Invalid telemetry schema version")
    fields = {
        "schema_version", "vehicle_id", "message_type", "captured_at", "values",
    }
    version = record["schema_version"]
    if version == 2:
        fields.update({"record_id", "uav_identity", "system_id", "component_id", "source_boot_ms"})
    elif version != 1:
        raise ValueError("Unsupported telemetry schema version")
    if set(record) != fields:
        raise ValueError("Invalid telemetry record fields")
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
    if version == 2:
        _validate_live_fields(record, values)
    return record


def _validate_live_fields(record, values):
    for key in ("record_id", "uav_identity"):
        if not isinstance(record[key], str) or not record[key].strip():
            raise ValueError("Invalid live telemetry identifier")
    for key in ("system_id", "component_id"):
        if type(record[key]) is not int or not 1 <= record[key] <= 255:
            raise ValueError("Invalid MAVLink source ID")
    if record["vehicle_id"] != str(record["system_id"]):
        raise ValueError("Vehicle ID disagrees with system ID")
    boot_ms = record["source_boot_ms"]
    if boot_ms is not None and (type(boot_ms) is not int or not 0 <= boot_ms < 2**32):
        raise ValueError("Invalid MAVLink boot timestamp")
    if record["message_type"] == "HEARTBEAT":
        if set(values) != {"vehicle_type", "armed"} or boot_ms is not None:
            raise ValueError("Invalid heartbeat fields")
        if type(values["vehicle_type"]) is not int or not 0 <= values["vehicle_type"] <= 255:
            raise ValueError("Invalid vehicle type")
        if type(values["armed"]) is not int or values["armed"] not in (0, 1):
            raise ValueError("Invalid armed state")
    elif record["message_type"] == "GLOBAL_POSITION_INT":
        required = {
            "latitude_deg", "longitude_deg", "altitude_msl_m", "relative_altitude_m",
            "velocity_north_mps", "velocity_east_mps", "velocity_down_mps",
        }
        if boot_ms is None or not required <= values.keys() <= required | {"heading_deg"}:
            raise ValueError("Invalid global-position fields")
        if not (-90 <= values["latitude_deg"] <= 90 and -180 <= values["longitude_deg"] <= 180):
            raise ValueError("Invalid position coordinates")
    else:
        raise ValueError("Unsupported live telemetry message type")


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
