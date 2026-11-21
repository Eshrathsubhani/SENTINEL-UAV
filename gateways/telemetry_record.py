"""Framing for one bounded telemetry record per connection."""

from datetime import datetime
import json
from math import hypot, isclose, isfinite
import re
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
    if version in (2, 3):
        fields.update({"record_id", "uav_identity", "system_id", "component_id", "source_boot_ms"})
    elif version != 1:
        raise ValueError("Unsupported telemetry schema version")
    if version == 3:
        fields.add("signing_key_id")
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
    if version in (2, 3):
        _validate_live_fields(record, values)
    if version == 3:
        key_id = record["signing_key_id"]
        if not isinstance(key_id, str) or re.fullmatch(r"[0-9a-f]{64}", key_id) is None:
            raise ValueError("Invalid signing key identifier")
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
        required = {"vehicle_type", "armed"}
        optional = {"base_mode", "autopilot_type", "flight_mode_code"}
        if not required <= values.keys() <= required | optional or boot_ms is not None:
            raise ValueError("Invalid heartbeat fields")
        if type(values["vehicle_type"]) is not int or not 0 <= values["vehicle_type"] <= 255:
            raise ValueError("Invalid vehicle type")
        if type(values["armed"]) is not int or values["armed"] not in (0, 1):
            raise ValueError("Invalid armed state")
        for key in ("base_mode", "autopilot_type"):
            if key in values and (type(values[key]) is not int or not 0 <= values[key] <= 255):
                raise ValueError("Invalid heartbeat mode metadata")
        if "base_mode" in values and values["armed"] != int(bool(values["base_mode"] & 128)):
            raise ValueError("Armed state disagrees with base mode")
        if "flight_mode_code" in values:
            if (type(values["flight_mode_code"]) is not int or not 0 <= values["flight_mode_code"] < 2**32
                    or not values.get("base_mode", 0) & 1):
                raise ValueError("Invalid autopilot-specific mode code")
    elif record["message_type"] == "GLOBAL_POSITION_INT":
        required = {
            "latitude_deg", "longitude_deg", "altitude_msl_m", "relative_altitude_m",
            "velocity_north_mps", "velocity_east_mps", "velocity_down_mps",
        }
        if boot_ms is None or not required <= values.keys() <= required | {"heading_deg", "ground_speed_mps"}:
            raise ValueError("Invalid global-position fields")
        if not (-90 <= values["latitude_deg"] <= 90 and -180 <= values["longitude_deg"] <= 180):
            raise ValueError("Invalid position coordinates")
        if "ground_speed_mps" in values:
            expected = hypot(values["velocity_north_mps"], values["velocity_east_mps"])
            if values["ground_speed_mps"] < 0 or not isclose(values["ground_speed_mps"], expected,
                                                          rel_tol=1e-9, abs_tol=1e-9):
                raise ValueError("Groundspeed disagrees with horizontal velocity")
    elif record["message_type"] in {"SYS_STATUS", "BATTERY_STATUS"}:
        allowed = {"battery_remaining_pct", "battery_voltage_v"}
        if record["message_type"] == "BATTERY_STATUS":
            allowed.add("battery_id")
            if (type(values.get("battery_id")) is not int or not 0 <= values["battery_id"] <= 255):
                raise ValueError("Invalid battery ID")
        if boot_ms is not None or not values.keys() <= allowed:
            raise ValueError("Invalid battery fields")
        if "battery_remaining_pct" in values and (
                type(values["battery_remaining_pct"]) is not int
                or not 0 <= values["battery_remaining_pct"] <= 100):
            raise ValueError("Invalid battery percentage")
        if "battery_voltage_v" in values and not 0 < values["battery_voltage_v"] < 1000:
            raise ValueError("Invalid battery voltage")
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
