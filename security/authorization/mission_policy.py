"""Apply the existing local-area policy to accepted GPS telemetry."""

from datetime import datetime
import json
from math import atan2, cos, isfinite, radians, sin, sqrt

from security.sentinel_uav_policy import Decision, Position, evaluate_mission_update

EARTH_RADIUS_M = 6371000.0


def valid_coordinates(latitude, longitude):
    return (type(latitude) in (int, float) and type(longitude) in (int, float)
            and isfinite(latitude) and isfinite(longitude)
            and -90 <= latitude <= 90 and -180 <= longitude <= 180)


def _timestamp(value):
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        raise ValueError("Expected a timezone-aware timestamp")
    return stamp.timestamp()


def mission_reason(db, uav_id, now):
    policy = db.execute(
        "SELECT configuration_json FROM policies WHERE name = ?", ("mission_area:" + uav_id,)
    ).fetchone()
    if policy is None:
        return "mission_policy_missing"
    snapshot = db.execute("""
        SELECT * FROM telemetry_snapshots
        WHERE uav_id = ? AND message_type = 'GLOBAL_POSITION_INT'
    """, (uav_id,)).fetchone()
    if snapshot is None:
        return "mission_missing_position"
    uav = db.execute("SELECT * FROM uavs WHERE uav_id = ?", (uav_id,)).fetchone()
    try:
        configuration = json.loads(policy["configuration_json"])
        record = json.loads(snapshot["payload_json"])
        origin_lat = configuration["origin_latitude_deg"]
        origin_lon = configuration["origin_longitude_deg"]
        lat = record["values"]["latitude_deg"]
        lon = record["values"]["longitude_deg"]
        if not valid_coordinates(origin_lat, origin_lon) or not valid_coordinates(lat, lon):
            return "mission_invalid_position"
        if (record["schema_version"] != 3 or record["system_id"] != uav["system_id"]
                or record["uav_identity"] != uav["certificate_identity"]
                or record["signing_key_id"] != uav["signing_key_id"]):
            return "mission_identity_mismatch"
        captured = _timestamp(record["captured_at"])
        received = _timestamp(snapshot["received_at_utc"])
        if captured > now or received > now:
            return "mission_future_position"
        lat1, lat2 = radians(origin_lat), radians(lat)
        delta_lat = lat2 - lat1
        delta_lon = radians(lon - origin_lon)
        a = sin(delta_lat / 2)**2 + cos(lat1) * cos(lat2) * sin(delta_lon / 2)**2
        a = max(0.0, min(1.0, a))
        distance = EARTH_RADIUS_M * 2 * atan2(sqrt(a), sqrt(1 - a))
        bearing = atan2(sin(delta_lon) * cos(lat2),
                        cos(lat1) * sin(lat2) - sin(lat1) * cos(lat2) * cos(delta_lon))
        position = Position(50 + distance * sin(bearing),
                            50 + distance * cos(bearing), min(captured, received))
    except (KeyError, TypeError, ValueError, OverflowError):
        return "mission_invalid_position"
    decision = evaluate_mission_update(position, now)
    if decision is Decision.ALLOW:
        return "allowed"
    return "mission_" + decision.name.lower()
