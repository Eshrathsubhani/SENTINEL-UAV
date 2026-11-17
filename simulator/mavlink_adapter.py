"""Decode telemetry from a local simulator stream without sending messages."""
from math import isfinite


def open_receiver(port):
    from pymavlink import mavutil

    return mavutil.mavlink_connection(f"udpin:127.0.0.1:{port}")


def normalize(message):
    """Return fields in SI units where applicable. Missing fields remain blank."""
    kind = message.get_type()
    if kind == "GPS_RAW_INT":
        fields = {"gps_fix_type": message.fix_type}
        if message.fix_type >= 2:
            fields.update(latitude_deg=message.lat / 1e7, longitude_deg=message.lon / 1e7)
        if message.fix_type >= 3:
            fields["altitude_msl_m"] = message.alt / 1000
        return fields
    if kind == "GLOBAL_POSITION_INT":
        return {
            "latitude_deg": message.lat / 1e7,
            "longitude_deg": message.lon / 1e7,
            "altitude_msl_m": message.alt / 1000,
            "relative_altitude_m": message.relative_alt / 1000,
            "heading_deg": message.hdg / 100 if message.hdg != 65535 else None,
        }
    if kind == "VFR_HUD":
        return {"ground_speed_mps": message.groundspeed, "heading_deg": message.heading}
    if kind == "ATTITUDE":
        return {
            name + "_rad": value if isfinite(value) else None
            for name, value in (("roll", message.roll), ("pitch", message.pitch), ("yaw", message.yaw))
        }
    if kind in {"SYS_STATUS", "BATTERY_STATUS"}:
        fields = {
            "battery_remaining_pct": (
                message.battery_remaining if 0 <= message.battery_remaining <= 100 else None
            ),
        }
        if kind == "SYS_STATUS":
            millivolts = message.voltage_battery
            fields["battery_voltage_v"] = millivolts / 1000 if 0 < millivolts < 65535 else None
        else:
            fields["battery_id"] = message.id
            millivolts = sum(
                value
                for value in (*message.voltages, *getattr(message, "voltages_ext", ()))
                if 0 < value < 65535
            )
            fields["battery_voltage_v"] = millivolts / 1000 if millivolts else None
        return fields
    return {}
