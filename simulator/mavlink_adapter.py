"""Decode telemetry from a local simulator stream without sending messages."""
from math import hypot, isfinite


def open_receiver(port):
    from pymavlink import mavutil

    return mavutil.mavlink_connection(f"udpin:127.0.0.1:{port}")


def normalize(message):
    """Return fields in SI units where applicable. Missing fields remain blank."""
    kind = message.get_type()
    if kind == "HEARTBEAT":
        fields = {}
        base_mode = getattr(message, "base_mode", None)
        if base_mode is not None:
            fields.update(base_mode=base_mode, armed=int(bool(base_mode & 128)))
            if base_mode & 1 and getattr(message, "custom_mode", None) is not None:
                fields["flight_mode_code"] = message.custom_mode
        if getattr(message, "autopilot", None) is not None:
            fields["autopilot_type"] = message.autopilot
        return fields
    if kind == "GPS_RAW_INT":
        fields = {"gps_fix_type": message.fix_type}
        if message.fix_type >= 2:
            fields.update(latitude_deg=message.lat / 1e7, longitude_deg=message.lon / 1e7)
        if message.fix_type >= 3:
            fields["altitude_msl_m"] = message.alt / 1000
        return fields
    if kind == "GLOBAL_POSITION_INT":
        fields = {
            "latitude_deg": message.lat / 1e7,
            "longitude_deg": message.lon / 1e7,
            "altitude_msl_m": message.alt / 1000,
            "relative_altitude_m": message.relative_alt / 1000,
            "heading_deg": message.hdg / 100 if message.hdg != 65535 else None,
        }
        if hasattr(message, "vx") and hasattr(message, "vy"):
            speed = hypot(message.vx / 100, message.vy / 100)
            fields["ground_speed_mps"] = speed if isfinite(speed) else None
        return fields
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
            base_cells = tuple(message.voltages)
            extension_cells = getattr(message, "voltages_ext", ()) if (
                len(base_cells) == 10 and all(0 < value < 65535 for value in base_cells)
            ) else ()
            millivolts = sum(value for value in (*base_cells, *extension_cells)
                             if 0 < value < 65535)
            fields["battery_voltage_v"] = millivolts / 1000 if millivolts else None
        return fields
    return {}
