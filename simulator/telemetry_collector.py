"""Capture MAVLink telemetry from one ArduCopter SITL instance."""
import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
from time import monotonic
from uuid import uuid4

from simulator.mavlink_adapter import normalize, open_receiver

FIELDS = (
    "run_id", "scenario", "received_at_utc", "elapsed_s", "vehicle_id",
    "component_id", "message_type", "message_size_bytes", "sample_boot_ms",
    "gps_fix_type", "latitude_deg", "longitude_deg", "altitude_msl_m",
    "relative_altitude_m", "ground_speed_mps", "heading_deg",
    "roll_rad", "pitch_rad", "yaw_rad", "battery_id", "battery_remaining_pct", "battery_voltage_v",
    "armed", "base_mode", "autopilot_type", "flight_mode_code",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def collect(receiver, destination, args, *, on_live_telemetry=None, on_run_started=None):
    """Record one SITL run and optionally publish accepted live telemetry.

    The callback receives a parsed message and its CSV receive timestamp.
    It runs on the collection thread and should enqueue records without
    performing blocking network operations.
    """
    started = monotonic()
    destination.mkdir(parents=True, exist_ok=False)
    run = {
        "run_id": destination.name, "scenario": args.scenario,
        "port": args.port, "system_id": args.system_id, "started_at_utc": utc_now(),
        "heartbeat_timeout_s": args.heartbeat_timeout, "duration_limit_s": args.seconds,
        "simulator_revision": args.simulator_revision,
        "message_counts": {}, "link_events": [], "stop_reason": "error",
    }
    metadata = destination / "run.json"
    metadata.write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
    if on_run_started is not None:
        on_run_started(destination, started)
    last_heartbeat = started
    last_flush = started
    connected = False
    was_connected = False
    timeout_reported = False
    result = 0

    def event(name, now):
        run["link_events"].append({"event": name, "elapsed_s": now - started})
        print(f"{now - started:.1f}s {name}", flush=True)

    try:
        with (destination / "telemetry.csv").open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=FIELDS)
            writer.writeheader()
            while monotonic() - started < args.seconds:
                remaining = args.seconds - (monotonic() - started)
                if remaining <= 0:
                    break
                message = receiver.recv_match(blocking=True, timeout=min(0.25, remaining))
                now = monotonic()
                if now - last_heartbeat >= args.heartbeat_timeout and not timeout_reported:
                    event("heartbeat_lost" if connected else "heartbeat_timeout", now)
                    connected = False
                    timeout_reported = True
                if message is None or message.get_type() == "BAD_DATA":
                    continue
                if message.get_srcSystem() != args.system_id or message.get_srcComponent() != 1:
                    continue
                kind = message.get_type()
                if kind == "HEARTBEAT":
                    # MAV_AUTOPILOT_ARDUPILOTMEGA=3, MAV_TYPE_QUADROTOR=2.
                    if message.autopilot != 3 or message.type != 2:
                        continue
                    if not connected:
                        event("heartbeat_recovered" if was_connected else "heartbeat_received", now)
                    connected = was_connected = True
                    timeout_reported = False
                    last_heartbeat = now
                if not connected:
                    continue
                received_at_utc = utc_now()
                writer.writerow({
                    "run_id": run["run_id"], "scenario": args.scenario,
                    "received_at_utc": received_at_utc, "elapsed_s": now - started,
                    "vehicle_id": args.system_id, "component_id": message.get_srcComponent(),
                    "message_type": kind, "message_size_bytes": len(message.get_msgbuf()),
                    "sample_boot_ms": getattr(message, "time_boot_ms", None),
                    **normalize(message),
                })
                run["message_counts"][kind] = run["message_counts"].get(kind, 0) + 1
                if on_live_telemetry is not None and kind in {"HEARTBEAT", "GLOBAL_POSITION_INT", "SYS_STATUS", "BATTERY_STATUS"}:
                    on_live_telemetry(message, received_at_utc)
                if now - last_flush >= 1:
                    output.flush()
                    last_flush = now
        run["stop_reason"] = "duration_reached" if was_connected else "heartbeat_never_received"
    except KeyboardInterrupt:
        run["stop_reason"] = "interrupted"
    finally:
        run["ended_at_utc"] = utc_now()
        metadata.write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
        print(f"Recording directory: {destination}")
    if not was_connected:
        print("No matching ArduCopter heartbeat. Check MAVProxy output and system ID.")
        result = 1
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=14551)
    parser.add_argument("--system-id", type=int, default=1)
    parser.add_argument("--seconds", type=int, default=45)
    parser.add_argument("--heartbeat-timeout", type=int, default=5)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--simulator-revision")
    parser.add_argument("--output", type=Path, default=Path("datasets/sitl_generated"))
    args = parser.parse_args()
    if not (1 <= args.port <= 65535 and 1 <= args.system_id <= 255
            and args.seconds > 0 and args.heartbeat_timeout > 0):
        parser.error("Port, system ID, duration and heartbeat timeout must be in range.")
    receiver = open_receiver(args.port)
    try:
        return collect(receiver, args.output / uuid4().hex, args)
    finally:
        receiver.close()


if __name__ == "__main__":
    raise SystemExit(main())
