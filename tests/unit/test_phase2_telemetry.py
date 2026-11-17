import csv
import json
from types import SimpleNamespace
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest.mock import patch

from simulator.mavlink_adapter import normalize
from simulator.telemetry_collector import collect


class Message(SimpleNamespace):
    def get_type(self):
        return self.kind

    def get_srcSystem(self):
        return getattr(self, "system", 1)

    def get_srcComponent(self):
        return 1

    def get_msgbuf(self):
        return b"frame"


class TelemetryTest(unittest.TestCase):
    def test_position_units_and_unknown_heading(self):
        data = normalize(Message(kind="GLOBAL_POSITION_INT", lat=125000000,
                                 lon=-725000000, alt=202500, relative_alt=2500, hdg=65535))
        self.assertEqual(data, dict(latitude_deg=12.5, longitude_deg=-72.5,
                                    altitude_msl_m=202.5, relative_altitude_m=2.5, heading_deg=None))

    def test_missing_gps_and_battery(self):
        self.assertEqual(normalize(Message(kind="GPS_RAW_INT", fix_type=1)), {"gps_fix_type": 1})
        self.assertEqual(normalize(Message(kind="SYS_STATUS", voltage_battery=65535,
                                          battery_remaining=-1)),
                         {"battery_remaining_pct": None, "battery_voltage_v": None})

    def test_battery_status_pack_voltage(self):
        message = Message(kind="BATTERY_STATUS", id=1, battery_remaining=75,
                          voltages=[65534, 4466] + [65535] * 8, voltages_ext=[0] * 4)
        self.assertEqual(normalize(message)["battery_voltage_v"], 70.0)

    def test_duration_without_heartbeat(self):
        receiver = SimpleNamespace(recv_match=lambda **kwargs: None)
        args = SimpleNamespace(seconds=1, scenario="unit", port=14551, system_id=1,
                               heartbeat_timeout=5, simulator_revision=None)
        with TemporaryDirectory() as temp:
            destination = Path(temp) / "no-heartbeat"
            with patch("simulator.telemetry_collector.monotonic",
                       side_effect=[0, 0, 0, 1, 1]):
                self.assertEqual(collect(receiver, destination, args), 1)
            metadata = json.loads((destination / "run.json").read_text())
        self.assertEqual(metadata["stop_reason"], "heartbeat_never_received")

    def test_recording_after_heartbeat_and_recovery(self):
        heartbeat = Message(kind="HEARTBEAT", type=2, autopilot=3)
        wrong_system = Message(kind="HEARTBEAT", type=2, autopilot=3, system=2)
        hud = Message(kind="VFR_HUD", groundspeed=2.5, heading=45)
        messages = iter([hud, wrong_system, heartbeat, hud, None, hud, heartbeat, hud])
        clock = 0

        def receive(**kwargs):
            nonlocal clock
            clock += 1
            return next(messages)

        receiver = SimpleNamespace(recv_match=receive)
        args = SimpleNamespace(seconds=8, scenario="unit", port=14551, system_id=1,
                               heartbeat_timeout=2, simulator_revision=None)
        with TemporaryDirectory() as temp:
            destination = Path(temp) / "test-run"
            with patch("simulator.telemetry_collector.monotonic", lambda: clock):
                self.assertEqual(collect(receiver, destination, args), 0)
            with (destination / "telemetry.csv").open(newline="") as source:
                rows = list(csv.DictReader(source))
            metadata = json.loads((destination / "run.json").read_text())
        self.assertEqual([row["message_type"] for row in rows],
                         ["HEARTBEAT", "VFR_HUD", "HEARTBEAT", "VFR_HUD"])
        self.assertEqual(rows[-1]["ground_speed_mps"], "2.5")
        self.assertEqual([item["event"] for item in metadata["link_events"]],
                         ["heartbeat_timeout", "heartbeat_received", "heartbeat_lost",
                          "heartbeat_recovered"])
