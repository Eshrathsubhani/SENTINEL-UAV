"""Battery/mode/speed normalization, validation and schema-5 history preservation."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from database.connection import connect_database, database_transaction
from database.identity_database import initialize_database
from database import migrations
from gateways.live_gateway import live_record
from gateways.telemetry_record import validate_record
from security.mavlink_signing import MAVLINK_EPOCH_NS, SignedTelemetryReceiver, SigningVerifier
from simulator.mavlink_adapter import normalize
from simulator.telemetry_collector import collect

IDENTITY = "urn:sentinel:uav:1"
STAMP = "2026-01-01T00:00:00+00:00"
KEY_ID = "a" * 64


def message(kind, **values):
    return SimpleNamespace(get_type=lambda: kind, get_srcSystem=lambda: 1,
                           get_srcComponent=lambda: 1, get_msgbuf=lambda: b"frame", **values)


class ExtendedTelemetryTest(unittest.TestCase):
    def record(self, kind, **values):
        return live_record(message(kind, **values), STAMP, IDENTITY, KEY_ID)

    def test_signed_battery_payload_has_correct_units_and_identifier(self):
        record = self.record("BATTERY_STATUS", id=2, battery_remaining=72,
                             voltages=[4200, 4190, 4180] + [65535] * 7, voltages_ext=[0] * 4)
        self.assertEqual(record["values"], {"battery_id": 2, "battery_remaining_pct": 72,
                                             "battery_voltage_v": 12.57})
        self.assertEqual(validate_record(record), record)
        self.assertEqual(record["signing_key_id"], KEY_ID)

    def test_unknown_battery_values_remain_absent_in_gateway_json(self):
        record = self.record("SYS_STATUS", battery_remaining=-1, voltage_battery=65535)
        self.assertEqual(record["values"], {})
        validate_record(record)

    def test_extension_cells_are_ignored_when_base_cells_are_unused(self):
        record = self.record("BATTERY_STATUS", id=0, battery_remaining=-1,
                             voltages=[12000] + [65535] * 9, voltages_ext=[4200] * 4)
        self.assertEqual(record["values"], {"battery_id": 0, "battery_voltage_v": 12.0})
        full = normalize(message("BATTERY_STATUS", id=0, battery_remaining=50,
                                 voltages=[4000] * 10, voltages_ext=[4000, 65535, 0, 0]))
        self.assertEqual(full["battery_voltage_v"], 44.0)

    def test_heartbeat_preserves_mode_code_and_armed_state_without_inventing_name(self):
        record = self.record("HEARTBEAT", type=2, autopilot=3, base_mode=129, custom_mode=4)
        self.assertEqual(record["values"], {"vehicle_type": 2, "autopilot_type": 3,
                                             "base_mode": 129, "armed": 1, "flight_mode_code": 4})
        validate_record(record)
        no_custom = self.record("HEARTBEAT", type=2, autopilot=3, base_mode=128, custom_mode=4)
        self.assertNotIn("flight_mode_code", no_custom["values"])
        validate_record(no_custom)

    def test_horizontal_speed_is_derived_from_position_velocity(self):
        record = self.record("GLOBAL_POSITION_INT", lat=0, lon=0, alt=1000,
                             relative_alt=0, hdg=65535, vx=300, vy=400, vz=-1200, time_boot_ms=100)
        self.assertEqual(record["values"]["ground_speed_mps"], 5.0)
        self.assertEqual(record["values"]["velocity_down_mps"], -12.0)
        validate_record(record)
        record["values"]["ground_speed_mps"] = 13.0
        with self.assertRaises(ValueError):
            validate_record(record)

    def test_invalid_battery_and_mode_payloads_are_rejected(self):
        record = self.record("BATTERY_STATUS", id=1, battery_remaining=50,
                             voltages=[12000] + [65535] * 9)
        for values in ({"battery_id": True}, {"battery_id": -1},
                       {"battery_id": 1, "battery_remaining_pct": 101},
                       {"battery_id": 1, "battery_voltage_v": -1},
                       {"battery_id": 1, "battery_voltage_v": float("nan")},
                       {"battery_id": 1, "extra": 1}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                validate_record(dict(record, values=values))
        heartbeat = self.record("HEARTBEAT", type=2, autopilot=3, base_mode=129, custom_mode=4)
        heartbeat["values"]["armed"] = 0
        with self.assertRaises(ValueError):
            validate_record(heartbeat)

    def test_collector_publishes_battery_only_after_matching_heartbeat(self):
        battery = message("SYS_STATUS", battery_remaining=50, voltage_battery=12000)
        heartbeat = message("HEARTBEAT", type=2, autopilot=3, base_mode=1, custom_mode=4)
        messages = iter([battery, heartbeat, battery])
        clock = 0
        accepted = []

        def receive(**kwargs):
            nonlocal clock
            clock += 1
            return next(messages)

        args = SimpleNamespace(seconds=3, scenario="battery-unit", port=14551, system_id=1,
                               heartbeat_timeout=5, simulator_revision=None)
        with TemporaryDirectory() as temp, patch("simulator.telemetry_collector.monotonic", lambda: clock):
            result = collect(SimpleNamespace(recv_match=receive), Path(temp) / "run", args,
                             on_live_telemetry=lambda msg, stamp: accepted.append(msg.get_type()))
        self.assertEqual(result, 0)
        self.assertEqual(accepted, ["HEARTBEAT", "SYS_STATUS"])

    def test_real_signed_battery_frames_pass_strict_receiver_and_wrong_key_does_not(self):
        from pymavlink.dialects.v20 import ardupilotmega as mav
        key = bytes(range(32))
        ticks = 100_000_000
        encoder = mav.MAVLink(None, srcSystem=1, srcComponent=1)
        encoder.signing.secret_key = key
        encoder.signing.timestamp = ticks
        encoder.signing.link_id = 1
        encoder.signing.sign_outgoing = True
        decoder = mav.MAVLink(None)
        raw_messages = [encoder.sys_status_encode(0, 0, 0, 0, 12000, 0, 75, 0, 0, 0, 0, 0, 0),
                        encoder.battery_status_encode(0, 0, 0, 0, [12000] + [65535] * 9,
                                                      0, 0, 0, 75)]
        with TemporaryDirectory() as temp, patch("security.mavlink_signing.time_ns",
                return_value=MAVLINK_EPOCH_NS + ticks * 10000):
            verifier = SigningVerifier(key, Path(temp) / "state.sqlite3")
            try:
                for original in raw_messages:
                    parsed = decoder.parse_char(original.pack(encoder))
                    receiver = SignedTelemetryReceiver(SimpleNamespace(recv_match=lambda **kw: parsed), verifier, 1)
                    self.assertIs(receiver.recv_match(), parsed)
                    self.assertIsNone(receiver.recv_match())  # Duplicate is still rejected.
                encoder.signing.secret_key = bytes(reversed(key))
                wrong = decoder.parse_char(raw_messages[0].pack(encoder))
                receiver = SignedTelemetryReceiver(SimpleNamespace(recv_match=lambda **kw: wrong), verifier, 1)
                self.assertIsNone(receiver.recv_match())
                self.assertEqual(receiver.rejected, {"invalid_signature": 1})
                encoder.signing.sign_outgoing = False
                unsigned = decoder.parse_char(raw_messages[0].pack(encoder))
                receiver = SignedTelemetryReceiver(SimpleNamespace(recv_match=lambda **kw: unsigned), verifier, 1)
                self.assertIsNone(receiver.recv_match())
                self.assertEqual(receiver.rejected, {"unsigned": 1})
            finally:
                verifier.close()

    def version5_fixture(self, path):
        with database_transaction(path) as db:
            for index, step in enumerate(migrations.MIGRATIONS[:5], 1):
                step(db)
                db.execute(f"PRAGMA user_version={index}")
            db.execute("INSERT INTO uavs (uav_id,name,system_id,certificate_identity,signing_key_id) "
                       "VALUES ('uav','fixture',1,?,?)", (IDENTITY, KEY_ID))
            db.execute("INSERT INTO telemetry_records VALUES ('old','uav',1,2,'HEARTBEAT',1,1,"
                       "'authenticated_uav_gateway','gateway_attested','{}')")

    def test_version5_history_and_index_survive_upgrade_to_current_schema(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "db.sqlite3"
            self.version5_fixture(path)
            with closing(connect_database(path)) as db:
                before = tuple(db.execute("SELECT * FROM telemetry_records").fetchone())
            initialize_database(path)
            with closing(connect_database(path)) as db:
                self.assertEqual(tuple(db.execute("SELECT * FROM telemetry_records").fetchone()), before)
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 9)
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertIn("telemetry_uav_time", {row[1] for row in db.execute("PRAGMA index_list(telemetry_records)")})

    def test_failed_history_rebuild_restores_original_table_and_version(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "db.sqlite3"
            self.version5_fixture(path)
            original = migrations.version_6

            def failure(db):
                original(db)
                raise RuntimeError("injected after table rebuild")

            with patch.object(migrations, "MIGRATIONS", (*migrations.MIGRATIONS[:5], failure)):
                with self.assertRaises(RuntimeError):
                    initialize_database(path)
            with closing(connect_database(path)) as db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertEqual(db.execute("SELECT record_id FROM telemetry_records").fetchone()[0], "old")
                self.assertNotIn("telemetry_records_v6", {row[0] for row in db.execute("SELECT name FROM sqlite_master")})
            initialize_database(path)
