"""Verify provenance, intervention boundaries and existing signed forwarding."""
import json
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from gateways import live_gateway
from simulator.experiment_run import ExperimentRun


class ExperimentRunTest(unittest.TestCase):
    def make(self, **kwargs):
        return ExperimentRun("parent-01", "stationary", "abc123", "sitl123", **kwargs)

    def record(self):
        return dict(record_id="r1", captured_at="2026-11-26T00:00:00+00:00",
                    message_type="HEARTBEAT", system_id=1, component_id=1)

    def prepare(self, directory, **kwargs):
        run = self.make(**kwargs)
        for name in ("telemetry.csv", "run.json"):
            (directory / name).write_text("test\n", encoding="utf-8")
        run.start(directory, 100)
        return run

    def test_reject_invalid_configuration(self):
        for kwargs in (dict(interrupt_at=1), dict(interrupt_for=2),
                       dict(interrupt_at=-1, interrupt_for=2),
                       dict(interrupt_at=1, interrupt_for=0),
                       dict(interrupt_at=float("nan"), interrupt_for=1),
                       dict(interrupt_at=1, interrupt_for=float("inf"))):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.make(**kwargs)
        with self.assertRaises(ValueError):
            ExperimentRun("../outside", "normal", "rev", "rev")

    def test_suppression_is_half_open_and_does_not_modify_records(self):
        with TemporaryDirectory() as root:
            run = self.prepare(Path(root), interrupt_at=10, interrupt_for=5)
            record = self.record()
            original = dict(record)
            for clock, expected in ((109.9, False), (110, True), (114.99, True), (115, False)):
                with patch("simulator.experiment_run.monotonic", return_value=clock):
                    self.assertEqual(run.suppress(record), expected)
            self.assertEqual(original, record)
            run.finish("collector_returned", {"acknowledged": 0})
            events = [json.loads(line) for line in (Path(root) / "experiment_events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(e["event"] == "forwarding_suppressed" for e in events), 2)
            self.assertEqual(sum(e["event"] == "interruption_observed_start" for e in events), 1)
            self.assertEqual(sum(e["event"] == "interruption_observed_end" for e in events), 1)

    def test_manifest_hashes_and_no_overwrite(self):
        with TemporaryDirectory() as root:
            path = Path(root)
            run = self.prepare(path)
            self.assertFalse(run.suppress(self.record()))
            run.finish("collector_returned", {})
            manifest = json.loads((path / "experiment_manifest.json").read_text())
            self.assertEqual(manifest["label_status"], "requires_run_review")
            self.assertEqual(manifest["parent_group_id"], "parent-01")
            for name, details in manifest["artifacts"].items():
                self.assertEqual(details["sha256"], sha256((path / name).read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError):
                self.make().start(path, 100)

    def test_suppression_never_calls_transport(self):
        self.capture(True)

    def test_normal_forwarding_records_ack(self):
        self.capture(False)

    def test_transport_failure_is_not_reported_as_ack(self):
        self.capture(False, transport_error=True)

    def capture(self, suppress, transport_error=False):
        with TemporaryDirectory() as root:
            args = SimpleNamespace(
                security_event_database=None, signing_key_file=Path("key"),
                signing_state=Path("state"), registry_records=True,
                command_database=None, credential_audit_db=None, port=14551,
                system_id=1, uav_identity="urn:sentinel:uav:1",
                output=Path(root), tls_port=18443, server_name="gcs.sentinel.test",
                seconds=60, heartbeat_timeout=5,
            )
            experiment = self.make(**(dict(interrupt_at=0, interrupt_for=20) if suppress else {}))
            message = Mock()
            message.get_type.return_value = "HEARTBEAT"
            record = self.record()

            def capture(receiver, destination, args, *, on_live_telemetry, on_run_started):
                destination.mkdir()
                (destination / "telemetry.csv").write_text("source stays recorded\n")
                (destination / "run.json").write_text('{"stop_reason":"duration_reached"}')
                from time import monotonic
                on_run_started(destination, monotonic())
                on_live_telemetry(message, record["captured_at"])
                return 0

            with patch.object(live_gateway, "open_receiver"), \
                 patch.object(Path, "read_bytes", return_value=b"a" * 32), \
                 patch.object(live_gateway, "SigningVerifier"), \
                 patch.object(live_gateway, "SignedTelemetryReceiver"), \
                 patch.object(live_gateway, "collect", side_effect=capture), \
                 patch.object(live_gateway, "live_record", return_value=record), \
                 patch.object(live_gateway, "send_telemetry") as send:
                send.return_value = (1.0, 2.0)
                if transport_error:
                    send.side_effect = OSError("test transport failure")
                self.assertEqual(live_gateway.run_uav(args, Mock(), experiment=experiment), 0)
                if suppress:
                    send.assert_not_called()
                else:
                    send.assert_called_once()
                    self.assertEqual(send.call_args.args[3], record)
            manifest = json.loads((Path(root) / experiment.run_id / "experiment_manifest.json").read_text())
            self.assertEqual(manifest["suppressed_records"], int(suppress))
            self.assertEqual(manifest["forwarding_summary"]["enqueued"], int(not suppress))
            self.assertEqual(manifest["forwarding_summary"]["acknowledged"],
                             int(not suppress and not transport_error))
            self.assertEqual(manifest["forwarding_summary"]["unacknowledged"],
                             int(not suppress and transport_error))

    def test_cli_rejects_experiment_without_strict_signing(self):
        argv = ["gateway", "uav", "--ca-file", "ca", "--cert-file", "cert",
                "--key-file", "key", "--experiment-parent-group", "parent"]
        with patch("sys.argv", argv), self.assertRaises(SystemExit) as error:
            live_gateway.main()
        self.assertEqual(error.exception.code, 2)
