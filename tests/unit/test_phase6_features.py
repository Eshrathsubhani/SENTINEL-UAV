import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.phase6_extract_features import FEATURES, digest, extract, load_run, windows


class FeaturesTest(unittest.TestCase):
    def fixture(self, root, run_id="run1", parent="shared-parent"):
        root.mkdir()
        rows = []
        for index, (elapsed, kind) in enumerate(((1, "HEARTBEAT"), (2, "GLOBAL_POSITION_INT"), (6, "HEARTBEAT"))):
            rows.append(dict(run_id=run_id, elapsed_s=elapsed,
                             received_at_utc=f"2026-11-26T00:00:0{index}+00:00",
                             message_type=kind, vehicle_id=1, component_id=1, message_size_bytes=34))
        with (root / "telemetry.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
        events = []
        def event(kind, elapsed, **details):
            events.append(dict(sequence=len(events)+1, event=kind, elapsed_s=elapsed, **details))
        event("run_started", 0)
        for index, row in enumerate(rows):
            fields = dict(record_id=str(index), captured_at=row["received_at_utc"],
                          message_type=row["message_type"], system_id=1, component_id=1)
            event("source_record", row["elapsed_s"]+0.1, **fields)
            event("forwarding_acknowledged" if index < 2 else "forwarding_suppressed",
                  row["elapsed_s"]+0.2, **fields)
        event("run_finished", 10.1)
        (root / "experiment_events.jsonl").write_text("".join(json.dumps(e)+"\n" for e in events))
        (root / "run.json").write_text(json.dumps(dict(run_id=run_id, stop_reason="duration_reached",
            duration_limit_s=10, message_counts={"HEARTBEAT": 2, "GLOBAL_POSITION_INT": 1})))
        manifest = dict(run_id=run_id, parent_group_id=parent, status="collector_returned",
                        forwarding_summary={"acknowledged": 2, "queue_drops": 0}, suppressed_records=1,
                        artifacts={name: {"sha256": digest(root/name), "bytes": (root/name).stat().st_size}
                                   for name in ("telemetry.csv", "run.json", "experiment_events.jsonl")})
        (root / "experiment_manifest.json").write_text(json.dumps(manifest))
        return root

    def test_boundaries_empty_windows_and_heartbeat_carry(self):
        rows = list(windows([(0, "HEARTBEAT", 34), (5, "SYS_STATUS", 20)], 15, 5))
        self.assertEqual([r["message_count"] for r in rows], [1, 1, 0])
        self.assertEqual(rows[-1]["heartbeat_age_at_end_s"], 15)
        self.assertIsNone(rows[-1]["source_frame_bytes_mean"])
        self.assertIsNone(rows[0]["interarrival_mean_s"])

    def test_trailing_partial_window_is_not_exported(self):
        self.assertEqual(len(list(windows([], 12, 5))), 2)
        self.assertIsNone(list(windows([], 5, 5))[0]["heartbeat_age_at_end_s"])

    def test_invalid_width(self):
        for width in (0, -1, float("inf"), float("nan")):
            with self.subTest(width=width), self.assertRaises(ValueError):
                list(windows([], 10, width))

    def test_scopes_groups_and_no_label_features(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            one = self.fixture(root/"one")
            two = self.fixture(root/"two", run_id="run2")
            self.assertEqual(extract([one, two], root/"output"), {"source": 4, "forwarding_ack": 4})
            contract = json.loads((root/"output/feature_contract.json").read_text())
            self.assertFalse(contract["training_approved"])
            self.assertEqual({r["parent_group_id"] for r in contract["runs"]}, {"shared-parent"})
            self.assertFalse(set(FEATURES) & {"scenario", "label", "suppressed_records", "run_id", "parent_group_id"})
            with (root/"output/forwarding_ack_features.csv").open(newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(rows[1]["message_count"], "0")
            self.assertEqual(rows[1]["source_frame_bytes_mean"], "")
            self.assertTrue((root/"output/COMPLETE").is_file())

    def test_tampering_rejected_before_output_creation(self):
        with TemporaryDirectory() as d:
            root = Path(d); one = self.fixture(root/"one")
            with (one/"telemetry.csv").open("a") as f: f.write("tampering")
            with self.assertRaises(ValueError): extract([one], root/"output")
            self.assertFalse((root/"output").exists())

    def test_incomplete_run_rejected(self):
        with TemporaryDirectory() as d:
            one = self.fixture(Path(d)/"one")
            p = one/"experiment_manifest.json"; m = json.loads(p.read_text());m["status"]="error";p.write_text(json.dumps(m))
            with self.assertRaises(ValueError): load_run(one)

    def test_existing_export_never_overwritten(self):
        with TemporaryDirectory() as d:
            root = Path(d);one=self.fixture(root/"one");out=root/"output";out.mkdir();(out/"keep").write_text("keep")
            with self.assertRaises(FileExistsError): extract([one], out)
            self.assertEqual((out/"keep").read_text(), "keep")

    def test_duplicate_run_rejected(self):
        with TemporaryDirectory() as d:
            root=Path(d);one=self.fixture(root/"one")
            with self.assertRaises(ValueError): extract([one,one], root/"output")

    def test_ambiguous_csv_key_rejected_even_with_updated_hashes(self):
        with TemporaryDirectory() as d:
            one=self.fixture(Path(d)/"one")
            p=one/"telemetry.csv"
            with p.open(newline="") as f:rows=list(csv.DictReader(f))
            rows[1].update(received_at_utc=rows[0]["received_at_utc"], message_type=rows[0]["message_type"])
            with p.open("w",newline="") as f:
                writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
            mpath=one/"experiment_manifest.json";m=json.loads(mpath.read_text());m["artifacts"]["telemetry.csv"]={"sha256":digest(p),"bytes":p.stat().st_size};mpath.write_text(json.dumps(m))
            with self.assertRaisesRegex(ValueError, "Ambiguous"):load_run(one)

    def test_horizon_tail_is_not_invented_as_an_extra_window(self):
        rows = list(windows([(9.9, "HEARTBEAT", 34), (10.01, "SYS_STATUS", 20)], 10, 5))
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(r["message_count"] for r in rows), 1)

    def test_window_heartbeat_history_does_not_cross_runs(self):
        one = list(windows([(1, "HEARTBEAT", 34)], 10, 5))
        two = list(windows([], 10, 5))
        self.assertEqual(one[1]["heartbeat_age_at_end_s"], 9)
        self.assertIsNone(two[0]["heartbeat_age_at_end_s"])
        self.assertIsNone(two[1]["heartbeat_age_at_end_s"])

    def test_backwards_event_time_rejected_with_valid_hash(self):
        with TemporaryDirectory() as d:
            one=self.fixture(Path(d)/"one")
            p=one/"experiment_events.jsonl"
            events=[json.loads(line) for line in p.read_text().splitlines()]
            events[2]["elapsed_s"]=0
            p.write_text("".join(json.dumps(e)+"\n" for e in events))
            mp=one/"experiment_manifest.json";m=json.loads(mp.read_text())
            m["artifacts"][p.name]={"sha256":digest(p),"bytes":p.stat().st_size};mp.write_text(json.dumps(m))
            with self.assertRaisesRegex(ValueError, "monotonic"):load_run(one)

    def test_queue_drop_requires_explicit_policy_and_keeps_source(self):
        with TemporaryDirectory() as d:
            root=Path(d);one=self.fixture(root/"one")
            p=one/"experiment_events.jsonl"
            events=[json.loads(line) for line in p.read_text().splitlines()]
            next(e for e in events if e["event"]=="forwarding_suppressed")["event"]="queue_drop"
            p.write_text("".join(json.dumps(e)+"\n" for e in events))
            mp=one/"experiment_manifest.json";m=json.loads(mp.read_text())
            m["suppressed_records"]=0;m["forwarding_summary"]["queue_drops"]=1
            m["artifacts"][p.name]={"sha256":digest(p),"bytes":p.stat().st_size};mp.write_text(json.dumps(m))
            with self.assertRaises(ValueError):load_run(one)
            loaded=load_run(one,allow_queue_drops=True)
            self.assertEqual(len(loaded[2]["source"]),3)
            self.assertEqual(len(loaded[2]["forwarding_ack"]),2)
