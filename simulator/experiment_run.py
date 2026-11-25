"""Local run evidence and a bounded forwarding interruption, never attack labels."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import re
from threading import Lock
from time import monotonic
from uuid import uuid4


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class ExperimentRun:
    def __init__(self, parent_group, scenario, source_revision, simulator_revision,
                 *, interrupt_at=None, interrupt_for=None):
        for value in (parent_group, scenario, source_revision, simulator_revision):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value):
                raise ValueError("Experiment identifiers must be 1-128 simple characters")
        if (interrupt_at is None) != (interrupt_for is None):
            raise ValueError("Interruption requires both start and duration")
        if interrupt_at is not None and not (
            math.isfinite(interrupt_at) and interrupt_at >= 0
            and math.isfinite(interrupt_for) and interrupt_for > 0
        ):
            raise ValueError("Invalid interruption interval")
        self.run_id = uuid4().hex
        self.parent_group = parent_group
        self.scenario = scenario
        self.source_revision = source_revision
        self.simulator_revision = simulator_revision
        self.interrupt_at = interrupt_at
        self.interrupt_for = interrupt_for
        self.lock = Lock()
        self.file = None
        self.started = None
        self.interrupted = False
        self.suppressed = 0
        self.sequence = 0

    def start(self, directory, started):
        self.directory = Path(directory)
        self.started = started
        self.file = (self.directory / "experiment_events.jsonl").open("x", encoding="utf-8")
        self.manifest = {
            "schema_version": 1, "run_id": self.run_id,
            "parent_group_id": self.parent_group, "scenario": self.scenario,
            "source_revision": self.source_revision,
            "simulator_revision": self.simulator_revision,
            "python_version": platform.python_version(),
            "configuration": getattr(self, "configuration", {}),
            "started_at_utc": utc_now(), "status": "running",
            "observation_boundary": "post_signature_verification_pre_mtls_forwarding",
            "ground_truth": "normal_candidate" if self.interrupt_at is None else "controlled_communication_fault",
            "label_status": "requires_run_review",
            "planned_interruption": None if self.interrupt_at is None else {
                "start_elapsed_s": self.interrupt_at,
                "end_elapsed_s": self.interrupt_at + self.interrupt_for,
                "mechanism": "suppress_new_forwarding_enqueues",
            },
        }
        self._manifest()
        self.event("run_started")

    def _manifest(self):
        path = self.directory / "experiment_manifest.json"
        temporary = self.directory / "experiment_manifest.tmp"
        temporary.write_text(json.dumps(self.manifest, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)

    def event(self, event, *, record=None, **details):
        with self.lock:
            self.sequence += 1
            data = {
                "sequence": self.sequence, "event": event,
                "elapsed_s": monotonic() - self.started,
                "occurred_at_utc": utc_now(),
            }
            if record is not None:
                data.update(record_id=record["record_id"],
                            captured_at=record["captured_at"],
                            message_type=record["message_type"],
                            system_id=record["system_id"],
                            component_id=record["component_id"])
            data.update(details)
            self.file.write(json.dumps(data, allow_nan=False) + "\n")
            self.file.flush()

    def suppress(self, record):
        elapsed = monotonic() - self.started
        active = (self.interrupt_at is not None
                  and self.interrupt_at <= elapsed < self.interrupt_at + self.interrupt_for)
        if active != self.interrupted:
            self.event("interruption_observed_start" if active else "interruption_observed_end")
            self.interrupted = active
        if active:
            self.suppressed += 1
            self.event("forwarding_suppressed", record=record)
        return active

    def finish(self, status, stats):
        if self.file is None:
            return
        try:
            self.event("run_finished", status=status)
        finally:
            self.file.close()
        artifacts = {}
        for name in ("telemetry.csv", "run.json", "experiment_events.jsonl"):
            path = self.directory / name
            if not path.is_file():
                artifacts[name] = {"missing": True}
                status = "incomplete_evidence"
                continue
            digest = sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            artifacts[name] = {"sha256": digest.hexdigest(), "bytes": path.stat().st_size}
        self.manifest.update(status=status, ended_at_utc=utc_now(),
                             suppressed_records=self.suppressed,
                             forwarding_summary=dict(stats), artifacts=artifacts,
                             interruption_active_at_finish=self.interrupted)
        self._manifest()
