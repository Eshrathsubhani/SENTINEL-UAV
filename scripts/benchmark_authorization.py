"""Measure local policy decisions and audit commits against isolated test data."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from math import ceil
from pathlib import Path
import platform
import statistics
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter_ns, time

from database.identity_database import connect_database
from security.authorization.policy_engine import PolicyEngine
from security.identity.uav_registry import UAVRegistry

ROOT = Path(__file__).resolve().parents[1]
BEGIN = "<!-- LATENCY_RESULTS_BEGIN -->"
END = "<!-- LATENCY_RESULTS_END -->"


def prepare(database):
    registry = UAVRegistry(database)
    auth = registry.auth
    admin_id = auth.bootstrap_admin("benchmark_admin", "temporary-benchmark-admin-password")
    admin = auth.login("benchmark_admin", "temporary-benchmark-admin-password")
    operator_id = auth.create_user(admin, "operator", "temporary-operator-password", "Operator")
    operator = auth.login("operator", "temporary-operator-password")
    viewer_id = auth.create_user(admin, "viewer", "temporary-viewer-password", "Viewer")
    viewer = auth.login("viewer", "temporary-viewer-password")
    revoked_id = auth.create_user(admin, "revoked", "temporary-revoked-password", "Operator")
    revoked = auth.login("revoked", "temporary-revoked-password")
    auth.set_user_status(admin, revoked_id, "revoked")
    uavs = [
        registry.register(admin, f"Benchmark UAV {number}", number,
                          f"urn:sentinel:uav:{number}", "a" * 64)
        for number in (1, 2, 3)
    ]
    for uav in uavs:
        registry.set_status(admin, uav, "active")
    for user in (admin_id, operator_id, viewer_id):
        registry.assign(admin, user, uavs[0])
    registry.assign(admin, operator_id, uavs[1])
    registry.set_status(admin, uavs[1], "suspended")
    engine = PolicyEngine(database)
    engine.configure_mission(admin, uavs[0], -35.3632622, 149.1652375)
    now = float(int(time()))
    engine.auth.clock = lambda: now

    def position(age):
        stamp = datetime.fromtimestamp(now - age, timezone.utc).isoformat()
        record = {
            "schema_version": 3, "uav_identity": "urn:sentinel:uav:1",
            "system_id": 1, "signing_key_id": "a" * 64,
            "captured_at": stamp,
            "values": {"latitude_deg": -35.3632622, "longitude_deg": 149.1652375},
        }
        # Controlled synthetic snapshots for measuring decision processing only.
        db = connect_database(database)
        try:
            with db:
                db.execute("""
                    INSERT INTO telemetry_snapshots VALUES (?, 'GLOBAL_POSITION_INT', ?, ?)
                    ON CONFLICT(uav_id, message_type) DO UPDATE SET
                        payload_json=excluded.payload_json, received_at_utc=excluded.received_at_utc
                """, (uavs[0], json.dumps(record), stamp))
        finally:
            db.close()

    position(0)
    cases = [
        ("assigned_operator", operator, uavs[0], "status.read", "allowed", None),
        ("viewer_command_denied", viewer, uavs[0], "command.status", "role_denied", None),
        ("unassigned_operator", operator, uavs[2], "status.read", "uav_unassigned", None),
        ("revoked_user", revoked, uavs[0], "status.read", "invalid_session", None),
        ("suspended_uav", operator, uavs[1], "status.read", "uav_inactive", None),
        ("unsupported_action", operator, uavs[0], "command.arm", "unsupported_action", None),
        ("unknown_uav", operator, "unknown-uav", "status.read", "unknown_uav", None),
        ("fresh_mission_update", operator, uavs[0], "mission.update", "allowed", lambda: position(0)),
        ("stale_mission_update", operator, uavs[0], "mission.update",
         "mission_stale_position", lambda: position(10)),
    ]
    return engine, cases


def measure(samples):
    rows = []
    with TemporaryDirectory(prefix="sentinel-authorization-benchmark-") as directory:
        engine, cases = prepare(Path(directory) / "identity.sqlite3")
        for name, token, uav, action, expected, setup in cases:
            if setup is not None:
                setup()
            print(f"Measuring {name}...", flush=True)
            durations = []
            for index in range(samples + 3):
                start = perf_counter_ns()
                decision = engine.authorize(token, uav, action)
                elapsed = (perf_counter_ns() - start) / 1_000_000
                if decision.reason != expected or decision.allowed != (expected == "allowed"):
                    raise RuntimeError(f"Unexpected decision for {name}: {decision.reason}")
                if index >= 3:
                    durations.append(elapsed)
            ordered = sorted(durations)
            row = {
                "case": name, "expected_reason": expected, "samples": samples,
                "p50_ms": ordered[ceil(samples * 0.50) - 1],
                "p95_ms": ordered[ceil(samples * 0.95) - 1],
                "mean_ms": statistics.mean(durations),
                "min_ms": ordered[0], "max_ms": ordered[-1],
                "samples_ms": durations,
            }
            rows.append(row)
            print(f"  p50={row['p50_ms']:.3f} ms  p95={row['p95_ms']:.3f} ms", flush=True)
    return rows


def git_value(arguments):
    result = subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def update_report(path, result):
    source = path.read_text(encoding="utf-8")
    if source.count(BEGIN) != 1 or source.count(END) != 1:
        raise ValueError("Report requires exactly one latency marker pair")
    start = source.index(BEGIN) + len(BEGIN)
    finish = source.index(END)
    if finish < start:
        raise ValueError("Report latency markers are out of order")
    lines = [
        "", "", f"Measured at {result['measured_at_utc']} on {result['platform']}.",
        f"Python {result['python']}. Each case has {result['samples_per_case']} measured samples",
        "after three warm-up decisions. All measured decisions matched their expected outcomes.",
        "", "| Authorization case | Median | 95th percentile |",
        "|---|---:|---:|",
    ]
    for row in result["cases"]:
        lines.append(f"| {row['case']} | {row['p50_ms']:.3f} ms | {row['p95_ms']:.3f} ms |")
    lines.extend([
        "", "Timing includes session and policy lookup, SQLite connection and transaction",
        "overhead, authorization evaluation, and the audit commit. Password hashing,",
        "login, fixture preparation, UI rendering, and network transport are excluded.",
        "The fixture uses synthetic local identities and a fixed test clock for reproducible",
        "fresh and stale mission decisions. The temporary database is removed afterward.",
        "Raw samples, environment details, source hashes, and Git provenance are saved",
        "in the benchmark JSON evidence file.", "", "",
    ])
    path.write_text(source[:start] + "\n".join(lines) + source[finish:], encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not 10 <= args.samples <= 1000:
        parser.error("Use between 10 and 1000 samples per case")
    if args.report is not None:
        source = args.report.read_text(encoding="utf-8")
        if source.count(BEGIN) != 1 or source.count(END) != 1:
            parser.error("The report must contain its latency marker pair")
    result = {
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "python": platform.python_version(),
        "scope": "local SQLite policy decisions including audit commit",
        "samples_per_case": args.samples, "warmup_per_case": 3,
        "git_revision": git_value(["rev-parse", "HEAD"]),
        "working_tree_status": git_value(["status", "--short"]),
        "source_sha256": {
            name: sha256((ROOT / name).read_bytes()).hexdigest()
            for name in (
                "security/authorization/policy_engine.py",
                "security/authorization/mission_policy.py",
                "security/authentication/auth_service.py",
                "database/identity_database.py",
                "scripts/benchmark_authorization.py",
            )
        },
        "cases": measure(args.samples),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.report is not None:
        update_report(args.report, result)
    print(f"Benchmark saved to {args.output}")
    if args.report is not None:
        print(f"Validation report updated at {args.report}")


if __name__ == "__main__":
    main()
