"""WSL-only paired capture with owned GCS lifecycle and reviewed provenance."""
import argparse
import csv
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

from scripts.phase6_extract_features import load_run


def git_revision(directory):
    return subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()


def simulator_instance(proc=Path("/proc")):
    """Identify a running ArduCopter process; new IDs alone do not establish groups."""
    boot = (proc / "sys/kernel/random/boot_id").read_text().strip()
    matches = []
    for directory in proc.iterdir():
        if not directory.name.isdigit():
            continue
        try:
            executable = (directory / "cmdline").read_bytes().split(b"\0", 1)[0].decode()
            if Path(executable).name != "arducopter":
                continue
            start_ticks = (directory / "stat").read_text().rsplit(")", 1)[1].split()[19]
            matches.append(sha256(f"{boot}:{directory.name}:{start_ticks}".encode()).hexdigest())
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    if len(matches) != 1:
        raise ValueError("Expected exactly one running arducopter process")
    return matches[0]


def check_group(root, group, fingerprint):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", group) or group in (".", ".."):
        raise ValueError("Use a simple parent-group name")
    if (root / group).exists():
        raise ValueError("Group directory exists; never overwrite or reuse it")
    for path in root.glob("*/session_manifest.json"):
        manifest = json.loads(path.read_text())
        if manifest.get("simulator_instance_fingerprint") == fingerprint:
            raise ValueError("This simulator process already has a group; restart SITL before a new group")


def port_free(port, socket_type=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, socket_type) as probe:
        probe.bind(("127.0.0.1", port))


def stop_owned(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)


def ready(process, log, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if process.poll() is not None:
            raise RuntimeError("GCS exited; inspect gateway_server.log")
        if "gcs_listening port=" in log.read_text(errors="replace"):
            return
        time.sleep(0.1)
    raise RuntimeError("GCS readiness timeout; inspect gateway_server.log")


def review(directory, received, allow_queue_drops):
    manifest, _, _, _ = load_run(directory, allow_queue_drops=allow_queue_drops)
    events = [json.loads(line) for line in (directory / "experiment_events.jsonl").read_text().splitlines() if line]
    ids = lambda kind: {e["record_id"] for e in events if e["event"] == kind}
    if not ids("forwarding_acknowledged") <= received:
        raise ValueError("GCS JSONL is missing acknowledged records")
    if (ids("forwarding_suppressed") | ids("queue_drop")) & received:
        raise ValueError("GCS received IDs declared unsent")
    with (directory / "telemetry.csv").open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) < 2:
        raise ValueError("Too few source observations")
    utc = [datetime.fromisoformat(row["received_at_utc"]).timestamp() for row in rows]
    elapsed = [float(row["elapsed_s"]) for row in rows]
    return dict(run_id=manifest["run_id"], scenario=manifest["scenario"],
                source_records=len(ids("source_record")),
                forwarding_summary=manifest["forwarding_summary"],
                suppressed_records=manifest["suppressed_records"],
                utc_backward_steps=sum(b < a for a, b in zip(utc, utc[1:])),
                utc_minus_monotonic_span_s=(utc[-1]-utc[0])-(elapsed[-1]-elapsed[0]),
                hashes_record_accounting_and_gcs_ids="PASS",
                training_acceptance="PENDING_REVIEW")


def collect(args):
    if os.name != "posix" or not Path("/proc").is_dir():
        raise ValueError("Run this helper in Ubuntu/WSL using the SENTINEL Python environment")
    os.umask(0o077)
    repository = Path(__file__).resolve().parents[1]
    # Require the helper and collection code to be committed for declared provenance.
    tracked = subprocess.check_output(["git", "-c", "core.autocrlf=true", "-C", str(repository), "ls-files", "scripts/phase6_collect_pair.py"], text=True)
    dirty = subprocess.check_output(["git", "-c", "core.autocrlf=true", "-C", str(repository), "diff", "HEAD", "--name-only", "--", "scripts", "simulator", "gateways", "security", "database", "backend"], text=True)
    if not tracked.strip() or dirty.strip():
        raise ValueError("Commit collection-code changes using Windows Git before running this helper")
    fingerprint = simulator_instance()
    root = args.output_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    check_group(root, args.parent_group, fingerprint)
    for path in (args.tls_dir/"ca.pem", args.tls_dir/"gcs.pem", args.tls_dir/"gcs.key",
                 args.tls_dir/"uav.pem", args.tls_dir/"uav.key", args.signing_key_file,
                 args.signing_state, args.identity_database):
        if not path.is_file():
            raise ValueError("Required file missing: " + str(path))
    port_free(18443)
    port_free(14551, socket.SOCK_DGRAM)
    folder = root/args.parent_group
    folder.mkdir()
    manifest = dict(parent_group_id=args.parent_group, status="collecting",
                    started_at_utc=datetime.now(timezone.utc).isoformat(),
                    simulator_instance_fingerprint=fingerprint,
                    source_revision=git_revision(repository),
                    simulator_revision=git_revision(args.ardupilot),
                    training_approved=False,
                    grouping_limitation="Different processes are separate sessions, not proof of statistical independence")
    mpath = folder/"session_manifest.json"
    def save():
        temp = folder/"session_manifest.tmp"
        temp.write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
        temp.replace(mpath)
    save()
    command = [sys.executable, "-m", "gateways.live_gateway"]
    tls = ["--ca-file", str(args.tls_dir/"ca.pem")]
    database = str(args.identity_database)
    log = folder/"gateway_server.log"
    with log.open("x", encoding="utf-8") as stream:
        process = subprocess.Popen(command+["gcs"]+tls+[
            "--cert-file", str(args.tls_dir/"gcs.pem"), "--key-file", str(args.tls_dir/"gcs.key"),
            "--identity-database", database, "--security-event-database", database,
            "--heartbeat-timeout", "5", "--received", str(folder/"gcs_received_telemetry.jsonl")],
            cwd=repository, stdout=stream, stderr=subprocess.STDOUT)
        try:
            ready(process, log)
            for scenario in ("normal", "interruption"):
                if process.poll() is not None or simulator_instance() != fingerprint:
                    raise RuntimeError("GCS exited or simulator instance changed")
                print(f"Capturing {args.parent_group}: {scenario} (90 seconds)", flush=True)
                flags = [] if scenario == "normal" else ["--interrupt-at", "30", "--interrupt-for", "15"]
                with (folder/(scenario+"_client.log")).open("x", encoding="utf-8") as client_log:
                    subprocess.run(command+["uav"]+tls+[
                        "--cert-file", str(args.tls_dir/"uav.pem"), "--key-file", str(args.tls_dir/"uav.key"),
                        "--signing-key-file", str(args.signing_key_file), "--signing-state", str(args.signing_state),
                        "--security-event-database", database, "--registry-records", "--seconds", "90",
                        "--scenario", "phase6_stationary_"+scenario, "--experiment-parent-group", args.parent_group,
                        "--source-revision", manifest["source_revision"],
                        "--simulator-revision", manifest["simulator_revision"],
                        "--output", str(folder/scenario)]+flags,
                        cwd=repository, stdout=client_log, stderr=subprocess.STDOUT,
                        check=True, timeout=130)
                runs = list((folder/scenario).glob("*/experiment_manifest.json"))
                if len(runs) != 1:
                    raise RuntimeError("Expected one capture per scenario")
                received = {json.loads(line)["record_id"] for line in
                            (folder/"gcs_received_telemetry.jsonl").read_text().splitlines() if line.strip()}
                manifest.setdefault("runs", []).append(review(runs[0].parent, received, args.allow_queue_drops))
                save()
            manifest["status"] = "collected_pending_scientific_review"
        except BaseException:
            manifest["status"] = "error_or_interrupted"
            raise
        finally:
            stop_owned(process)
            manifest["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
            save()
    print(json.dumps(manifest, indent=2))
    print("Session saved:", folder)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tls-dir", type=Path, required=True)
    parser.add_argument("--signing-key-file", type=Path, required=True)
    parser.add_argument("--signing-state", type=Path, required=True)
    parser.add_argument("--identity-database", type=Path, required=True)
    parser.add_argument("--parent-group", required=True)
    parser.add_argument("--ardupilot", type=Path, default=Path.home()/"ardupilot")
    parser.add_argument("--output-root", type=Path, default=Path("datasets/sitl_generated/phase6_corpus_sessions"))
    parser.add_argument("--allow-queue-drops", action="store_true")
    args = parser.parse_args()
    try:
        collect(args)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Collection stopped: {error}\nPreserve partial evidence; do not reuse that group.\n")


if __name__ == "__main__":
    main()
