"""Create diagnostic window features; never approve runs or assign attack labels."""
import argparse
from bisect import bisect_left
import csv
from hashlib import sha256
import json
import math
import sys
from pathlib import Path
from statistics import mean

KINDS = ("HEARTBEAT", "GLOBAL_POSITION_INT", "SYS_STATUS", "BATTERY_STATUS")
FEATURES = ("message_count", "message_rate_hz", "heartbeat_count", "position_count",
            "system_status_count", "battery_status_count", "source_frame_bytes_mean",
            "interarrival_mean_s", "interarrival_max_s", "heartbeat_age_at_end_s")
META = ("run_id", "parent_group_id", "window_index", "window_start_s", "window_end_s")
UNITS = ("count", "messages/s", "count", "count", "count", "count", "bytes",
         "seconds", "seconds", "seconds")


def digest(path):
    h = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def number(value):
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError("Expected a finite nonnegative measurement")
    return result


def csv_key(row):
    return (row["received_at_utc"], row["message_type"],
            int(row["vehicle_id"]), int(row["component_id"]))


def event_key(event):
    return (event["captured_at"], event["message_type"],
            event["system_id"], event["component_id"])


def load_run(directory):
    directory = Path(directory)
    manifest_path = directory / "experiment_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    run = json.loads((directory / "run.json").read_text(encoding="utf-8"))
    if manifest["status"] != "collector_returned" or run["stop_reason"] != "duration_reached":
        raise ValueError("Only completed captures can enter this diagnostic export")
    if manifest["run_id"] != run["run_id"] or not manifest["parent_group_id"]:
        raise ValueError("Missing or inconsistent provenance")
    hashes = {"experiment_manifest.json": digest(manifest_path)}
    for name in ("telemetry.csv", "run.json", "experiment_events.jsonl"):
        info = manifest["artifacts"][name]
        path = directory / name
        hashes[name] = digest(path)
        if info.get("missing") or hashes[name] != info["sha256"] or path.stat().st_size != info["bytes"]:
            raise ValueError("Artifact verification failed: " + name)
    with (directory / "telemetry.csv").open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != sum(run["message_counts"].values()):
        raise ValueError("CSV count disagrees with run metadata")
    lookup = {}
    previous = -1
    for row in rows:
        elapsed = number(row["elapsed_s"])
        if elapsed < previous or row["run_id"] != run["run_id"]:
            raise ValueError("Source time reversal or mixed run IDs")
        previous = elapsed
        number(row["message_size_bytes"])
        if row["message_type"] in KINDS:
            key = csv_key(row)
            if key in lookup:
                raise ValueError("Ambiguous source CSV join key")
            lookup[key] = row
    events = [json.loads(line) for line in
              (directory / "experiment_events.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    sources, acks, suppressed = {}, {}, set()
    previous = -1
    for sequence, event in enumerate(events, 1):
        elapsed = number(event["elapsed_s"])
        if elapsed < previous or event["sequence"] != sequence:
            raise ValueError("Event sequence or monotonic time is invalid")
        previous = elapsed
        kind = event["event"]
        if kind == "source_record":
            identity = event["record_id"]
            if identity in sources or event_key(event) not in lookup:
                raise ValueError("Duplicate or unmatched source event")
            row = lookup[event_key(event)]
            if elapsed < number(row["elapsed_s"]):
                raise ValueError("Source event precedes CSV observation")
            sources[identity] = row
        elif kind == "forwarding_acknowledged":
            identity = event["record_id"]
            if identity in acks or identity not in sources:
                raise ValueError("Duplicate or unmatched ACK")
            if event_key(event) != csv_key(sources[identity]):
                raise ValueError("ACK source identity mismatch")
            acks[identity] = elapsed
        elif kind == "forwarding_suppressed":
            identity = event["record_id"]
            if identity in suppressed or identity not in sources:
                raise ValueError("Duplicate or unmatched suppression")
            suppressed.add(identity)
        elif kind in {"queue_drop", "stale_drop", "forwarding_unacknowledged"}:
            raise ValueError("Loss/retry handling requires a separately reviewed export policy")
    if len(sources) != len(lookup) or len({csv_key(r) for r in sources.values()}) != len(lookup):
        raise ValueError("Source linkage is not one-to-one")
    if set(sources) != set(acks) | suppressed or set(acks) & suppressed:
        raise ValueError("Unaccounted or conflicting forwarding outcomes")
    if len(acks) != manifest["forwarding_summary"]["acknowledged"] or len(suppressed) != manifest["suppressed_records"]:
        raise ValueError("Manifest counts disagree with events")
    duration = number(run["duration_limit_s"])
    if not events or events[-1]["event"] != "run_finished" or events[-1]["elapsed_s"] < duration:
        raise ValueError("Capture completion does not cover configured duration")
    observations = {
        "source": sorted((number(row["elapsed_s"]), row["message_type"],
                          number(row["message_size_bytes"])) for row in sources.values()),
        "forwarding_ack": sorted((elapsed, sources[identity]["message_type"],
                                  number(sources[identity]["message_size_bytes"]))
                                 for identity, elapsed in acks.items()),
    }
    return manifest, duration, observations, hashes


def windows(observations, duration, width):
    """Half-open complete windows; carry last heartbeat within this run only."""
    width, duration = number(width), number(duration)
    if width == 0:
        raise ValueError("Window width must be positive")
    times = [item[0] for item in observations]
    heartbeats = [t for t, kind, _ in observations if kind == "HEARTBEAT"]
    for index in range(math.floor(duration / width)):
        start, end = index * width, (index + 1) * width
        group = observations[bisect_left(times, start):bisect_left(times, end)]
        gaps = [b[0] - a[0] for a, b in zip(group, group[1:])]
        before = bisect_left(heartbeats, end)
        values = (len(group), len(group) / width,
                  *(sum(item[1] == kind for item in group) for kind in KINDS),
                  mean(item[2] for item in group) if group else None,
                  mean(gaps) if gaps else None, max(gaps) if gaps else None,
                  end - heartbeats[before - 1] if before else None)
        yield dict(window_index=index, window_start_s=start, window_end_s=end,
                   **dict(zip(FEATURES, values)))


def extract(paths, output, width=5.0):
    width = number(width)
    if not 0 < width <= 3600:
        raise ValueError("Window width must be in (0, 3600] seconds")
    loaded = [load_run(path) for path in paths]
    ids = [item[0]["run_id"] for item in loaded]
    if not loaded or len(set(ids)) != len(ids):
        raise ValueError("Provide distinct explicit run directories")
    if any(duration < width for _, duration, _, _ in loaded):
        raise ValueError("Each run needs at least one complete window")
    # Validate every input before creating output; never overwrite an earlier export.
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    counts = {}
    for scope in ("source", "forwarding_ack"):
        count = 0
        with (output / (scope + "_features.csv")).open("x", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=META + FEATURES)
            writer.writeheader()
            for manifest, duration, observations, _ in loaded:
                for row in windows(observations[scope], duration, width):
                    writer.writerow(dict(run_id=manifest["run_id"],
                                         parent_group_id=manifest["parent_group_id"], **row))
                    count += 1
        counts[scope] = count
    contract = {
        "schema_version": 1, "artifact_role": "diagnostic_features_only",
        "python_version": sys.version.split()[0], "extractor_sha256": digest(Path(__file__)),
        "training_approved": False, "window_width_s": width,
        "feature_order": list(FEATURES), "units": dict(zip(FEATURES, UNITS)),
        "metadata_columns_excluded_from_models": list(META),
        "missing_policy": "Empty CSV cells mean unavailable; no imputation or scaling fitted",
        "window_policy": "Complete half-open windows from run elapsed zero; empty windows retained",
        "scope_policy": "Separate observation scopes; never pool them into a single comparison",
        "forwarding_ack_boundary": "Sender ACK receipt, not exact GCS arrival or persistence time",
        "source_frame_bytes_mean": "Original MAVLink frame size, not TLS or JSON byte count",
        "interarrival_policy": "Adjacent observations inside each window only",
        "grouping_policy": "All windows/derivatives of a parent group stay in one split",
        "ground_truth_policy": "No labels generated; intervention/scenario metadata excluded from features",
        "rows_per_scope": counts,
        "runs": [{"run_id": m["run_id"], "parent_group_id": m["parent_group_id"],
                  "observations_outside_complete_windows": {
                      scope: sum(t >= math.floor(duration / width) * width for t, _, _ in values)
                      for scope, values in observations.items()},
                  "input_sha256": hashes,
                  "trailing_partial_window_s": duration - math.floor(duration / width) * width}
                 for m, duration, observations, hashes in loaded],
    }
    with (output / "feature_contract.json").open("x", encoding="utf-8") as stream:
        json.dump(contract, stream, indent=2, allow_nan=False)
        stream.write("\n")
    (output / "COMPLETE").write_text("Diagnostic export complete; not training approval.\n", encoding="utf-8")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window-seconds", type=float, default=5.0)
    args = parser.parse_args()
    try:
        counts = extract(args.run, args.output, args.window_seconds)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f"Export failed: {error}\n")
    print(json.dumps({"result": "PASS", "rows_per_scope": counts,
                      "training_approved": False, "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
