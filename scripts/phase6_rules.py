"""Diagnostic heartbeat-gap rule; not attack classification."""
import argparse
from collections import Counter
import csv
from hashlib import sha256
import json
import math
from pathlib import Path


def decide(age):
    if age is None:
        return "unknown"
    if not math.isfinite(age) or age < 0:
        raise ValueError("Heartbeat age must be finite and nonnegative")
    return "gap_flagged" if age >= 5.0 else "not_flagged"


def evaluate(features, output):
    features, output = Path(features), Path(output)
    contract_path = features / "feature_contract.json"
    table_path = features / "forwarding_ack_features.csv"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    if "heartbeat_age_at_end_s" not in contract["feature_order"]:
        raise ValueError("Required heartbeat feature missing from contract")
    groups = {r["run_id"]: r["parent_group_id"] for r in contract["runs"]}

    with table_path.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError("Feature table is empty")

    predictions, seen = [], set()
    for row in rows:
        run_id = row["run_id"]
        if row["parent_group_id"] != groups[run_id]:
            raise ValueError("Parent group disagrees with contract")
        start, end = float(row["window_start_s"]), float(row["window_end_s"])
        if not all(math.isfinite(v) for v in (start, end)) or not 0 <= start < end:
            raise ValueError("Invalid window boundaries")
        key = (run_id, row["window_index"])
        if key in seen:
            raise ValueError("Duplicate run/window")
        seen.add(key)
        text = row["heartbeat_age_at_end_s"].strip()
        age = None if not text else float(text)
        predictions.append({
            "run_id": run_id,
            "parent_group_id": row["parent_group_id"],
            "window_index": row["window_index"],
            "window_start_s": start,
            "window_end_s": end,
            "heartbeat_age_at_end_s": age,
            "decision": decide(age),
        })

    counts = dict(Counter(p["decision"] for p in predictions))
    summary = {
        "artifact_role": "diagnostic_rule_predictions",
        "scope": "sender_forwarding_ack_feedback",
        "rule": "Flag known heartbeat age >= 5 seconds at window end",
        "threshold_s": 5.0,
        "threshold_basis": "Existing GCS heartbeat timeout; not tuned on pilot",
        "window_decision_counts": counts,
        "input_sha256": {
            p.name: sha256(p.read_bytes()).hexdigest()
            for p in (contract_path, table_path)
        },
        "limitations": [
            "Missing heartbeat history is unknown, not normal.",
            "Not flagged does not establish normal or attack-free operation.",
            "Flagged windows are not deduplicated incident counts.",
            "Sender ACK time is not exact GCS receipt time.",
            "No ground-truth evaluation, model training or training approval.",
        ],
    }
    output.mkdir(parents=True, exist_ok=False)
    with (output / "predictions.csv").open(
        "x", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=list(predictions[0]))
        writer.writeheader()
        writer.writerows(predictions)
    with (output / "summary.json").open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    print(json.dumps(summary, indent=2))
    print("Saved:", output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evaluate(args.features, args.output)