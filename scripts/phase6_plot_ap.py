"""Plot observed candidate labels; no cleaning or model training."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

source = Path(
    "docs/evidence/phase6/"
    "uav_nidd_ap_quality_20261125T185825592179Z.json"
)
report = json.loads(source.read_text(encoding="utf-8"))
counts = report["candidate_label_counts"]
ordered = sorted(counts.items(), key=lambda item: item[1])

folder = Path("docs/evidence/phase6/ap_eda")
folder.mkdir(parents=True, exist_ok=True)

for scale in ("linear", "log"):
    fig, ax = plt.subplots(figsize=(11, 7))
    names, values = zip(*ordered)
    bars = ax.barh(names, values, color="#2686b5")
    ax.bar_label(bars, labels=[f"{v:,}" for v in values], padding=4)
    ax.set_xscale(scale)
    ax.set_xlabel(f"Record count ({scale} scale)")
    ax.set_title("UAV-NIDD AP Case 2: observed candidate labels")
    ax.margins(x=0.25)
    fig.text(
        0.02, 0.02,
        "Original label spellings preserved. Label semantics and "
        "capture groups remain unverified.",
        fontsize=8,
    )
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(folder / f"candidate_labels_{scale}.png", dpi=180)
    plt.close(fig)

total = sum(counts.values())
summary = [
    "# UAV-NIDD AP Case 2: preliminary EDA",
    "",
    f"Source report: `{source.name}`",
    f"Records: {total:,}",
    "",
    "| Candidate label | Records | Percentage |",
    "|---|---:|---:|",
]
for label, count in reversed(ordered):
    summary.append(f"| {label} | {count:,} | {100 * count / total:.4f}% |")

summary.extend([
    "",
    "## Interpretation and limits",
    "",
    "- Counts describe the observed candidate-label column.",
    "- Original labels, including `Ewil Twin`, are unchanged.",
    "- Only 40 records have the candidate label `Reconnaissance`.",
    "- The quality scan found 117 exact duplicate rows after the first.",
    "- Sample rows suggest header/value mismatches; mapping is unresolved.",
    "- Zero blank cells does not establish semantic validity.",
    "- No rows were removed, features corrected, splits made or models trained.",
])
output = folder / "PRELIMINARY_EDA.md"
output.write_text("\n".join(summary) + "\n", encoding="utf-8")
print("Saved two charts and:", output)