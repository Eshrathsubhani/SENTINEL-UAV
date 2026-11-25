"""Inspect UAV-NIDD AP Case 2 without changing the original archive."""
import hashlib
import json
import math
import shutil
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from openpyxl import load_workbook

ARCHIVE = Path.home() / "Downloads" / "UAV-NDD CSV.zip"
MEMBER = "UAV-NDD CSV/Access Point Case2 Label.xlsx"
EXPECTED_SHA256 = (
    "edc69bea34bd8fa096a1b69d05b7f6c078e92d2fba03cee19f1999399b7de6b1"
)


def main():
    output_dir = Path("docs/evidence/phase6")
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = output_dir / f"uav_nidd_ap_quality_{stamp}.json"

    digest = hashlib.sha256()
    with ARCHIVE.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != EXPECTED_SHA256:
        raise ValueError("Archive SHA-256 differs from the verified download")

    seen = set()
    labels = Counter()
    rows = duplicates = empty_rows = 0

    with zipfile.ZipFile(ARCHIVE) as archive:
        with tempfile.TemporaryFile() as temporary:
            with archive.open(MEMBER) as source:
                shutil.copyfileobj(source, temporary)
            temporary.seek(0)
            workbook = load_workbook(
                temporary, read_only=True, data_only=False
            )
            try:
                sheet = workbook["Sheet1"]
                header = list(next(sheet.iter_rows(
                    min_row=1, max_row=1, values_only=True
                )))
                if len(header) != 51 or header[-1] != "Normal":
                    raise ValueError("Unexpected AP workbook header")
                if len(set(header)) != len(header):
                    raise ValueError("Duplicate column names")

                profiles = [
                    {
                        "column": name,
                        "missing": 0,
                        "types": Counter(),
                        "finite_numeric": 0,
                        "nonfinite_numeric": 0,
                        "numeric_text": 0,
                        "nonfinite_text": 0,
                        "excel_errors": 0,
                        "formulas": 0,
                        "min": None,
                        "max": None,
                    }
                    for name in header
                ]

                sheet.reset_dimensions()
                for cells in sheet.iter_rows(min_row=2):
                    values = [cell.value for cell in cells]
                    if all(value is None for value in values):
                        empty_rows += 1
                        continue
                    if len(values) > len(header):
                        if any(v is not None for v in values[len(header):]):
                            raise ValueError("Unexpected data beyond column 51")
                    values = values[:len(header)]
                    values += [None] * (len(header) - len(values))
                    rows += 1

                    # Typed hashes detect exact rows without retaining raw values.
                    typed = [
                        [type(v).__name__, str(v)] for v in values
                    ]
                    fingerprint = hashlib.sha256(
                        json.dumps(typed, ensure_ascii=True).encode()
                    ).digest()
                    duplicates += fingerprint in seen
                    seen.add(fingerprint)

                    label = values[-1]
                    labels["<MISSING>" if label is None else str(label)] += 1

                    for index, (profile, value) in enumerate(
                        zip(profiles, values)
                    ):
                        profile["types"][type(value).__name__] += 1
                        if index < len(cells):
                            profile["excel_errors"] += (
                                cells[index].data_type == "e"
                            )
                            profile["formulas"] += (
                                cells[index].data_type == "f"
                            )
                        if value is None or (
                            isinstance(value, str) and not value.strip()
                        ):
                            profile["missing"] += 1
                            continue
                        if type(value) in (int, float):
                            if not math.isfinite(value):
                                profile["nonfinite_numeric"] += 1
                                continue
                            profile["finite_numeric"] += 1
                            low, high = profile["min"], profile["max"]
                            profile["min"] = value if low is None else min(low, value)
                            profile["max"] = value if high is None else max(high, value)
                        elif isinstance(value, str):
                            try:
                                number = float(value.strip())
                            except ValueError:
                                pass
                            else:
                                key = (
                                    "numeric_text" if math.isfinite(number)
                                    else "nonfinite_text"
                                )
                                profile[key] += 1

                    if rows % 100000 == 0:
                        print(f"{rows:,} rows inspected", flush=True)
            finally:
                workbook.close()

    report = {
        "dataset": "UAV-NIDD",
        "archive_sha256": digest.hexdigest(),
        "member": MEMBER,
        "profiled_at_utc": datetime.now(timezone.utc).isoformat(),
        "nonempty_rows": rows,
        "fully_empty_rows": empty_rows,
        "columns": len(header),
        "exact_duplicate_rows_after_first": duplicates,
        "candidate_label_header": header[-1],
        "label_semantics_confirmed": False,
        "candidate_label_counts": dict(labels),
        "column_profiles": profiles,
        "limitations": [
            "Exact duplicates include every column, including identifiers.",
            "This does not establish independent capture or session groups.",
            "Numeric ranges are observations, not domain-validity checks.",
            "No cleaning, label mapping, splitting or training performed.",
        ],
    }
    with output.open("x", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2, allow_nan=False)
        destination.write("\n")

    print(f"\nRows: {rows:,}")
    print(f"Exact duplicates after first: {duplicates:,}")
    print("Columns with missing values:",
          sum(p["missing"] > 0 for p in profiles))
    print("Excel error cells:", sum(p["excel_errors"] for p in profiles))
    print("Formula cells:", sum(p["formulas"] for p in profiles))
    print("Report saved:", output)


if __name__ == "__main__":
    main()