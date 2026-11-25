# UAV-NIDD acquisition and initial compatibility audit

Review date: 2026-11-25.
Status: Acquired and initially profiled; not approved for training or final evaluation.
Evidence consists of user-executed Windows inspections and their posted output.
The assistant did not independently load the 302 MB archive.

## Provenance and integrity

- Publisher record: https://zenodo.org/records/15125851
- Associated paper: https://doi.org/10.1109/TNSE.2025.3553442
- Publisher-described release: v1; exact local bytes are pinned below.
- Original filename: `UAV-NDD CSV.zip`.
- Original byte size: 302353406.
- SHA-256: `edc69bea34bd8fa096a1b69d05b7f6c078e92d2fba03cee19f1999399b7de6b1`.
- Local MD5: `75bce40dd1d24dce8e4622bb87fb9147`.
- That MD5 matches the checksum previously retrieved from the publisher record.
- ZIP CRC check: passed in the user-run inspection.
- Rights section: user reported **Creative Commons Attribution 4.0 International**.
- Licence reference: https://creativecommons.org/licenses/by/4.0/

The licence evidence is the user's transcription of the record's Rights section,
not a successful API export or an archived screenshot. Retain attribution to the
creators and source and document derived-data changes. The MD5 match checks
consistency with that published archive, not cryptographic publisher identity or
correctness of the archive's contents. The local SHA-256 is a provenance anchor.

Keep the original unchanged. No training-ready extraction or repaired copy has
been approved. Raw data remains outside Git; only small aggregate evidence is tracked.

## Archive members

| Member under UAV-NDD CSV/ | Uncompressed bytes | Observed format |
|---|---:|---|
| Access Point Case2 Label.xlsx | 130211371 | Excel workbook |
| GSC Case3 Label .csv | 252428371 | Excel workbook despite .csv extension |
| UAV-Case1-Label.csv | 307374586 | CSV-like prefix followed by a suspected binary/non-CSV tail |

Use format-aware readers. Never fix an extension by editing the original ZIP.
The access-point workbook uses Sheet1; the GCS workbook uses Dataset-UAV-GCS.
Inspection used openpyxl 3.1.5 in read-only/data-only mode and temporary files.
These initial inspections are not complete feature/row-quality validation.

## Case 1: UAV CSV — quarantine from training

The header has 45 fields, including Label. UTF-8 decoding failed during the scan.
A reversible Latin-1 inspection parsed 885384 nonempty records: 860652 had 45
fields and 24732 had other widths (1–5). All labels counted in the 45-field
records were ASCII, but correct width does not validate feature values.

The first malformed record was parsed record 860653, immediately after a full
DDoS-labelled record. Its preview started with 1, 66, 193181. Following previews
contained binary-looking/control characters. This supports a tail-like format
anomaly; it does not establish the original encoding or the publisher's intended
content. The integrity checks do not resolve the content anomaly.

The 24732 entries are **parser fragments, not confirmed lost observations**.
Do not report a 2.8% packet-loss/data-loss rate. Do not silently skip them or
claim that the 860652 expected-width records form a validated repaired dataset.

The provisional label profile has 17949 Normal records; its rare raw label
Reconnassiance has six records. Preserve that spelling in source evidence.
Do not train on the apparent prefix until any salvage procedure has a documented
byte boundary, semantic validation, provenance and an explicit experimental role.
A publisher-corrected release or raw-capture re-extraction is preferable to an
undocumented repair. No publisher contact or correction has been obtained.

Evidence: evidence/phase6/uav_nidd_case1_label_profile.json.
That earlier file's well_formed_records means expected field count only; read it
with the stronger limitations in this audit.

## Case 3: GCS — attack-heavy candidate

The actual workbook has 85 header cells, including Class. The scan inspected
823632 class cells, with zero blanks. Other feature cells were not fully validated.
The UID is not verified as an independent capture/run identifier.

| Raw Class value | Count |
|---|---:|
| Benign | 109 |
| Reconnaissance | 14329 |
| Bruteforce | 10161 |
| Evil Twin | 142 |
| MITM | 3312 |
| Scanning | 44552 |
| Fake Landing plus a trailing space | 298 |
| De-authentication | 1321 |
| DoS | 556285 |
| DDoS | 192826 |
| Fake Landing without trailing space | 297 |

Only about 0.0132% of inspected class cells are Benign. DoS/DDoS together account
for about 90.95%. Trimming the two Fake Landing strings would combine 595 cells,
but no normalization has been applied to the raw file.

This case is a poor sole basis for normal-only training or reliable independent
normal-validation/test partitions without further provenance and diversity.
Class balance cannot be repaired by duplicating the same few normal observations.
Keep any attack-heavy stress experiment separate and accurately labelled.

Evidence: evidence/phase6/uav_nidd_gcs_class_profile.json.

## Case 2: Access Point — preferred supplementary candidate

The sheet declares 51 columns and 631357 rows including the header. Column 51 is
headed Normal. A full scan inspected 631356 candidate-label cells, with zero
blanks. The values strongly support a categorical-label interpretation, but the
header/target semantics and capture provenance remain explicitly unconfirmed.

| Raw candidate value | Count |
|---|---:|
| Normal | 129541 |
| Scanning | 70319 |
| Reconnaissance | 40 |
| De-authentication | 155564 |
| Brute-Force | 172509 |
| DoS | 23612 |
| DDoS | 31612 |
| Fake Landing | 24584 |
| Replay | 8525 |
| Ewil Twin | 10034 |
| MITM | 5016 |

Normal comprises about 20.52% of the candidate cells. This is more useful for
further normal/attack inspection than the GCS class distribution. It does not
prove independent normal runs or establish model suitability. Reconnaissance
has only 40 entries, which may not represent 40 independent observations/runs.

Do not rename the source header or silently change Ewil Twin to Evil Twin.
A derived label mapping must retain the raw values and justify corrections.
Until confirmed, refer to column 51 as a candidate target, as the evidence JSON does.

Features include wireless/packet statistics and some protocol/content fields.
They are not the same as SENTINEL's accepted MAVLink telemetry. For example,
eapol.keydes.replay_counter is an EAPOL field, not a MAVLink signing timestamp.
Identifiers, absolute times, addresses and content fields require separate
leakage/privacy/feature-availability review before use.

Evidence: evidence/phase6/uav_nidd_ap_candidate_label_profile.json.

## Selection disposition and next gates

- Primary experiment: project-owned, independently labelled SITL runs, unchanged.
- Preferred public candidate for further exploration: UAV-NIDD Access Point case.
- GCS case: retain as a possible separate attack-heavy comparison; not the sole
  normal-training source.
- UAV case: quarantine from modelling because of the unresolved tail anomaly.
- SHADOW-GCS and UAVIDS-2025: no licence or acquisition status is changed here.

Before final public selection, confirm the candidate target's meaning, read the
full paper/capture documentation, investigate run/session provenance and define
a truthful split protocol. Feature profiling must cover numerical/categorical
values, missingness, infinities, duplicate observations and capture/label order.
Do not make a random row split and describe it as run-disjoint. Packet counters,
UIDs, timestamps and contiguous blocks are not automatically independent runs.

Source data have not been combined, cleaned, balanced, split or used for model
training. The evidence is preliminary acquisition/compatibility work supporting
6.1, not completion of 6.2–6.5. Stage 6.1 remains in progress.
