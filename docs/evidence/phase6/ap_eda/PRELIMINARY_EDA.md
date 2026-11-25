# UAV-NIDD AP Case 2: preliminary EDA

Source report: `uav_nidd_ap_quality_20261125T185825592179Z.json`
Records: 631,356

| Candidate label | Records | Percentage |
|---|---:|---:|
| Brute-Force | 172,509 | 27.3236% |
| De-authentication | 155,564 | 24.6397% |
| Normal | 129,541 | 20.5179% |
| Scanning | 70,319 | 11.1378% |
| DDoS | 31,612 | 5.0070% |
| Fake Landing | 24,584 | 3.8938% |
| DoS | 23,612 | 3.7399% |
| Ewil Twin | 10,034 | 1.5893% |
| Replay | 8,525 | 1.3503% |
| MITM | 5,016 | 0.7945% |
| Reconnaissance | 40 | 0.0063% |

## Interpretation and limits

- Counts describe the observed candidate-label column.
- Original labels, including `Ewil Twin`, are unchanged.
- Only 40 records have the candidate label `Reconnaissance`.
- The quality scan found 117 exact duplicate rows after the first.
- Sample rows suggest header/value mismatches; mapping is unresolved.
- Zero blank cells does not establish semantic validity.
- No rows were removed, features corrected, splits made or models trained.
