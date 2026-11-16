# Requirements and acceptance

| ID | Requirement | Acceptance evidence |
|---|---|---|
| F1 | Receive authentic SITL telemetry and support multiple registered UAVs in the final build | Independent recordings keyed by vehicle and run |
| F2 | Authenticate both gateways and protect their channel | Successful approved session and rejected unregistered peer |
| F3 | Enforce operator and geolocation policy | Allowed, outside, stale, missing, and unauthorized cases with observed simulator outcomes |
| F4 | Record integrity failures and suppress duplicate mission operations | Failure reason logged and operation count verified |
| F5 | Train Isolation Forest and Random Forest and run live detection | Saved models, held-out metrics, and traceable live alerts |
| F6 | Present telemetry, mission decisions, and incidents | Dashboard values traceable to backend events |
| N1 | Keep local development reproducible | Python version, dependency lock after verification, and run instructions |
| N2 | Measure operating overhead | Repeated latency and resource measurements with comparable workloads |
| N3 | Separate credentials and collected data from source | Ignore checks and repository review |
| N4 | Preserve reproducibility of experiments | Dataset versions, splits, configs, seed, and recorded metrics |
