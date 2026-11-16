# Master specification

SENTINEL UAV will evaluate protected UAV–ground station communication in
ArduPilot SITL. The architecture uses Python services and workers, with
Streamlit for visibility and operator requests. The primary scenario is a
simulated mission update authorized by operator permission and fresh UAV
position within the mission area. The UAV gateway evaluates this deterministic policy. Mutual
TLS protects the gateway channel. The ML detector analyzes communication
behavior and raises alerts separately from the authorization decision. The
100 m square and two-second freshness limit are prototype settings. Neither
threshold has been validated for real flight operations.

| Component | Expected output |
|---|---|
| SITL adapter | Timestamped telemetry and simulator acknowledgments |
| Ground gateway | Authenticated operator context and protected requests |
| UAV gateway | Verified peer, final allow or deny decision, forwarded allowed request |
| Storage and audit | Correlated telemetry, decisions, outcomes, and incident records |
| Hybrid IDS | Rules, Isolation Forest, Random Forest, evidence and alerts |
| Streamlit | Fleet status, telemetry, mission decisions, and experiment results |

The first integration spans one simulated UAV. The complete project target
includes multiple simulated UAVs, registered gateway identities, an incident
workflow, and reproducible security, ML, and performance evaluations.

- [Architecture](architecture.md)
- [Protocol](protocol_design.md)
- [Threat model](threat_model.md)
- [Acceptance requirements](requirements.md)
- [Storage](database_design.md)
- [Datasets](dataset_documentation.md)
- [Research methodology](research_methodology.md)
