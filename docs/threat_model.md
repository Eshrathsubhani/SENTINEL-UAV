# Threat model

Assets are gateway credentials, operator identity, mission requests,
telemetry, and audit evidence. Assume an untrusted network between gateways.
The prototype trusts the simulator, its position source, and gateway hosts.
Physical access, endpoint compromise, and falsified position sources are
outside the first experiment.

| Threat | Defensive control | Evidence |
|---|---|---|
| Unknown gateway | Certificate validation and device registration | Session denied, reason logged |
| Network disclosure or modification | Authenticated transport between gateways | Only authenticated channel delivers application messages |
| Unauthorized mission request | Operator permission and gateway-side policy | Denial logged and simulator mission state unchanged |
| Duplicate request | Scoped request identifier and deduplication | One applied operation for duplicate submissions |
| Stale or missing position | Freshness and availability checks | Policy denies the update |
| Link loss | Operator alert and independent flight-controller behavior | Loss recorded and behavior verified in SITL |
| Audit alteration | Hash-chain verification with a separately retained checkpoint | Modified record fails verification |

The IDS raises alerts. Mission authorization follows deterministic policy.
