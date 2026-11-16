# Database design

Start with recordings grouped by run. Introduce SQLite when the application
needs durable operator state and queries across runs.

| Entity | Key fields |
|---|---|
| Vehicles | vehicle ID, gateway identity, registration status |
| Operators and assignments | operator ID, role, permitted vehicle and mission |
| Missions | mission ID, vehicle ID, geographic policy reference |
| Runs and telemetry | run ID, vehicle ID, timestamps, message metadata |
| Decisions | request ID, mission ID, policy version, verdict, reason, observed outcome |
| Events and incidents | event ID, related request or run, evidence reference, status |

Use request and run IDs to correlate records. Keep credentials outside the
database. Review the write volume before deciding on a PostgreSQL migration.
