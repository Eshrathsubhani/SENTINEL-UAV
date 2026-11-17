# Phase 4 mission authorization

mission.update requires command.request permission, a valid active session,
an active UAV, and an explicit assignment. It additionally applies the existing
evaluate_mission_update policy to the stored accepted GLOBAL_POSITION_INT record.

An assigned administrator configures a geographic origin. The origin maps to
east=50 m and north=50 m in the existing inclusive 0–100 m square. A spherical
distance and bearing calculation converts latitude and longitude into local
east/north offsets. This conversion is intended for the small SITL test area.

The existing two-second freshness bound applies to both source capture and GCS
receipt timestamps. Future timestamps, invalid coordinates, missing positions,
and records whose identity mapping differs from the current UAV registry are
denied. Mission policy configuration is stored per UAV in the existing policies
table, with an incrementing version. A configuration change affects subsequent
decisions using existing sessions.

These area and age limits are development parameters inherited from Phase 1.
They require separate evaluation for operational use.

Configure the simulation origin through the Windows CLI:

    python -m security.authorization.policy_engine --database "%USERPROFILE%\.sentinel-uav\identity.sqlite3" --uav-id UAV_ID --action mission.configure --origin-latitude -35.3632622 --origin-longitude 149.1652375

Check an update with --action mission.update while signed telemetry ingestion
is running. Once telemetry is older than two seconds the decision is denied.

This milestone evaluates mission permissions and records the decisions.
Command transport and dispatch are the next integration step. Existing
command.rtl checks retain their role and assignment behavior. A separate
recovery action policy must define which conditions apply to RTL.

The full suite covers accepted updates, missing policy, missing position,
stale and future positions, outside-area positions, invalid inputs, mismatched
credentials, Viewer restrictions, removed assignments, and live policy changes.
