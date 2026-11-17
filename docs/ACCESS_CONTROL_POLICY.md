# Phase 4 access-control policy

| Operation | Administrator | Operator | Viewer |
|---|---|---|---|
| Read assigned active UAV telemetry | Allow | Allow | Allow |
| Check assigned active UAV status | Allow | Allow | Allow |
| Request simulated SYS_STATUS | Allow | Allow | Deny |
| Request designated mission update | Apply mission policy | Apply mission policy | Deny |
| Manage users and roles | Allow | Deny | Deny |
| Register UAVs and change UAV status | Allow | Deny | Deny |
| Manage assignments | Allow | Deny | Deny |
| Configure assigned UAV mission origin | Allow | Deny | Deny |
| Read audit events | All | Own actor ID | Deny |

Every protected UAV request requires a valid unexpired session, an active user,
the action's role permission, an active registered UAV, and a current assignment.
Unsupported actions are denied. Resource discovery returns assigned active UAVs.

Mission updates additionally require a configured origin and an identity-bound
accepted position within the inherited area and freshness bounds. The operator
cannot supply a replacement position directly in the request.

The status dispatcher supports MAV_CMD_REQUEST_MESSAGE for SYS_STATUS only.
It rechecks the current session, role, assignment, UAV status, expiration, and
gateway credential mapping after queuing and before sending. A policy decision
check for command.rtl alone does not provide an RTL sender.

Administrator management operations validate current administrator identity
inside their mutation transaction. Denied operations are recorded. Role changes
invalidate existing sessions. Policy changes affect subsequent decisions.

UI visibility follows role permissions. Backend service checks enforce access
for direct calls as well. Audit services expose read operations and apply role
and actor scoping before returning records.
