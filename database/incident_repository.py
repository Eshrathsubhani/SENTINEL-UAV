"""Internal incident storage. Call within an authorized service transaction."""

import json
from uuid import uuid4
from database.security_event_repository import append_event

ATTACK_TYPES = {
    "signature_failure",
    "replay",
    "freshness",
    "tls_authentication",
    "unauthorized_access",
    "authentication",
    "telemetry_validation",
    "availability",
    "credential",
    "storage",
    "other",
}
STATUSES = {"open", "investigating", "resolved"}


class IncidentError(ValueError):
    """Bounded business-rule denial; no sensitive exception message."""


def get_incident(db, incident_id):
    row = db.execute(
        "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
    ).fetchone()
    if row is None:
        raise IncidentError("incident_not_found")
    result = dict(row)
    for table, key in (
        ("incident_notes", "note_count"),
        ("incident_event_links", "linked_event_count"),
    ):
        result[key] = db.execute(
            "SELECT COUNT(*) FROM " + table + " WHERE incident_id=?", (incident_id,)
        ).fetchone()[0]
    return result


def mutable(db, incident_id, now):
    incident = get_incident(db, incident_id)
    if incident["status"] == "resolved":
        raise IncidentError("incident_resolved")
    if now < incident["updated_at_us"]:
        raise IncidentError("incident_clock_regressed")
    return incident


def activity(db, incident_id, actor_id, now, action, details):
    row = db.execute(
        "INSERT INTO incident_history(incident_id,actor_id,occurred_at_us,action,details_json) VALUES (?,?,?,?,?)",
        (
            incident_id,
            actor_id,
            now,
            action,
            json.dumps(details, allow_nan=False, sort_keys=True, separators=(",", ":")),
        ),
    )
    db.execute(
        "UPDATE incidents SET updated_at_us=? WHERE incident_id=?", (now, incident_id)
    )
    incident = db.execute(
        "SELECT uav_id,severity FROM incidents WHERE incident_id=?", (incident_id,)
    ).fetchone()
    append_event(
        db,
        "incident_service",
        "incident",
        "incident." + action,
        actor_id=actor_id,
        uav_id=incident["uav_id"],
        target_id=incident_id,
        severity=incident["severity"],
        outcome="success",
        occurred_at_us=now,
        producer_event_id="history:" + str(row.lastrowid),
        details={"reason": action},
    )


def validate_links(db, uav_id, event_ids):
    for event_id in event_ids:
        row = db.execute(
            "SELECT uav_id FROM security_events WHERE event_id=?", (event_id,)
        ).fetchone()
        if row is None:
            raise IncidentError("security_event_not_found")
        if uav_id is not None and row["uav_id"] is not None and row["uav_id"] != uav_id:
            raise IncidentError("incident_event_uav_mismatch")


def add_links(db, incident_id, actor_id, now, event_ids):
    incident = mutable(db, incident_id, now)
    validate_links(db, incident["uav_id"], event_ids)
    for event_id in event_ids:
        previous = db.execute(
            "SELECT 1 FROM incident_event_links WHERE incident_id=? AND security_event_id=?",
            (incident_id, event_id),
        ).fetchone()
        if previous:
            continue
        db.execute(
            "INSERT INTO incident_event_links(incident_id,security_event_id,actor_id,linked_at_us) VALUES (?,?,?,?)",
            (incident_id, event_id, actor_id, now),
        )
        activity(
            db,
            incident_id,
            actor_id,
            now,
            "event_linked",
            {"security_event_id": event_id},
        )
    return get_incident(db, incident_id)


def create_incident(
    db, actor_id, now, title, description, attack_type, severity, uav_id, event_ids
):
    if (
        uav_id is not None
        and db.execute("SELECT 1 FROM uavs WHERE uav_id=?", (uav_id,)).fetchone()
        is None
    ):
        raise IncidentError("unknown_uav")
    validate_links(db, uav_id, event_ids)
    incident_id = uuid4().hex
    db.execute(
        """INSERT INTO incidents(incident_id,uav_id,title,description,attack_type,severity,status,
                  created_by,created_at_us,updated_at_us) VALUES (?,?,?,?,?,?,'open',?,?,?)""",
        (
            incident_id,
            uav_id,
            title,
            description,
            attack_type,
            severity,
            actor_id,
            now,
            now,
        ),
    )
    activity(
        db,
        incident_id,
        actor_id,
        now,
        "created",
        {"attack_type": attack_type, "severity": severity},
    )
    if event_ids:
        add_links(db, incident_id, actor_id, now, event_ids)
    return get_incident(db, incident_id)


def add_note(db, incident_id, actor_id, now, body):
    mutable(db, incident_id, now)
    note = db.execute(
        "INSERT INTO incident_notes(incident_id,actor_id,occurred_at_us,body) VALUES (?,?,?,?)",
        (incident_id, actor_id, now, body),
    )
    activity(db, incident_id, actor_id, now, "note_added", {"note_id": note.lastrowid})
    return {"incident_id": incident_id, "note_id": note.lastrowid}


def change_status(db, incident_id, actor_id, now, target, resolution):
    current = mutable(db, incident_id, now)
    if target == "investigating" and current["status"] != "open":
        raise IncidentError("invalid_incident_transition")
    db.execute(
        "UPDATE incidents SET status=?,resolution=?,resolved_at_us=? WHERE incident_id=?",
        (target, resolution, now if target == "resolved" else None, incident_id),
    )
    activity(
        db,
        incident_id,
        actor_id,
        now,
        "status_changed",
        {"from": current["status"], "to": target},
    )
    return get_incident(db, incident_id)


def classify(db, incident_id, actor_id, now, attack_type, severity):
    current = mutable(db, incident_id, now)
    if (current["attack_type"], current["severity"]) != (attack_type, severity):
        db.execute(
            "UPDATE incidents SET attack_type=?,severity=? WHERE incident_id=?",
            (attack_type, severity, incident_id),
        )
        activity(
            db,
            incident_id,
            actor_id,
            now,
            "classification_changed",
            {
                "before": {
                    "attack_type": current["attack_type"],
                    "severity": current["severity"],
                },
                "after": {"attack_type": attack_type, "severity": severity},
            },
        )
    return get_incident(db, incident_id)


def list_incidents(
    db, *, status, severity, attack_type, uav_id, start, end, limit, before
):
    sql, args = "SELECT * FROM incidents WHERE 1=1", []
    for column, value in (
        ("status", status),
        ("severity", severity),
        ("attack_type", attack_type),
        ("uav_id", uav_id),
    ):
        if value is not None:
            sql += " AND " + column + "=?"
            args.append(value)
    if start is not None:
        sql += " AND created_at_us>=?"
        args.append(start)
    if end is not None:
        sql += " AND created_at_us<?"
        args.append(end)
    if before is not None:
        sql += " AND (created_at_us,incident_id)<(?,?)"
        args.extend(before)
    rows = db.execute(
        sql + " ORDER BY created_at_us DESC,incident_id DESC LIMIT ?",
        [*args, limit + 1],
    ).fetchall()
    page = rows[:limit]
    cursor = (
        [page[-1]["created_at_us"], page[-1]["incident_id"]]
        if len(rows) > limit
        else None
    )
    return {"incidents": [dict(r) for r in page], "next_before": cursor}


def components(db, incident_id, component, limit, before):
    get_incident(db, incident_id)
    if component == "events":
        sql = """SELECT l.link_id,l.actor_id AS linked_by,l.linked_at_us,e.* FROM incident_event_links l
               JOIN security_events e ON e.event_id=l.security_event_id WHERE l.incident_id=?"""
        column = "l.link_id"
        key = "link_id"
    else:
        table, key = {
            "notes": ("incident_notes", "note_id"),
            "history": ("incident_history", "history_id"),
        }[component]
        sql = "SELECT * FROM " + table + " WHERE incident_id=?"
        column = key
    args = [incident_id]
    if before is not None:
        sql += " AND " + column + "<?"
        args.append(before)
    rows = db.execute(
        sql + " ORDER BY " + column + " DESC LIMIT ?", [*args, limit + 1]
    ).fetchall()
    page = rows[:limit]
    output = []
    for row in page:
        item = dict(row)
        if "details_json" in item:
            item["details"] = json.loads(item.pop("details_json"))
        output.append(item)
    return {
        component: output,
        "next_before": page[-1][key] if len(rows) > limit else None,
    }
