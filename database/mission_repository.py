"""Mission persistence helpers; callers must authorize and own the transaction."""

import json
from uuid import uuid4

from database.security_event_repository import append_event
from database.telemetry_repository import MAX_US

STATUSES = {"planned", "active", "completed", "aborted", "cancelled"}
TRANSITIONS = {
    "start": ("planned", "active", "started"),
    "complete": ("active", "completed", "completed"),
    "abort": ("active", "aborted", "aborted"),
    "cancel": ("planned", "cancelled", "cancelled"),
}


class MissionError(ValueError):
    """A bounded business-rule rejection that can be committed to the audit log."""


def clock_us(value):
    if type(value) is not int or not 0 <= value <= MAX_US:
        raise MissionError("invalid_mission_clock")
    return value


def describe(row):
    result = dict(row)
    result["details"] = json.loads(result.pop("details_json"))
    return result


def get_mission(db, uav_id, mission_id):
    row = db.execute(
        "SELECT * FROM missions WHERE uav_id=? AND mission_id=?", (uav_id, mission_id)
    ).fetchone()
    if row is None:
        raise MissionError("mission_not_found")
    result = describe(row)
    result["history"] = [
        dict(r)
        for r in db.execute(
            "SELECT event_id,actor_id,occurred_at_us,event FROM mission_events WHERE mission_id=? ORDER BY event_id",
            (mission_id,),
        )
    ]
    result["telemetry_count"] = db.execute(
        "SELECT COUNT(*) FROM mission_telemetry WHERE mission_id=?", (mission_id,)
    ).fetchone()[0]
    return result


def record_event(db, actor_id, uav_id, mission_id, now_us, event):
    cursor = db.execute(
        "INSERT INTO mission_events(mission_id,actor_id,occurred_at_us,event) VALUES (?,?,?,?)",
        (mission_id, actor_id, now_us, event),
    )
    append_event(
        db,
        "mission_service",
        "mission",
        "mission." + event,
        outcome="success",
        actor_id=actor_id,
        uav_id=uav_id,
        target_id=mission_id,
        occurred_at_us=now_us,
        producer_event_id="mission-event:" + str(cursor.lastrowid),
    )


def create_mission(db, actor_id, uav_id, name, description, details_json, now_us):
    clock_us(now_us)
    mission_id = uuid4().hex
    db.execute(
        """INSERT INTO missions(mission_id,uav_id,name,description,details_json,status,created_at_us,created_by)
                  VALUES (?,?,?,?,?,'planned',?,?)""",
        (mission_id, uav_id, name, description, details_json, now_us, actor_id),
    )
    record_event(db, actor_id, uav_id, mission_id, now_us, "created")
    return get_mission(db, uav_id, mission_id)


def transition_mission(db, actor_id, uav_id, mission_id, operation, now_us):
    clock_us(now_us)
    current = get_mission(db, uav_id, mission_id)
    previous, target, event = TRANSITIONS[operation]
    if current["status"] != previous:
        raise MissionError("invalid_mission_transition")
    if now_us < (
        current["started_at_us"]
        if current["started_at_us"] is not None
        else current["created_at_us"]
    ):
        raise MissionError("mission_clock_regressed")
    if operation == "start":
        if db.execute(
            "SELECT 1 FROM missions WHERE uav_id=? AND status='active'", (uav_id,)
        ).fetchone():
            raise MissionError("mission_already_active")
        db.execute(
            "UPDATE missions SET status='active',started_at_us=? WHERE mission_id=?",
            (now_us, mission_id),
        )
    else:
        latest = db.execute(
            "SELECT MAX(linked_at_us) FROM mission_telemetry WHERE mission_id=?",
            (mission_id,),
        ).fetchone()[0]
        if latest is not None and now_us < latest:
            raise MissionError("mission_clock_regressed")
        db.execute(
            "UPDATE missions SET status=?,ended_at_us=? WHERE mission_id=?",
            (target, now_us, mission_id),
        )
    record_event(db, actor_id, uav_id, mission_id, now_us, event)
    return get_mission(db, uav_id, mission_id)


def list_missions(db, uav_id, *, status, start, end, limit, before):
    sql = "SELECT * FROM missions WHERE uav_id=?"
    parameters = [uav_id]
    if status is not None:
        sql += " AND status=?"
        parameters.append(status)
    if start is not None:
        sql += " AND created_at_us>=?"
        parameters.append(start)
    if end is not None:
        sql += " AND created_at_us<?"
        parameters.append(end)
    if before is not None:
        sql += " AND (created_at_us,mission_id)<(?,?)"
        parameters.extend(before)
    sql += " ORDER BY created_at_us DESC,mission_id DESC LIMIT ?"
    parameters.append(limit + 1)
    rows = db.execute(sql, parameters).fetchall()
    page = rows[:limit]
    next_before = (
        [page[-1]["created_at_us"], page[-1]["mission_id"]]
        if len(rows) > limit
        else None
    )
    return {"missions": [describe(r) for r in page], "next_before": next_before}
