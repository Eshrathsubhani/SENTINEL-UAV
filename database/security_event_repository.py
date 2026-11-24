"""Internal validated security-event appends and bounded queries."""

import json
import re
from time import time_ns
from uuid import uuid4

CATEGORIES = {
    "authentication",
    "authorization",
    "identity",
    "administration",
    "communication",
    "mavlink_signing",
    "replay",
    "freshness",
    "tls",
    "credential",
    "storage",
    "mission",
    "incident",
}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
OUTCOMES = {"info", "success", "failure", "allow", "deny"}
DETAIL_KEYS = {
    "reason",
    "role",
    "kind",
    "verify_code",
    "errno",
    "system_id",
    "tls_version",
    "peer_role",
    "accepted",
    "rejected_total",
    "version",
}


def identifier(value, name, *, optional=False):
    if optional and value is None:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("Invalid " + name)
    return value


def append_event(
    db,
    producer,
    category,
    event,
    *,
    severity="info",
    outcome="info",
    actor_id=None,
    uav_id=None,
    target_id=None,
    details=None,
    producer_event_id=None,
    occurred_at_us=None,
):
    identifier(producer, "producer")
    identifier(event, "event")
    if (
        not isinstance(category, str)
        or category not in CATEGORIES
        or not isinstance(severity, str)
        or severity not in SEVERITIES
        or not isinstance(outcome, str)
        or outcome not in OUTCOMES
    ):
        raise ValueError("Invalid event classification")
    for name, value in (("actor", actor_id), ("uav", uav_id), ("target", target_id)):
        identifier(value, name, optional=True)
    details = {} if details is None else details
    if type(details) is not dict or not details.keys() <= DETAIL_KEYS:
        raise ValueError("Event details contain unsupported fields")
    for value in details.values():
        if value is None or type(value) in (bool, int):
            continue
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is None
        ):
            raise ValueError(
                "Event details must be bounded metadata, not payloads or secrets"
            )
    stamp = time_ns() // 1000 if occurred_at_us is None else occurred_at_us
    if type(stamp) is not int or not 0 <= stamp <= 253402300799999999:
        raise ValueError("Invalid event timestamp")
    source_id = (
        uuid4().hex
        if producer_event_id is None
        else identifier(producer_event_id, "producer event ID")
    )
    payload = json.dumps(
        details, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    previous = db.execute(
        "SELECT * FROM security_events WHERE producer=? AND producer_event_id=?",
        (producer, source_id),
    ).fetchone()
    values = (
        producer,
        source_id,
        stamp,
        category,
        event,
        severity,
        outcome,
        actor_id,
        uav_id,
        target_id,
        payload,
    )
    columns = (
        "producer",
        "producer_event_id",
        "occurred_at_us",
        "category",
        "event",
        "severity",
        "outcome",
        "actor_id",
        "uav_id",
        "target_id",
        "details_json",
    )
    if previous:
        # Caller retries must preserve their original event time and content.
        if tuple(previous[c] for c in columns) != values:
            raise ValueError("Conflicting producer event ID")
        return previous["event_id"]
    result = db.execute(
        "INSERT INTO security_events ("
        + ",".join(columns)
        + ") VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        values,
    )
    return result.lastrowid


def query_events(
    db,
    *,
    actor_scope=None,
    category=None,
    severity=None,
    uav_id=None,
    start=None,
    end=None,
    limit=100,
    before=None,
):
    sql = "SELECT * FROM security_events WHERE 1=1"
    parameters = []
    for column, value in (
        ("actor_id", actor_scope),
        ("category", category),
        ("severity", severity),
        ("uav_id", uav_id),
    ):
        if value is not None:
            sql += f" AND {column}=?"
            parameters.append(value)
    if start is not None:
        sql += " AND occurred_at_us>=?"
        parameters.append(start)
    if end is not None:
        sql += " AND occurred_at_us<?"
        parameters.append(end)
    if before is not None:
        sql += " AND (occurred_at_us,event_id)<(?,?)"
        parameters.extend(before)
    sql += " ORDER BY occurred_at_us DESC,event_id DESC LIMIT ?"
    parameters.append(limit + 1)
    rows = db.execute(sql, parameters).fetchall()
    page = rows[:limit]
    next_before = (
        [page[-1]["occurred_at_us"], page[-1]["event_id"]]
        if len(rows) > limit
        else None
    )
    output = []
    for row in page:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        output.append(item)
    return {"events": output, "next_before": next_before}
