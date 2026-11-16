"""SENTINEL UAV milestone 1. Run with Python 3.10+ and no dependencies.

    python sentinel_uav_policy.py
    python -m unittest -v sentinel_uav_policy

The example uses synthetic positions in a local Cartesian coordinate frame.
Simulation time and sample time are expressed in seconds on the same clock.
This file evaluates a position rule in isolation from identity and transport.
"""
from dataclasses import dataclass
from enum import Enum
from math import isfinite
import unittest


class Decision(Enum):
    ALLOW = "allow"
    MISSING_POSITION = "missing position"
    INVALID_POSITION = "invalid position or timestamp"
    FUTURE_POSITION = "position timestamp is in the future"
    STALE_POSITION = "stale position"
    OUTSIDE_AREA = "outside authorized area"


@dataclass(frozen=True)
class Position:
    east_m: float
    north_m: float
    sampled_at_s: float


def evaluate_mission_update(position: Position | None, now_s: float) -> Decision:
    """Allow updates inside the inclusive 0–100 m square with samples ≤2 s old."""
    if position is None:
        return Decision.MISSING_POSITION
    values = (position.east_m, position.north_m, position.sampled_at_s, now_s)
    try:
        values_are_finite = all(map(isfinite, values))
    except (TypeError, ValueError, OverflowError):
        return Decision.INVALID_POSITION
    if not values_are_finite:
        return Decision.INVALID_POSITION
    age_s = now_s - position.sampled_at_s
    if age_s < 0:
        return Decision.FUTURE_POSITION
    if age_s > 2:
        return Decision.STALE_POSITION
    if 0 <= position.east_m <= 100 and 0 <= position.north_m <= 100:
        return Decision.ALLOW
    return Decision.OUTSIDE_AREA


SCENARIOS = (
    ("Inside", Position(50, 50, 9), Decision.ALLOW),
    ("Boundary and age limit", Position(0, 100, 8), Decision.ALLOW),
    ("Outside", Position(101, 50, 9), Decision.OUTSIDE_AREA),
    ("Stale", Position(50, 50, 7), Decision.STALE_POSITION),
    ("Missing", None, Decision.MISSING_POSITION),
    ("Future timestamp", Position(50, 50, 11), Decision.FUTURE_POSITION),
    ("Invalid coordinate", Position(float("nan"), 50, 9), Decision.INVALID_POSITION),
    ("String coordinate", Position("50", 50, 9), Decision.INVALID_POSITION),
    ("None coordinate", Position(50, None, 9), Decision.INVALID_POSITION),
)


class MissionPolicyTest(unittest.TestCase):
    def test_scenarios(self):
        for name, position, expected in SCENARIOS:
            with self.subTest(scenario=name):
                self.assertIs(evaluate_mission_update(position, 10), expected)


if __name__ == "__main__":
    for name, position, _ in SCENARIOS:
        decision = evaluate_mission_update(position, 10)
        print(f"{name}: {decision.value}")
