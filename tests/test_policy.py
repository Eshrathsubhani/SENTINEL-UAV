"""Expose the existing policy test suite to pytest discovery."""
from security.sentinel_uav_policy import MissionPolicyTest

__all__ = ["MissionPolicyTest"]
