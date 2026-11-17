"""Local administrative console for Phase 4 access-control validation."""

import os
from pathlib import Path
import sqlite3

import streamlit as st

from backend.administration.access_service import AccessAdministration
from backend.commands.status_request import CommandService
from security.authentication.auth_service import AuthService, AuthenticationError
from security.authorization.policy_engine import PolicyEngine
from security.identity.uav_registry import UAVRegistry

DATABASE = Path(os.environ.get(
    "SENTINEL_IDENTITY_DB", str(Path.home() / ".sentinel-uav" / "identity.sqlite3")))


def action(operation, message):
    try:
        operation()
    except (ValueError, OSError, sqlite3.Error) as error:
        st.error(str(error))
    else:
        st.session_state["notice"] = message
        st.rerun()


def users_page(auth, admin, token):
    users = admin.list_users(token)
    st.dataframe(users, hide_index=True)
    with st.form("create_user", clear_on_submit=True):
        username = st.text_input("New username", key="new_username")
        password = st.text_input("New password", type="password", key="new_password")
        role = st.selectbox("New user role", ("Operator", "Viewer", "Administrator"))
        if st.form_submit_button("Create user"):
            action(lambda: auth.create_user(token, username, password, role), "User created.")
    names = {user["user_id"]: user["username"] for user in users}
    if names:
        with st.form("change_role"):
            user = st.selectbox("Account for role change", list(names), format_func=names.get)
            role = st.selectbox("Role", ("Operator", "Viewer", "Administrator"))
            if st.form_submit_button("Change role"):
                action(lambda: admin.set_role(token, user, role), "Role updated. Existing sessions revoked.")
        with st.form("change_status"):
            user = st.selectbox("Account for status change", list(names), format_func=names.get)
            status = st.selectbox("Account status", ("active", "suspended", "revoked"))
            if st.form_submit_button("Change account status"):
                action(lambda: auth.set_user_status(token, user, status), "Account status updated.")


def uavs_page(registry, token):
    uavs = registry.list_uavs(token)
    st.dataframe(uavs, hide_index=True)
    with st.form("register_uav", clear_on_submit=True):
        name = st.text_input("UAV name")
        system = st.number_input("MAVLink system ID", min_value=1, max_value=255, value=1)
        identity = st.text_input("Certificate URI", value="urn:sentinel:uav:1")
        key_id = st.text_input("Signing-key SHA-256 fingerprint")
        if st.form_submit_button("Register UAV"):
            action(lambda: registry.register(token, name, int(system), identity, key_id),
                   "UAV registered with pending status.")
    names = {uav["uav_id"]: uav["name"] for uav in uavs}
    if names:
        with st.form("uav_status"):
            target = st.selectbox("UAV for status change", list(names), format_func=names.get)
            status = st.selectbox("UAV status", ("active", "suspended", "revoked"))
            if st.form_submit_button("Change UAV status"):
                action(lambda: registry.set_status(token, target, status), "UAV status updated.")


def assignments_page(admin, registry, token):
    st.dataframe(admin.list_assignments(token), hide_index=True)
    users = {u["user_id"]: u["username"] for u in admin.list_users(token)}
    uavs = {u["uav_id"]: u["name"] for u in registry.list_uavs(token)}
    if users and uavs:
        with st.form("assignments"):
            user = st.selectbox("User", list(users), format_func=users.get)
            uav = st.selectbox("UAV", list(uavs), format_func=uavs.get)
            operation = st.selectbox("Assignment operation", ("Assign", "Unassign"))
            if st.form_submit_button("Apply assignment"):
                method = registry.assign if operation == "Assign" else registry.unassign
                action(lambda: method(token, user, uav), "Assignment updated.")


def telemetry_page(admin, policy, commands, token, profile):
    uavs = {row["uav_id"]: row["name"] for row in admin.assigned_uavs(token)}
    if not uavs:
        st.info("You have no active UAV assignments.")
        return
    target = st.selectbox("Assigned UAV", list(uavs), format_func=uavs.get)
    st.button("Refresh telemetry")
    st.json(policy.read_telemetry(token, target))
    if profile["role_name"] in ("Administrator", "Operator"):
        if st.button("Check mission update permission"):
            decision = policy.authorize(token, target, "mission.update")
            st.write(("ALLOW " if decision.allowed else "DENY ") + decision.reason)
        if st.button("Request simulator status"):
            try:
                request = commands.request_status(token, target)
            except (ValueError, OSError, sqlite3.Error) as error:
                st.error(str(error))
            else:
                st.session_state["status_request"] = request
        if st.session_state.get("status_request"):
            st.write(commands.result(token, st.session_state["status_request"]))


def main():
    st.set_page_config(page_title="SENTINEL UAV access", layout="wide")
    st.title("SENTINEL UAV — Access control")
    auth = AuthService(DATABASE)
    admin = AccessAdministration(DATABASE)
    registry = UAVRegistry(DATABASE)
    policy = PolicyEngine(DATABASE)
    token = st.session_state.get("token")
    if token:
        try:
            profile = auth.authenticate(token)
        except AuthenticationError:
            st.session_state.clear()
            st.rerun()
    else:
        with st.form("login", clear_on_submit=True):
            username = st.text_input("Username", key="username")
            password = st.text_input("Password", type="password", key="password")
            submitted = st.form_submit_button("Sign in")
        if submitted:
            try:
                st.session_state["token"] = auth.login(username, password)
            except (ValueError, OSError, sqlite3.Error) as error:
                st.error(str(error))
            else:
                st.rerun()
        st.stop()
    st.sidebar.write(profile["username"], profile["role_name"])
    if st.sidebar.button("Sign out"):
        auth.logout(token)
        st.session_state.clear()
        st.rerun()
    notice = st.session_state.pop("notice", None)
    if notice:
        st.success(notice)
    pages = ["Telemetry"]
    if profile["role_name"] == "Administrator":
        pages += ["Users", "UAVs", "Assignments", "Audit"]
    elif profile["role_name"] == "Operator":
        pages += ["Audit"]
    page = st.sidebar.radio("Section", pages)
    if page == "Users":
        users_page(auth, admin, token)
    elif page == "UAVs":
        uavs_page(registry, token)
    elif page == "Assignments":
        assignments_page(admin, registry, token)
    elif page == "Audit":
        events = admin.audit_events(token)
        st.subheader("Identity events")
        st.dataframe(events["identity_events"], hide_index=True)
        st.subheader("Authorization decisions")
        st.dataframe(events["authorization_events"], hide_index=True)
    else:
        telemetry_page(admin, policy, CommandService(DATABASE), token, profile)


try:
    main()
except AuthenticationError:
    st.session_state.clear()
    st.rerun()
except (ValueError, OSError, sqlite3.Error) as error:
    st.error(str(error))
