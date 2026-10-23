
from app.threat_feed_manager import (
    load_feed as load_managed_feed,
    add_indicator,
    remove_indicator,
)
from app.pipeline import run_pipeline
from app.incident_store import (
    sync_incidents,
    get_all_incidents,
    update_incident_status,
    update_analyst_notes,
)
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SENTRY | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SENTRY — Security Operations Dashboard")
st.caption("Security Event Detection & Threat Investigation Platform")


# --------------------------------------------------
# LOAD PIPELINE AND STORED INCIDENTS
# --------------------------------------------------

try:
    results = run_pipeline()

    events = results.get("events", [])
    alerts = results.get("alerts", [])
    correlations = results.get("correlations", [])
    detected_incidents = results.get("incidents", [])

    sync_incidents(detected_incidents)
    stored_incidents = get_all_incidents()

except Exception as exc:
    st.error("SENTRY could not load its pipeline or incident database.")
    st.exception(exc)
    st.stop()


# --------------------------------------------------
# NORMALIZE INCIDENT RECORDS
# --------------------------------------------------

def normalize_incident(record):
    """Normalize incident records for dashboard display."""

    incident = dict(record)

    incident_type = (
        incident.get("type")
        or incident.get("incident_type")
        or "unknown"
    )

    incident["type"] = incident_type
    incident["incident_type"] = incident_type
    incident["incident_id"] = incident.get(
        "incident_id", "Unknown"
    )
    incident["source_ip"] = incident.get("source_ip") or "Unknown"
    incident["username"] = incident.get("username") or "Unknown"

    try:
        incident["risk_score"] = int(
            incident.get("risk_score") or 0
        )
    except (TypeError, ValueError):
        incident["risk_score"] = 0

    incident["risk_level"] = str(
        incident.get("risk_level") or "low"
    ).lower()

    incident["status"] = str(
        incident.get("status") or "open"
    ).lower()

    incident["analyst_notes"] = (
        incident.get("analyst_notes") or ""
    )

    incident["related_events"] = int(
        incident.get("related_events") or 0
    )

    incident["timeline"] = incident.get("timeline") or []
    incident["evidence"] = incident.get("evidence") or {}

    return incident


def get_threat_findings(incident):
    """Return threat-intelligence evidence as a list."""

    evidence = incident.get("evidence") or {}
    findings = evidence.get("threat_intelligence") or []

    if isinstance(findings, dict):
        findings = [findings]

    return [
        item for item in findings
        if isinstance(item, dict)
    ]


def get_intel_status(finding):
    return str(
        finding.get("status") or "not_available"
    ).lower()


incidents = [
    normalize_incident(item)
    for item in stored_incidents
]


# --------------------------------------------------
# SECURITY OVERVIEW
# --------------------------------------------------

critical_count = sum(
    item["risk_level"] == "critical"
    for item in incidents
)

high_count = sum(
    item["risk_level"] == "high"
    for item in incidents
)

open_count = sum(
    item["status"] == "open"
    for item in incidents
)

investigating_count = sum(
    item["status"] == "investigating"
    for item in incidents
)

resolved_count = sum(
    item["status"] == "resolved"
    for item in incidents
)

alert_intel = [
    item.get("threat_intel", {})
    for item in alerts
    if isinstance(item.get("threat_intel"), dict)
]

known_matches = sum(
    get_intel_status(item) == "known_malicious"
    for item in alert_intel
)

unmatched_ips = sum(
    get_intel_status(item) == "not_found"
    for item in alert_intel
)

invalid_ips = sum(
    get_intel_status(item) == "invalid_ip"
    for item in alert_intel
)

st.subheader("Security Overview")

metric_cols = st.columns(5)

metric_cols[0].metric("Events Processed", len(events))
metric_cols[1].metric("Alerts Generated", len(alerts))
metric_cols[2].metric("Open Incidents", open_count)
metric_cols[3].metric("Investigating", investigating_count)
metric_cols[4].metric("Resolved", resolved_count)

threat_cols = st.columns(4)

threat_cols[0].metric("Known Feed Matches", known_matches)
threat_cols[1].metric("Unmatched IPs", unmatched_ips)
threat_cols[2].metric("Invalid IP Values", invalid_ips)
threat_cols[3].metric("Threat Intel Checks", len(alert_intel))

st.caption(
    "Threat intelligence uses the local offline feed. "
    "An unmatched IP is unknown; it is not proof that the IP is safe."
)

st.divider()


# --------------------------------------------------
# INCIDENT MANAGEMENT
# --------------------------------------------------

st.header("🚨 Incident Management")

risk_options = ["critical", "high", "medium", "low"]

type_options = sorted({
    item["type"]
    for item in incidents
})

status_options = ["open", "investigating", "resolved"]

filter_cols = st.columns(3)

with filter_cols[0]:
    selected_risks = st.multiselect(
        "Filter by risk level",
        options=risk_options,
        default=risk_options,
        format_func=lambda value: value.upper(),
    )

with filter_cols[1]:
    selected_types = st.multiselect(
        "Filter by incident type",
        options=type_options,
        default=type_options,
        format_func=lambda value: value.replace(
            "_", " "
        ).title(),
    )

with filter_cols[2]:
    selected_statuses = st.multiselect(
        "Filter by status",
        options=status_options,
        default=status_options,
        format_func=lambda value: value.title(),
    )

filtered_incidents = [
    item
    for item in incidents
    if item["risk_level"] in selected_risks
    and item["type"] in selected_types
    and item["status"] in selected_statuses
]

if not filtered_incidents:
    st.info("No incidents match the selected filters.")

else:
    incident_rows = []

    for incident in filtered_incidents:
        findings = get_threat_findings(incident)

        intel_statuses = sorted({
            get_intel_status(item)
            for item in findings
        })

        incident_rows.append({
            "Incident ID": incident["incident_id"],
            "Type": incident["type"].replace(
                "_", " "
            ).title(),
            "Source IP": incident["source_ip"],
            "Username": incident["username"],
            "Risk Score": incident["risk_score"],
            "Risk Level": incident["risk_level"].upper(),
            "Status": incident["status"].title(),
            "Related Events": incident["related_events"],
            "Threat Intel": (
                ", ".join(intel_statuses)
                if intel_statuses
                else "not available"
            ),
        })

    st.dataframe(
        pd.DataFrame(incident_rows),
        width="stretch",
        hide_index=True,
    )

    incident_lookup = {
        (
            f'{item["incident_id"]} — '
            f'{item["type"].replace("_", " ").title()} '
            f'({item["source_ip"]})'
        ): item
        for item in filtered_incidents
    }

    selected_label = st.selectbox(
        "Select an incident to investigate",
        options=list(incident_lookup.keys()),
    )

    selected_incident = incident_lookup[selected_label]
    incident_id = selected_incident["incident_id"]

    # --------------------------------------------------
    # INCIDENT INVESTIGATION
    # --------------------------------------------------

    st.subheader("🔎 Incident Investigation")

    detail_cols = st.columns(4)

    detail_cols[0].metric(
        "Risk Score",
        selected_incident["risk_score"],
    )

    detail_cols[1].metric(
        "Risk Level",
        selected_incident["risk_level"].upper(),
    )

    detail_cols[2].metric(
        "Related Events",
        selected_incident["related_events"],
    )

    detail_cols[3].metric(
        "Current Status",
        selected_incident["status"].title(),
    )

    info_cols = st.columns(2)

    with info_cols[0]:
        st.write(f'**Incident ID:** {incident_id}')
        st.write(
            f'**Incident Type:** {selected_incident["type"]}'
        )

    with info_cols[1]:
        st.write(
            f'**Source IP:** {selected_incident["source_ip"]}'
        )
        st.write(
            f'**Username:** {selected_incident["username"]}'
        )

    # --------------------------------------------------
    # INCIDENT THREAT INTELLIGENCE
    # --------------------------------------------------

    st.markdown("### 🧠 Threat Intelligence")

    incident_findings = get_threat_findings(
        selected_incident
    )

    if incident_findings:
        for index, finding in enumerate(
            incident_findings,
            start=1,
        ):
            finding_status = get_intel_status(finding)

            status_label = {
                "known_malicious": "Known feed match",
                "not_found": "Not found in local feed",
                "invalid_ip": "Invalid IP",
                "not_available": "Not available",
            }.get(
                finding_status,
                finding_status.replace("_", " ").title(),
            )

            with st.expander(
                f"Finding {index}: {status_label}",
                expanded=True,
            ):
                st.write(
                    f'**IP:** {finding.get("ip") or "Not available"}'
                )
                st.write(
                    f'**Source:** {finding.get("source") or "Unknown"}'
                )
                st.write(
                    f'**Category:** {finding.get("category") or "None"}'
                )
                st.write(
                    f'**Description:** '
                    f'{finding.get("description") or "No description"}'
                )

        if any(
            get_intel_status(item) == "not_found"
            for item in incident_findings
        ):
            st.warning(
                "An IP absent from the local feed is unknown, "
                "not automatically safe."
            )

    else:
        st.info(
            "No threat-intelligence findings are stored for this incident."
        )

    # --------------------------------------------------
    # INCIDENT EVIDENCE
    # --------------------------------------------------

    with st.expander(
        "Evidence and Correlation Details",
        expanded=True,
    ):
        if selected_incident.get("evidence"):
            st.json(selected_incident["evidence"])
        else:
            st.info(
                "No stored evidence details for this incident."
            )

    # --------------------------------------------------
    # INCIDENT TIMELINE
    # --------------------------------------------------

    with st.expander("Incident Timeline", expanded=True):
        timeline = selected_incident.get("timeline", [])

        if timeline:
            for timestamp in timeline:
                st.write(f"• {timestamp}")
        else:
            st.info(
                "No timeline is available for this incident."
            )

    # --------------------------------------------------
    # INCIDENT STATUS AND ANALYST NOTES
    # --------------------------------------------------

    st.markdown("### 📝 Incident Response")

    with st.form(key=f"incident_update_{incident_id}"):

        current_status = selected_incident["status"]

        new_status = st.selectbox(
            "Update incident status",
            options=status_options,
            index=(
                status_options.index(current_status)
                if current_status in status_options
                else 0
            ),
            format_func=lambda value: value.title(),
        )

        new_notes = st.text_area(
            "Analyst notes",
            value=selected_incident["analyst_notes"],
            height=130,
            placeholder=(
                "Record investigation steps, findings, "
                "and next actions..."
            ),
        )

        submitted = st.form_submit_button(
            "Save Incident Updates"
        )

        if submitted:
            try:
                update_incident_status(
                    incident_id,
                    new_status,
                )

                update_analyst_notes(
                    incident_id,
                    new_notes,
                )

                st.success(
                    "Incident status and analyst notes saved."
                )
                st.rerun()

            except Exception as exc:
                st.error(
                    "Could not save the incident updates."
                )
                st.exception(exc)

st.divider()


# --------------------------------------------------
# SECURITY ALERTS
# --------------------------------------------------

st.header("🛡️ Security Alerts")

if alerts:
    alert_rows = []

    for item in alerts:
        event = item.get("event", {})
        detection = item.get("detection", {})
        risk = item.get("risk", {})
        intel = item.get("threat_intel") or {}

        status = (
            get_intel_status(intel)
            if intel
            else "not_available"
        )

        alert_rows.append({
            "Timestamp": event.get(
                "timestamp", "Unknown"
            ),
            "Rule ID": detection.get(
                "rule_id", "Unknown"
            ),
            "Alert": (
                detection.get("reason")
                or detection.get("alert")
                or "Detection matched"
            ),
            "Severity": str(
                detection.get("severity", "unknown")
            ).upper(),
            "Risk Score": risk.get("risk_score", 0),
            "Risk Level": str(
                risk.get("risk_level", "low")
            ).upper(),
            "Username": event.get("username") or "—",
            "Source IP": event.get("source_ip") or "—",
            "Threat Intel Status": status.replace(
                "_", " "
            ).upper(),
            "Threat Category": intel.get("category") or "—",
        })

    st.dataframe(
        pd.DataFrame(alert_rows),
        width="stretch",
        hide_index=True,
    )

    with st.expander("Alert Threat-Intelligence Details"):
        for index, item in enumerate(alerts, start=1):
            event = item.get("event", {})
            intel = item.get("threat_intel") or {}

            status = (
                get_intel_status(intel)
                if intel
                else "not_available"
            )

            st.markdown(
                f'**{index}. {event.get("timestamp", "Unknown")} — '
                f'{event.get("source_ip") or "Unknown IP"} — '
                f'{status.replace("_", " ").title()}**'
            )

            st.json(intel or {"status": "not_available"})

            if index < len(alerts):
                st.divider()

else:
    st.info(
        "No security alerts were generated by the current pipeline run."
    )

st.divider()


# --------------------------------------------------
# EVENT CORRELATIONS
# --------------------------------------------------

st.header("🔗 Event Correlations")

if correlations:
    correlation_rows = [
        {
            "Correlation ID": item.get(
                "correlation_id", "Unknown"
            ),
            "Type": str(
                item.get("type", "unknown")
            ).replace("_", " ").title(),
            "Source IP": item.get(
                "source_ip", "Unknown"
            ),
            "Username": item.get("username") or "—",
            "Event Count": item.get("event_count", 0),
            "Time Window (seconds)": item.get(
                "time_window_seconds", 0
            ),
            "Reason": item.get("reason", ""),
        }
        for item in correlations
    ]

    st.dataframe(
        pd.DataFrame(correlation_rows),
        width="stretch",
        hide_index=True,
    )

else:
    st.info("No event correlations were found.")

st.divider()


# --------------------------------------------------
# PROCESSED SECURITY EVENTS
# --------------------------------------------------

st.header("📋 Processed Security Events")

if events:
    st.dataframe(
        pd.DataFrame(events),
        width="stretch",
        hide_index=True,
    )

else:
    st.info("No security events were processed.")

st.divider()


# --------------------------------------------------
# THREAT INTELLIGENCE FEED MANAGEMENT
# --------------------------------------------------

st.header("🧠 Threat Intelligence Feed Management")

st.caption(
    "Manage indicators in the local offline feed at "
    "data/threat_feed.json. No external service is contacted."
)

flash_message = st.session_state.pop(
    "feed_management_flash",
    None,
)

if flash_message:
    st.success(flash_message)

try:
    managed_feed = load_managed_feed()

except Exception as exc:
    managed_feed = None

    st.error(
        "The local threat feed could not be loaded. "
        "No changes were made."
    )
    st.exception(exc)

if managed_feed is not None:

    st.metric(
        "Indicators in Local Feed",
        len(managed_feed),
    )

    if managed_feed:
        feed_rows = [
            {
                "IP Address": address,
                "Category": details.get(
                    "category", "unspecified"
                ),
                "Description": details.get(
                    "description", ""
                ),
            }
            for address, details in sorted(
                managed_feed.items()
            )
        ]

        st.dataframe(
            pd.DataFrame(feed_rows),
            width="stretch",
            hide_index=True,
        )

    else:
        st.info(
            "The local threat feed is empty. "
            "Add an indicator below."
        )

    add_tab, remove_tab = st.tabs([
        "Add / Update Indicator",
        "Remove Indicator",
    ])

    # --------------------------------------------------
    # ADD OR UPDATE INDICATOR
    # --------------------------------------------------

    with add_tab:

        with st.form(
            "sentry_add_threat_indicator",
            clear_on_submit=True,
        ):
            new_ip = st.text_input(
                "IPv4 or IPv6 address",
                placeholder="For example: 203.0.113.60",
            )

            new_category = st.text_input(
                "Threat category",
                placeholder="For example: phishing, scanner, malware",
            )

            new_description = st.text_area(
                "Analyst description",
                placeholder=(
                    "Explain why this indicator is "
                    "included in the feed."
                ),
            )

            replace_existing = st.checkbox(
                "Replace details if this IP already exists",
                value=False,
            )

            add_submitted = st.form_submit_button(
                "Save Indicator"
            )

        if add_submitted:
            try:
                saved_ip = add_indicator(
                    new_ip,
                    new_category,
                    new_description,
                    overwrite=replace_existing,
                )

                st.session_state[
                    "feed_management_flash"
                ] = (
                    f"Saved indicator {saved_ip} "
                    "to the local feed."
                )

                st.rerun()

            except ValueError as exc:
                st.error(str(exc))

            except Exception as exc:
                st.error("Could not save the indicator.")
                st.exception(exc)

    # --------------------------------------------------
    # REMOVE INDICATOR
    # --------------------------------------------------

    with remove_tab:

        if not managed_feed:
            st.info("There are no indicators to remove.")

        else:
            with st.form(
                "sentry_remove_threat_indicator"
            ):
                selected_ip = st.selectbox(
                    "Select an indicator to remove",
                    options=sorted(managed_feed),
                    format_func=lambda address: (
                        f"{address} — "
                        f"{managed_feed[address].get('category', 'unspecified')}"
                    ),
                )

                confirm_remove = st.checkbox(
                    "I confirm that I want to remove this indicator",
                    value=False,
                )

                remove_submitted = st.form_submit_button(
                    "Remove Selected Indicator"
                )

            if remove_submitted:

                if not confirm_remove:
                    st.error(
                        "Confirm removal before deleting an indicator."
                    )

                else:
                    try:
                        removed_ip = remove_indicator(
                            selected_ip
                        )

                        st.session_state[
                            "feed_management_flash"
                        ] = (
                            f"Removed indicator {removed_ip} "
                            "from the local feed."
                        )

                        st.rerun()

                    except ValueError as exc:
                        st.error(str(exc))

                    except Exception as exc:
                        st.error("Could not remove the indicator.")
                        st.exception(exc)


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:
    st.header("🛡️ SENTRY")

    st.write(
        "Security Event Detection & Threat Investigation Platform"
    )

    st.metric(
        "Stored Incidents",
        len(incidents),
    )

    st.metric(
        "High-Risk Incidents",
        high_count + critical_count,
    )

    st.metric(
        "Investigating",
        investigating_count,
    )

    st.metric(
        "Known Threat Feed Matches",
        known_matches,
    )

    st.caption(
        "Prototype dashboard using local sample logs, "
        "a local threat feed, and SQLite persistence."
    )
