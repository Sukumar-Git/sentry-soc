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


# ---------------------------------------------------------------------
# PAGE CONFIGURATION + LIGHT THEME
# ---------------------------------------------------------------------

st.set_page_config(
    page_title="SENTRY | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

LIGHT_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');

:root {
  --sn-ink: #18233c;
  --sn-muted: #687791;
  --sn-violet: #6656d9;
  --sn-violet-dark: #5143c3;
  --sn-cyan: #0891b2;
  --sn-green: #168568;
  --sn-amber: #b7791f;
  --sn-red: #c24154;
  --sn-border: #e3e8f1;
  --sn-panel: #ffffff;
  --sn-canvas: #f4f6fb;
}

html, body, [data-testid="stAppViewContainer"] {
  color: var(--sn-ink) !important;
  background: var(--sn-canvas) !important;
  font-family: 'DM Sans', sans-serif !important;
}

[data-testid="stAppViewContainer"] {
  background:
    radial-gradient(ellipse at 4% 0%, rgba(117, 102, 224, .09), transparent 29%),
    radial-gradient(ellipse at 100% 12%, rgba(8, 145, 178, .06), transparent 25%),
    var(--sn-canvas) !important;
}

[data-testid="stHeader"] {
  background: rgba(244, 246, 251, .86) !important;
  backdrop-filter: blur(14px);
  border-bottom: 1px solid rgba(223, 229, 240, .8);
}

.block-container {
  max-width: 1580px;
  padding-top: 1.55rem;
  padding-bottom: 3rem;
}

h1, h2, h3, h4 {
  color: var(--sn-ink) !important;
  font-family: 'Space Grotesk', 'DM Sans', sans-serif !important;
  letter-spacing: -.035em;
}

h1 { font-weight: 700 !important; }
h2 {
  font-size: 1.38rem !important;
  font-weight: 700 !important;
  margin-top: .55rem !important;
  margin-bottom: .85rem !important;
}
h3 { font-weight: 700 !important; font-size: 1.05rem !important; }

p, li, label, [data-testid="stMarkdownContainer"] {
  color: #34415c;
}

[data-testid="stCaptionContainer"] p {
  color: var(--sn-muted) !important;
  font-size: .82rem;
  line-height: 1.5;
}

a { color: var(--sn-violet) !important; text-decoration: none; }
a:hover { color: var(--sn-cyan) !important; }

.sentry-hero {
  position: relative;
  isolation: isolate;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.5rem;
  min-height: 205px;
  margin: .1rem 0 1.1rem;
  padding: 1.85rem 2rem;
  overflow: hidden;
  border-radius: 24px;
  border: 1px solid rgba(107, 94, 216, .19);
  background:
    radial-gradient(ellipse at 82% 0%, rgba(34, 211, 238, .20), transparent 35%),
    radial-gradient(ellipse at 9% 110%, rgba(155, 139, 255, .24), transparent 38%),
    linear-gradient(118deg, #ffffff 0%, #f4f3ff 57%, #edfaff 100%);
  box-shadow: 0 13px 38px rgba(39, 52, 93, .075), inset 0 1px 0 #fff;
}

.sentry-hero::before {
  content: "";
  position: absolute;
  inset: 0;
  z-index: -1;
  opacity: .33;
  background-image:
    linear-gradient(rgba(105, 98, 190, .08) 1px, transparent 1px),
    linear-gradient(90deg, rgba(105, 98, 190, .08) 1px, transparent 1px);
  background-size: 31px 31px;
  mask-image: linear-gradient(90deg, black, transparent 91%);
}

.sentry-hero-main { z-index: 1; min-width: 0; }
.sentry-eyebrow {
  display: flex;
  align-items: center;
  gap: .55rem;
  margin-bottom: .72rem;
  color: #6457c5;
  font-size: .66rem;
  font-weight: 800;
  letter-spacing: .16em;
}
.sentry-live-dot {
  width: 8px; height: 8px; flex-shrink: 0;
  border-radius: 50%;
  background: #16a37a;
  box-shadow: 0 0 0 4px rgba(22, 163, 122, .11);
  animation: snPulse 2.4s ease-in-out infinite;
}
.sentry-brand {
  color: #202a47;
  font-family: 'Space Grotesk', sans-serif;
  font-size: clamp(2.35rem, 4.5vw, 3.65rem);
  font-weight: 700;
  letter-spacing: -.075em;
  line-height: 1;
}
.sentry-brand span {
  color: #7769dd;
  font-size: .39em;
  letter-spacing: .05em;
  vertical-align: middle;
  margin-left: .3rem;
}
.sentry-subtitle {
  margin-top: .78rem;
  color: #596780;
  font-size: .94rem;
  max-width: 630px;
}
.sentry-hero-foot {
  display: flex;
  align-items: center;
  gap: .6rem;
  margin-top: 1.05rem;
  color: #7b87a0;
  text-transform: uppercase;
  letter-spacing: .1em;
  font-size: .61rem;
  font-weight: 800;
}
.sentry-hero-foot .mini-line {
  width: 26px; height: 3px; border-radius: 99px;
  background: linear-gradient(90deg, #7b68e8, #22b6d5);
}
.sentry-hero-aside {
  z-index: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: .75rem;
}
.sentry-orbit-visual {
  position: relative;
  width: 132px; height: 132px;
  display: grid; place-items: center;
}
.sentry-orbit {
  position: absolute;
  border: 1px solid rgba(107, 94, 216, .35);
  border-radius: 50%;
}
.sentry-orbit-one { inset: 5px; border-top-color: #15a9c7; animation: snRotate 16s linear infinite; }
.sentry-orbit-two { inset: 19px; border-right-color: #15a9c7; animation: snRotate 11s linear infinite reverse; }
.sentry-orbit-three { inset: 33px; border-bottom-color: #9283f2; animation: snRotate 20s linear infinite; }
.sentry-radar-core {
  width: 45px; height: 45px; display: grid; place-items: center;
  border: 1px solid rgba(108, 91, 220, .34);
  border-radius: 15px;
  color: #fff; font-size: 1.45rem; font-weight: 800;
  background: linear-gradient(145deg, #8b7cf0, #5145bb);
  box-shadow: 0 8px 24px rgba(95, 79, 197, .24);
}
.sentry-radar-node {
  position: absolute; width: 7px; height: 7px; border-radius: 50%;
  background: #11a9c8; box-shadow: 0 0 0 4px rgba(17, 169, 200, .10);
}
.sentry-node-one { top: 8px; left: 47px; }
.sentry-node-two { right: 7px; top: 68px; }
.sentry-node-three { bottom: 12px; left: 34px; background: #18a378; }
.sentry-hero-tags { display: flex; flex-direction: column; align-items: flex-end; gap: .45rem; }
.sentry-hero-tags span {
  border: 1px solid #dce2f0;
  background: rgba(255,255,255,.73);
  color: #626f88;
  border-radius: 999px;
  padding: .4rem .65rem;
  font-size: .58rem;
  font-weight: 800;
  letter-spacing: .07em;
  white-space: nowrap;
}
.sentry-hero-tags span:first-child { border-color: #cceade; color: #168568; }
.sentry-hero-tags span:last-child { border-color: #c9edf5; color: #087e9b; }

.sentry-section-head {
  display: flex;
  align-items: center;
  gap: .65rem;
  margin: .45rem 0 .8rem;
  color: #1b2844;
  font-family: 'Space Grotesk', sans-serif;
  font-weight: 700;
  font-size: 1.22rem;
  letter-spacing: -.025em;
}
.sentry-section-mark {
  width: 30px; height: 30px; display: inline-grid; place-items: center;
  border-radius: 9px;
  color: #6556cf;
  background: #eceaff;
  border: 1px solid #e0dcff;
  font-size: .9rem;
}
.sentry-section-note {
  margin: -.45rem 0 .9rem 2.55rem;
  font-size: .82rem;
  color: #7a879d;
}

[data-testid="stMetric"] {
  position: relative;
  overflow: hidden;
  min-height: 111px;
  padding: 1rem 1.08rem .9rem;
  border-radius: 16px;
  border: 1px solid #e4e9f3;
  background: linear-gradient(145deg, #fff, #fbfcff);
  box-shadow: 0 5px 18px rgba(36, 49, 82, .045), inset 0 1px 0 #fff;
  transition: transform .18s ease, box-shadow .18s ease, border-color .18s ease;
}
[data-testid="stMetric"]::before {
  content: "";
  position: absolute; top: 0; left: 1rem; right: 1rem;
  height: 3px; border-radius: 0 0 99px 99px;
  background: linear-gradient(90deg, #8373e9, #27b9d0);
  opacity: .78;
}
[data-testid="stMetric"]:hover {
  transform: translateY(-2px);
  border-color: #d1ccfa;
  box-shadow: 0 10px 24px rgba(66, 70, 128, .08);
}
[data-testid="stMetricLabel"] p {
  color: #74819a !important;
  font-size: .73rem !important;
  font-weight: 700 !important;
}
[data-testid="stMetricValue"] {
  color: #202b48 !important;
  font-size: clamp(1.5rem, 2.1vw, 2.05rem) !important;
  font-weight: 800 !important;
  letter-spacing: -.05em;
}
[data-testid="stMetricDelta"] { font-size: .75rem !important; }

.stButton > button,
[data-testid="stFormSubmitButton"] > button,
[data-testid="stDownloadButton"] > button {
  border-radius: 10px;
  border: 1px solid #d9d3ff;
  background: linear-gradient(135deg, #7868e7, #6555d2);
  color: #fff !important;
  font-weight: 700;
  padding: .55rem .95rem;
  box-shadow: 0 5px 14px rgba(98, 81, 210, .14);
  transition: all .16s ease-in-out;
}
.stButton > button:hover,
[data-testid="stFormSubmitButton"] > button:hover,
[data-testid="stDownloadButton"] > button:hover {
  border-color: #b7b0f3;
  background: linear-gradient(135deg, #6b5bdd, #5545c3);
  color: #fff !important;
  box-shadow: 0 7px 20px rgba(98, 81, 210, .21);
  transform: translateY(-1px);
}
.stButton > button:focus-visible {
  outline: 2px solid #0da5c3;
  outline-offset: 2px;
}

[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea,
[data-testid="stSelectbox"] [data-baseweb="select"] > div,
[data-testid="stMultiSelect"] [data-baseweb="select"] > div,
[data-testid="stDateInput"] input {
  background: #fff !important;
  border-color: #dfe5f0 !important;
  border-radius: 10px !important;
  color: #24314e !important;
}
[data-testid="stTextInput"] input:focus,
[data-testid="stTextArea"] textarea:focus {
  border-color: #8879e8 !important;
  box-shadow: 0 0 0 1px rgba(123, 105, 227, .18) !important;
}
[data-testid="stForm"] {
  padding: 1rem;
  border: 1px solid #e3e8f2;
  border-radius: 15px;
  background: rgba(255,255,255,.83);
  box-shadow: 0 5px 20px rgba(36,49,82,.035);
}

[data-testid="stTabs"] [data-baseweb="tab-list"] {
  gap: .35rem;
  border-bottom: 1px solid #e4e9f3;
}
[data-testid="stTabs"] button[data-baseweb="tab"] {
  color: #77839a;
  border-radius: 10px 10px 0 0;
  padding: .65rem .95rem;
  font-weight: 700;
}
[data-testid="stTabs"] button[data-baseweb="tab"][aria-selected="true"] {
  color: #5d4fc7;
  background: #f0eeff;
  border-bottom-color: #7666df;
}
[data-testid="stDataFrame"], [data-testid="stTable"] {
  border: 1px solid #e3e8f2;
  border-radius: 13px;
  overflow: hidden;
  background: #fff;
}
[data-testid="stExpander"] {
  background: rgba(255,255,255,.91);
  border: 1px solid #e2e7f0;
  border-radius: 13px;
  overflow: hidden;
  margin-bottom: .6rem;
  box-shadow: 0 3px 12px rgba(36,49,82,.025);
}
[data-testid="stExpander"] summary {
  color: #283552;
  font-weight: 700;
}
[data-testid="stAlert"] {
  border-radius: 12px;
  border-width: 1px;
}
hr {
  border-color: #e1e7f1 !important;
  margin: 1.55rem 0 !important;
}
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #fff, #f7f8fd);
  border-right: 1px solid #e4e8f1;
}
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
  color: #263452 !important;
}
[data-testid="stSidebar"] [data-testid="stMetric"] {
  min-height: 92px;
}
[data-testid="stHorizontalBlock"] { gap: .82rem; }
* { scrollbar-color: #c7cce0 #f4f6fb; scrollbar-width: thin; }

.sentry-runtime {
  display: flex; justify-content: space-between; align-items: center; gap: 1rem;
  padding: 12px 15px; margin: .1rem 0 1.25rem;
  background: rgba(255,255,255,.84);
  border: 1px solid #e3e8f2; border-radius: 13px;
  box-shadow: 0 4px 15px rgba(36,49,82,.035);
}
.sentry-runtime-block { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.sentry-runtime-label { color: #8a95a9; font-size: 9px; font-weight: 800; letter-spacing: .13em; text-transform: uppercase; }
.sentry-runtime-value { color: #34415d; font-size: 12px; font-weight: 750; white-space: nowrap; }
.sentry-runtime-state { display: inline-flex; align-items: center; gap: 6px; color: #168568; font-size: 10px; font-weight: 800; }
.sentry-runtime-state::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: #18a67b; }

@keyframes snPulse { 0%, 100% { opacity: 1; } 50% { opacity: .62; } }
@keyframes snRotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; }
}
@media (max-width: 850px) {
  .block-container { padding-top: 1rem; }
  .sentry-hero { align-items: flex-start; flex-direction: column; padding: 1.35rem; min-height: unset; }
  .sentry-hero-aside { flex-direction: row; flex-wrap: wrap; }
  .sentry-hero-tags { align-items: flex-start; }
  [data-testid="stMetric"] { min-height: 92px; padding: .8rem; }
  .sentry-runtime { flex-wrap: wrap; }
}
@media (max-width: 480px) {
  .sentry-brand { font-size: 2.25rem; }
  .sentry-orbit-visual { width: 105px; height: 105px; }
}
</style>
"""

st.markdown(LIGHT_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------
# HERO
# ---------------------------------------------------------------------

st.markdown(
    """
    <div class="sentry-hero">
      <div class="sentry-hero-main">
        <div class="sentry-eyebrow">
          <span class="sentry-live-dot"></span>
          SECURITY OPERATIONS CENTER
        </div>
        <div class="sentry-brand">SENTRY <span>/ SOC</span></div>
        <div class="sentry-subtitle">
          Security Event Detection &amp; Threat Investigation Platform
        </div>
        <div class="sentry-hero-foot">
          <span class="mini-line"></span>
          DETECT &nbsp;·&nbsp; CORRELATE &nbsp;·&nbsp; INVESTIGATE
        </div>
      </div>
      <div class="sentry-hero-aside">
        <div class="sentry-orbit-visual">
          <div class="sentry-orbit sentry-orbit-one"></div>
          <div class="sentry-orbit sentry-orbit-two"></div>
          <div class="sentry-orbit sentry-orbit-three"></div>
          <div class="sentry-radar-core">S</div>
          <span class="sentry-radar-node sentry-node-one"></span>
          <span class="sentry-radar-node sentry-node-two"></span>
          <span class="sentry-radar-node sentry-node-three"></span>
        </div>
        <div class="sentry-hero-tags">
          <span>LOCAL MONITORING</span>
          <span>OFFLINE THREAT INTEL</span>
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# LOAD PIPELINE AND DATABASE
# ---------------------------------------------------------------------

try:
    results = run_pipeline()
    events = results.get("events", [])
    alerts = results.get("alerts", [])
    correlations = results.get("correlations", [])
    detected_incidents = results.get("incidents", [])

    # Synchronize current detections with persistent storage.
    sync_incidents(detected_incidents)
    stored_incidents = get_all_incidents()
except Exception as exc:
    st.error("SENTRY could not load its pipeline or incident database.")
    st.exception(exc)
    st.stop()


def normalize_incident(record):
    """Normalize pipeline and SQLite incident records for display."""
    incident = dict(record)
    incident_type = (
        incident.get("type")
        or incident.get("incident_type")
        or "unknown"
    )
    incident["type"] = incident_type
    incident["incident_type"] = incident_type
    incident["incident_id"] = incident.get("incident_id", "Unknown")
    incident["source_ip"] = incident.get("source_ip") or "Unknown"
    incident["username"] = incident.get("username") or "Unknown"

    try:
        incident["risk_score"] = int(incident.get("risk_score") or 0)
    except (TypeError, ValueError):
        incident["risk_score"] = 0

    incident["risk_level"] = str(incident.get("risk_level") or "low").lower()
    incident["status"] = str(incident.get("status") or "open").lower()
    incident["analyst_notes"] = incident.get("analyst_notes") or ""

    try:
        incident["related_events"] = int(incident.get("related_events") or 0)
    except (TypeError, ValueError):
        incident["related_events"] = 0

    incident["timeline"] = incident.get("timeline") or []
    incident["evidence"] = incident.get("evidence") or {}
    return incident


def get_threat_findings(incident):
    """Read threat-intelligence evidence, supporting older incident records."""
    evidence = incident.get("evidence") or {}
    findings = evidence.get("threat_intelligence") or []
    if isinstance(findings, dict):
        findings = [findings]
    return [item for item in findings if isinstance(item, dict)]


def intel_status(item):
    return str(item.get("status") or "not_available").lower()


incidents = [normalize_incident(item) for item in stored_incidents]

alert_intel = [
    item.get("threat_intel", {})
    for item in alerts
    if isinstance(item.get("threat_intel"), dict)
]

known_matches = sum(intel_status(item) ==
                    "known_malicious" for item in alert_intel)
unmatched_ips = sum(intel_status(item) == "not_found" for item in alert_intel)
invalid_ips = sum(intel_status(item) == "invalid_ip" for item in alert_intel)

critical_count = sum(item["risk_level"] == "critical" for item in incidents)
high_count = sum(item["risk_level"] == "high" for item in incidents)
open_count = sum(item["status"] == "open" for item in incidents)
investigating_count = sum(
    item["status"] == "investigating" for item in incidents)
resolved_count = sum(item["status"] == "resolved" for item in incidents)


# ---------------------------------------------------------------------
# CLIENT STATUS STRIP (JAVASCRIPT RUNS IN STREAMLIT COMPONENT IFRAME)
# ---------------------------------------------------------------------

status_html = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
  * { box-sizing: border-box; }
  body { margin: 0; background: transparent; font-family: Arial, sans-serif; }
  .runtime {
    display: flex; justify-content: space-between; align-items: center; gap: 12px;
    padding: 12px 15px; background: #fff; border: 1px solid #e3e8f2;
    border-radius: 13px; color: #34415d;
    box-shadow: 0 4px 15px rgba(36,49,82,.035);
  }
  .block { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .label { color: #8a95a9; font-size: 9px; font-weight: 800; letter-spacing: 1.1px; text-transform: uppercase; }
  .value { color: #34415d; font-size: 12px; font-weight: 700; white-space: nowrap; }
  .state { display: inline-flex; align-items: center; gap: 5px; color: #168568; font-size: 10px; font-weight: 800; white-space: nowrap; }
  .state::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: #18a67b; }
  @media (max-width: 600px) { .runtime { flex-wrap: wrap; } }
</style>
</head>
<body>
<div class="runtime">
  <div class="block">
    <span class="label">Pipeline</span>
    <span class="value">__EVENTS__ events processed</span>
  </div>
  <div class="block">
    <span class="label">Alert queue</span>
    <span class="value">__ALERTS__ alerts generated</span>
  </div>
  <div class="block">
    <span class="label">Threat intelligence</span>
    <span class="value">LOCAL / OFFLINE</span>
    <span class="state" id="sentry-client-state">ACTIVE SESSION</span>
  </div>
  <div class="block" style="text-align:right">
    <span class="label">Local browser time</span>
    <time class="value" id="sentry-live-clock">--:--:--</time>
    <span class="label" id="sentry-live-date">Loading date...</span>
  </div>
</div>
<script>
(() => {
  const clock = document.getElementById("sentry-live-clock");
  const dateLine = document.getElementById("sentry-live-date");
  const state = document.getElementById("sentry-client-state");
  if (!clock || !dateLine) return;

  const clockFmt = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
  });
  const dateFmt = new Intl.DateTimeFormat(undefined, {
    weekday: "short", day: "2-digit", month: "short", year: "numeric"
  });

  function refresh() {
    const now = new Date();
    clock.textContent = clockFmt.format(now);
    dateLine.textContent = dateFmt.format(now);
    clock.dateTime = now.toISOString();
  }

  function refreshVisibility() {
    if (!state) return;
    const active = document.visibilityState !== "hidden";
    state.textContent = active ? "ACTIVE SESSION" : "IN BACKGROUND";
    state.style.color = active ? "#168568" : "#9a6a17";
  }

  refresh();
  refreshVisibility();
  window.setInterval(refresh, 1000);
  document.addEventListener("visibilitychange", refreshVisibility);
})();
</script>
</body>
</html>
"""

status_html = (
    status_html
    .replace("__EVENTS__", str(len(events)))
    .replace("__ALERTS__", str(len(alerts)))
)

st.iframe(status_html, height=86)


# ---------------------------------------------------------------------
# OVERVIEW METRICS
# ---------------------------------------------------------------------

st.markdown(
    '<div class="sentry-section-head"><span class="sentry-section-mark">▦</span>Security overview</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="sentry-section-note">Current pipeline activity and the persistent incident queue.</div>',
    unsafe_allow_html=True,
)

overview_cols = st.columns(5)
overview_cols[0].metric("Events processed", len(events))
overview_cols[1].metric("Alerts generated", len(alerts))
overview_cols[2].metric("Open incidents", open_count)
overview_cols[3].metric("Investigating", investigating_count)
overview_cols[4].metric("Resolved", resolved_count)

threat_cols = st.columns(4)
threat_cols[0].metric("Known feed matches", known_matches)
threat_cols[1].metric("Unmatched IPs", unmatched_ips)
threat_cols[2].metric("Invalid IP values", invalid_ips)
threat_cols[3].metric("Threat intel checks", len(alert_intel))

st.caption(
    "Threat intelligence uses the local offline feed. An unmatched IP is unknown; "
    "it is not proof that the IP is safe. Feed matches reflect configured local indicators."
)
st.divider()


# ---------------------------------------------------------------------
# INCIDENT MANAGEMENT
# ---------------------------------------------------------------------

st.markdown(
    '<div class="sentry-section-head"><span class="sentry-section-mark">⌁</span>Incident management</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="sentry-section-note">Filter incidents and open a record to review evidence, timeline, and analyst actions.</div>',
    unsafe_allow_html=True,
)

risk_options = ["critical", "high", "medium", "low"]
type_options = sorted({item["type"] for item in incidents})
status_options = ["open", "investigating", "resolved"]

filter_cols = st.columns(3)
with filter_cols[0]:
    selected_risks = st.multiselect(
        "Risk level",
        options=risk_options,
        default=risk_options,
        format_func=lambda value: value.upper(),
        key="incident_risk_filter",
    )
with filter_cols[1]:
    selected_types = st.multiselect(
        "Incident type",
        options=type_options,
        default=type_options,
        format_func=lambda value: value.replace("_", " ").title(),
        key="incident_type_filter",
    )
with filter_cols[2]:
    selected_statuses = st.multiselect(
        "Incident status",
        options=status_options,
        default=status_options,
        format_func=lambda value: value.title(),
        key="incident_status_filter",
    )

filtered_incidents = [
    item for item in incidents
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
        statuses = sorted({intel_status(item) for item in findings})
        incident_rows.append({
            "Incident ID": incident["incident_id"],
            "Type": incident["type"].replace("_", " ").title(),
            "Source IP": incident["source_ip"],
            "Username": incident["username"],
            "Risk Score": incident["risk_score"],
            "Risk Level": incident["risk_level"].upper(),
            "Status": incident["status"].title(),
            "Related Events": incident["related_events"],
            "Threat Intel": ", ".join(statuses) if statuses else "not available",
        })

    st.dataframe(
        pd.DataFrame(incident_rows),
        width="stretch",
        hide_index=True,
    )

    incident_lookup = {
        (
            f'{incident["incident_id"]} — '
            f'{incident["type"].replace("_", " ").title()} '
            f'({incident["source_ip"]})'
        ): incident
        for incident in filtered_incidents
    }

    selected_label = st.selectbox(
        "Select an incident to investigate",
        options=list(incident_lookup.keys()),
        key="incident_to_investigate",
    )
    selected_incident = incident_lookup[selected_label]
    incident_id = selected_incident["incident_id"]

    st.markdown(
        '<div class="sentry-section-head"><span class="sentry-section-mark">⌕</span>Incident investigation</div>',
        unsafe_allow_html=True,
    )

    detail_cols = st.columns(4)
    detail_cols[0].metric("Risk score", selected_incident["risk_score"])
    detail_cols[1].metric(
        "Risk level", selected_incident["risk_level"].upper())
    detail_cols[2].metric(
        "Related events", selected_incident["related_events"])
    detail_cols[3].metric(
        "Current status", selected_incident["status"].title())

    info_cols = st.columns(2)
    with info_cols[0]:
        st.write(f'**Incident ID:** {incident_id}')
        st.write(
            f'**Incident type:** {selected_incident["type"].replace("_", " ").title()}')
    with info_cols[1]:
        st.write(f'**Source IP:** {selected_incident["source_ip"]}')
        st.write(f'**Username:** {selected_incident["username"]}')

    st.markdown("#### Threat intelligence")
    incident_findings = get_threat_findings(selected_incident)

    if incident_findings:
        for index, finding in enumerate(incident_findings, start=1):
            status = intel_status(finding)
            status_label = {
                "known_malicious": "Known local-feed match",
                "not_found": "Not found in local feed",
                "invalid_ip": "Invalid IP",
                "not_available": "Not available",
            }.get(status, status.replace("_", " ").title())

            with st.expander(f"Finding {index} · {status_label}", expanded=(index == 1)):
                st.write(
                    f'**IP address:** {finding.get("ip") or "Not available"}')
                st.write(f'**Source:** {finding.get("source") or "Unknown"}')
                st.write(f'**Category:** {finding.get("category") or "None"}')
                st.write(
                    f'**Description:** {finding.get("description") or "No description"}')

        if any(intel_status(item) == "not_found" for item in incident_findings):
            st.warning(
                "One or more IPs are absent from the local feed. "
                "An unmatched result does not establish that an IP is safe."
            )
    else:
        st.info("No threat-intelligence findings are stored for this incident.")

    with st.expander("Evidence and correlation details", expanded=False):
        if selected_incident.get("evidence"):
            st.json(selected_incident["evidence"])
        else:
            st.info("No stored evidence details for this incident.")

    with st.expander("Incident timeline", expanded=True):
        timeline = selected_incident.get("timeline", [])
        if timeline:
            for timestamp in timeline:
                st.write(f"• {timestamp}")
        else:
            st.info("No timeline is available for this incident.")

    st.markdown("#### Analyst response")
    with st.form(key=f"incident_update_{incident_id}"):
        current_status = selected_incident["status"]
        new_status = st.selectbox(
            "Update incident status",
            options=status_options,
            index=(
                status_options.index(current_status)
                if current_status in status_options else 0
            ),
            format_func=lambda value: value.title(),
        )
        new_notes = st.text_area(
            "Analyst notes",
            value=selected_incident["analyst_notes"],
            height=125,
            placeholder="Document investigation steps, findings, and next actions...",
        )
        submitted = st.form_submit_button("Save incident updates")

        if submitted:
            try:
                update_incident_status(incident_id, new_status)
                update_analyst_notes(incident_id, new_notes)
                st.success("Incident status and analyst notes saved.")
                st.rerun()
            except Exception as exc:
                st.error("Could not save the incident updates.")
                st.exception(exc)

st.divider()


# ---------------------------------------------------------------------
# SECURITY ALERTS
# ---------------------------------------------------------------------

st.markdown(
    '<div class="sentry-section-head"><span class="sentry-section-mark">⚑</span>Security alerts</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="sentry-section-note">Detection results enriched with risk scoring and local-feed status.</div>',
    unsafe_allow_html=True,
)

if alerts:
    alert_rows = []
    for item in alerts:
        event = item.get("event", {})
        detection = item.get("detection", {})
        risk = item.get("risk", {})
        intel = item.get("threat_intel") or {}
        status = intel_status(intel) if intel else "not_available"

        alert_rows.append({
            "Timestamp": event.get("timestamp", "Unknown"),
            "Rule ID": detection.get("rule_id", "Unknown"),
            "Alert": detection.get("reason") or detection.get("alert") or "Detection matched",
            "Severity": str(detection.get("severity", "unknown")).upper(),
            "Risk Score": risk.get("risk_score", 0),
            "Risk Level": str(risk.get("risk_level", "low")).upper(),
            "Username": event.get("username") or "—",
            "Source IP": event.get("source_ip") or "—",
            "Threat Intel": status.replace("_", " ").upper(),
            "Threat Category": intel.get("category") or "—",
        })

    st.dataframe(
        pd.DataFrame(alert_rows),
        width="stretch",
        hide_index=True,
    )

    with st.expander("Alert-by-alert threat-intelligence details"):
        for index, item in enumerate(alerts, start=1):
            event = item.get("event", {})
            intel = item.get("threat_intel") or {}
            status = intel_status(intel) if intel else "not_available"
            st.markdown(
                f'**{index}. {event.get("timestamp", "Unknown")} · '
                f'{event.get("source_ip") or "Unknown IP"} · '
                f'{status.replace("_", " ").title()}**'
            )
            st.json(intel or {"status": "not_available"})
            if index < len(alerts):
                st.divider()
else:
    st.info("No security alerts were generated by the current pipeline run.")

st.divider()


# ---------------------------------------------------------------------
# EVENT CORRELATIONS
# ---------------------------------------------------------------------

st.markdown(
    '<div class="sentry-section-head"><span class="sentry-section-mark">⤳</span>Event correlations</div>',
    unsafe_allow_html=True,
)

if correlations:
    correlation_rows = [
        {
            "Correlation ID": item.get("correlation_id", "Unknown"),
            "Type": str(item.get("type", "unknown")).replace("_", " ").title(),
            "Source IP": item.get("source_ip", "Unknown"),
            "Username": item.get("username") or "—",
            "Event Count": item.get("event_count", 0),
            "Time Window (seconds)": item.get("time_window_seconds", 0),
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


# ---------------------------------------------------------------------
# PROCESSED SECURITY EVENTS
# ---------------------------------------------------------------------

st.markdown(
    '<div class="sentry-section-head"><span class="sentry-section-mark">▤</span>Processed security events</div>',
    unsafe_allow_html=True,
)

if events:
    st.dataframe(
        pd.DataFrame(events),
        width="stretch",
        hide_index=True,
    )
else:
    st.info("No security events were processed.")

st.divider()


# ---------------------------------------------------------------------
# THREAT INTELLIGENCE FEED MANAGEMENT
# ---------------------------------------------------------------------

st.markdown(
    '<div class="sentry-section-head"><span class="sentry-section-mark">◎</span>Threat intelligence feed management</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="sentry-section-note">Manage the offline IP indicator list. An entry is an analyst-configured indicator, not an independent verdict from a reputation service.</div>',
    unsafe_allow_html=True,
)

flash_message = st.session_state.pop("feed_management_flash", None)
if flash_message:
    st.success(flash_message)

try:
    managed_feed = load_managed_feed()
    feed_load_error = None
except Exception as exc:
    managed_feed = None
    feed_load_error = exc

if feed_load_error:
    st.error("The local threat feed could not be loaded. No changes were made.")
    st.exception(feed_load_error)

else:
    st.metric("Indicators in local feed", len(managed_feed))

    if managed_feed:
        feed_rows = [
            {
                "IP address": address,
                "Category": details.get("category", "unspecified"),
                "Description": details.get("description", ""),
            }
            for address, details in sorted(managed_feed.items())
        ]
        st.dataframe(
            pd.DataFrame(feed_rows),
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("The local threat feed is empty. Add an indicator below.")

    add_tab, remove_tab = st.tabs([
        "Add / update indicator",
        "Remove indicator",
    ])

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
                placeholder="Explain why this indicator is in the feed.",
            )
            replace_existing = st.checkbox(
                "Replace details if this IP already exists",
                value=False,
            )
            add_submitted = st.form_submit_button("Save indicator")

        if add_submitted:
            try:
                saved_ip = add_indicator(
                    new_ip,
                    new_category,
                    new_description,
                    overwrite=replace_existing,
                )
                st.session_state["feed_management_flash"] = (
                    f"Saved indicator {saved_ip} to the local feed."
                )
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
            except Exception as exc:
                st.error("Could not save the indicator.")
                st.exception(exc)

    with remove_tab:
        if not managed_feed:
            st.info("There are no indicators to remove.")
        else:
            with st.form("sentry_remove_threat_indicator"):
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
                    "Remove selected indicator"
                )

            if remove_submitted:
                if not confirm_remove:
                    st.error("Confirm removal before deleting an indicator.")
                else:
                    try:
                        removed_ip = remove_indicator(selected_ip)
                        st.session_state["feed_management_flash"] = (
                            f"Removed indicator {removed_ip} from the local feed."
                        )
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
                    except Exception as exc:
                        st.error("Could not remove the indicator.")
                        st.exception(exc)


# ---------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------

with st.sidebar:
    st.markdown(
        """
        <div style="
            padding: 1rem 0 .7rem;
            border-bottom: 1px solid #e5e9f2;
            margin-bottom: 1rem;">
          <div style="display:flex;align-items:center;gap:10px;">
            <div style="
                display:grid;place-items:center;width:37px;height:37px;
                border-radius:12px;color:#fff;font-weight:800;font-size:18px;
                background:linear-gradient(135deg,#8677ed,#5748c5);
                box-shadow:0 6px 15px rgba(96,80,200,.20);">S</div>
            <div>
              <div style="font-family:'Space Grotesk',sans-serif;font-size:18px;
                  font-weight:800;letter-spacing:-.5px;color:#202b48;">SENTRY</div>
              <div style="font-size:10px;letter-spacing:1.3px;
                  font-weight:800;color:#7b87a0;">SOC CONSOLE</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption("SECURITY OPERATIONS")
    st.metric("Stored incidents", len(incidents))
    st.metric("High-risk incidents", high_count + critical_count)
    st.metric("Investigating", investigating_count)
    st.metric("Known feed matches", known_matches)

    st.divider()
    st.caption("ENVIRONMENT")
    st.write("**Mode:** Local prototype")
    st.write("**Threat feed:** Offline JSON")
    st.write("**Storage:** SQLite")
    st.caption(
        "Use verified indicators for real investigations. "
        "This prototype is intended for development and demonstration."
    )
