from app.pipeline import run_pipeline
from app.mitre_summary import alerts_to_rows, count_by
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# make `app` importable when Streamlit runs this page
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


st.set_page_config(page_title="SENTRY - MITRE ATT&CK", layout="wide")
st.title("MITRE ATT&CK Coverage")
st.caption(
    "Alerts grouped by attacker tactic and technique. Refresh the page for new data.")

results = run_pipeline()
rows = alerts_to_rows(results["alerts"])

if not rows:
    st.info("No alerts yet. Start the simulator and watcher, then refresh.")
    st.stop()

df = pd.DataFrame(rows)
tagged = df[df["tactic"] != "Untagged"]

c1, c2, c3 = st.columns(3)
c1.metric("Total alerts", len(df))
c2.metric("MITRE-tagged alerts", len(tagged))
c3.metric("Tactics seen", tagged["tactic"].nunique())

left, right = st.columns(2)
with left:
    st.subheader("Alerts by tactic")
    st.bar_chart(pd.Series(count_by(rows, "tactic")))
with right:
    st.subheader("Alerts by technique")
    st.bar_chart(pd.Series(count_by(rows, "technique")))

st.subheader("Alert details")
chosen = st.multiselect("Filter by tactic", sorted(df["tactic"].unique()))
view = df[df["tactic"].isin(chosen)] if chosen else df
st.dataframe(view.sort_values("time", ascending=False))
