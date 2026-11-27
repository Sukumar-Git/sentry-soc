from app.response import block_ip, load_blocklist, unblock_ip
from app.pipeline import run_pipeline
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


st.set_page_config(page_title="SENTRY - Response", layout="wide")
st.title("Response Actions")
st.warning(
    "Simulation only: blocking records an IP in data/blocklist.json. "
    "No firewall rule is created."
)

results = run_pipeline()
blocklist = load_blocklist()

by_ip = {}
for alert in results["alerts"]:
    ip = alert["event"].get("source_ip")
    if not ip:
        continue
    row = by_ip.setdefault(ip, {"source_ip": ip, "alerts": 0, "max_risk": 0})
    row["alerts"] += 1
    row["max_risk"] = max(row["max_risk"], alert["risk"].get("risk_score", 0))

suspects = sorted(by_ip.values(), key=lambda r: r["max_risk"], reverse=True)

st.subheader("Top source IPs")
if suspects:
    table = pd.DataFrame(suspects)
    table["blocked"] = table["source_ip"].isin(blocklist)
    st.dataframe(table)
else:
    st.info("No alerts with a source IP yet.")

st.subheader("Block an IP")
with st.form("block_form", clear_on_submit=True):
    choices = [r["source_ip"]
               for r in suspects if r["source_ip"] not in blocklist]
    picked = st.selectbox("Pick from alerts", [""] + choices)
    typed = st.text_input("...or type an IP address")
    reason = st.text_input("Reason", value="Manual block from dashboard")
    submitted = st.form_submit_button("Block (simulated)")

if submitted:
    ok = False
    try:
        block_ip(typed.strip() or picked, reason)
        ok = True
    except ValueError:
        st.error("Enter a valid IP address.")
    if ok:
        st.rerun()

st.subheader("Blocklist")
if blocklist:
    st.dataframe(pd.DataFrame.from_dict(
        blocklist, orient="index").rename_axis("ip").reset_index())
    with st.form("unblock_form"):
        target = st.selectbox("Unblock", list(blocklist))
        if st.form_submit_button("Unblock"):
            unblock_ip(target)
            st.rerun()
else:
    st.caption("Nothing blocked.")
