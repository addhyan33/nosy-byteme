from __future__ import annotations

import html
import json

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from backend.storage import query_dataframe
from frontend.styles import CSS

SEVERITY_COLOURS = {"critical": "#E5484D", "high": "#E8A33D", "medium": "#D8B84F", "low": "#6B93B0"}


def _uptime(seconds: int) -> str:
    hours, remainder = divmod(seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}"


def _hero(fps: float, uptime: int, total: int) -> None:
    st.markdown(f'''<div class="hero"><div class="brand"><span class="brand-mark">N</span>NOSY</div>
    <div class="pulse-wrap"><svg class="pulse" viewBox="0 0 300 20" preserveAspectRatio="none"><path d="M0 10 H54 L63 3 L72 17 L81 10 H130 L139 4 L148 16 L157 10 H300"/></svg></div>
    <div class="hero-stats"><div class="stat"><div class="stat-label">ingest rate</div><div class="stat-value">{fps:,.0f}/s</div></div>
    <div class="stat"><div class="stat-label">uptime</div><div class="stat-value">{_uptime(uptime)}</div></div>
    <div class="stat"><div class="stat-label">alerts today</div><div class="stat-value">{total:,}</div></div></div></div>''', unsafe_allow_html=True)


def _table(alerts: pd.DataFrame) -> None:
    rows = []
    for _, alert in alerts.iterrows():
        confidence = float(alert["confidence"])
        flow = f'{alert.get("src_ip") or "—"} → {alert.get("dst_ip") or "—"}'
        severity = str(alert["severity"])
        rows.append(f'''<tr><td>{html.escape(str(alert["timestamp"])[11:19])}</td><td>{html.escape(str(alert["threat_class"]))}</td>
        <td>{html.escape(flow)}</td><td><div class="confidence"><span>{confidence:.0%}</span><span class="confidence-track"><span class="confidence-fill" style="width:{confidence * 100:.0f}%"></span></span></div></td>
        <td><span class="severity severity-{html.escape(severity)}">{html.escape(severity)}</span></td></tr>''')
    content = "".join(rows) if rows else '<tr><td colspan="5" style="color:#8A93A6">awaiting inferred alerts</td></tr>'
    st.markdown(f'''<div class="panel"><div class="panel-title">live alerts <span style="color:#8A93A6;float:right">last 15 min</span></div>
    <table class="alert-table"><thead><tr><th>time</th><th>threat class</th><th>flow</th><th>confidence</th><th>severity</th></tr></thead><tbody>{content}</tbody></table></div>''', unsafe_allow_html=True)


def _sidebar(alerts: pd.DataFrame) -> None:
    counts = alerts["severity"].value_counts().reindex(["critical", "high", "medium", "low"], fill_value=0) if not alerts.empty else pd.Series([0, 0, 0, 0], index=["critical", "high", "medium", "low"])
    fig = go.Figure(go.Pie(labels=counts.index.str.title(), values=counts.values, hole=.7, marker={"colors": [SEVERITY_COLOURS[x] for x in counts.index]}, textinfo="label+percent", textfont={"color": "#E8E6DF", "size": 10}))
    fig.update_layout(height=190, margin=dict(l=0, r=0, t=0, b=0), paper_bgcolor="#1B2028", showlegend=False)
    st.markdown('<div class="panel"><div class="panel-title">severity breakdown</div>', unsafe_allow_html=True); st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}); st.markdown('</div>', unsafe_allow_html=True)
    top = alerts["src_ip"].value_counts().head(5) if not alerts.empty else pd.Series(dtype=int)
    sources = ''.join(f'<div class="source-row"><span class="mono">{html.escape(ip)}</span><span>{count}</span></div>' for ip, count in top.items()) or '<span style="color:#8A93A6">No alerting sources yet</span>'
    st.markdown(f'<div class="panel"><div class="panel-title">top sources</div>{sources}</div>', unsafe_allow_html=True)
    st.markdown('''<div class="panel"><div class="panel-title">ingest path</div><div class="ingest"><span class="ingest-node">prod net</span><span>→</span><span class="ingest-node">one-way gateway</span><span>→</span><span class="ingest-node">NOSY console</span></div><div class="ingest-note">no return path exists</div></div>''', unsafe_allow_html=True)


def _details(alerts: pd.DataFrame) -> None:
    st.sidebar.markdown("### alert evidence")
    if alerts.empty:
        st.sidebar.caption("Select an alert after the pipeline produces one.")
        return
    labels = {row.alert_id: f'{row.threat_class} · {str(row.timestamp)[11:19]} · {row.src_ip}' for _, row in alerts.iterrows()}
    selected = st.sidebar.selectbox("inspect alert", list(labels), format_func=labels.get, label_visibility="collapsed")
    row = alerts.loc[alerts.alert_id == selected].iloc[0]
    st.sidebar.markdown(f"**{row.threat_class}**  ")
    st.sidebar.caption(f"{row.timestamp} · {row.src_ip} → {row.dst_ip}")
    st.sidebar.progress(float(row.confidence), text=f"confidence {float(row.confidence):.0%}")
    evidence = json.loads(row.evidence_json)
    st.sidebar.dataframe(pd.DataFrame(evidence.items(), columns=["feature", "value"]), hide_index=True, use_container_width=True)


def render(pipeline) -> None:
    st.set_page_config(page_title="NOSY | passive detection", page_icon="◈", layout="wide", initial_sidebar_state="collapsed")
    st.markdown(CSS, unsafe_allow_html=True)
    # Streamlit fragments provide bounded, server-side polling without browser-side network calls to a traffic source.
    @st.fragment(run_every=2)
    def live_surface() -> None:
        alerts = query_dataframe("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 80")
        _hero(pipeline.flows_per_second, pipeline.uptime_seconds, len(alerts))
        left, right = st.columns([3, 1], gap="large")
        with left:
            _table(alerts)
        with right:
            _sidebar(alerts)
        _details(alerts)
    live_surface()
