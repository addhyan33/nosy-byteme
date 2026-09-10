"""Visual design tokens from UI_UX_DESIGN.md."""

CSS = """
<style>
:root { --bg:#12151C; --panel:#1B2028; --raised:#20262F; --border:#2A303B; --text:#E8E6DF; --muted:#8A93A6; --amber:#E8A33D; --signal:#4FA8D8; --critical:#E5484D; --high:#E8A33D; --medium:#D8B84F; --low:#6B93B0; }
.stApp { background:var(--bg); color:var(--text); }
html, body, [class*="css"] { font-family: Inter, Arial, sans-serif; }
.mono, .alert-table td, .stat-value, code { font-family:"IBM Plex Mono", Consolas, monospace; }
.hero { display:flex; align-items:center; gap:22px; padding:16px 20px; background:var(--panel); border:1px solid var(--border); border-radius:10px; margin-bottom:20px; }
.brand { min-width:170px; display:flex; align-items:center; gap:10px; font-family:"Space Grotesk",Arial,sans-serif; font-size:21px; font-weight:700; letter-spacing:.08em; }
.brand-mark { color:var(--amber); border:1px solid var(--amber); border-radius:5px; width:28px; height:28px; display:grid; place-items:center; }
.pulse-wrap { flex:1; color:var(--signal); min-width:160px; }.pulse { width:100%; height:20px; overflow:visible; }.pulse path { stroke:var(--signal); stroke-width:2; fill:none; stroke-dasharray:8 5; animation:dash 1.4s linear infinite; }@keyframes dash {to {stroke-dashoffset:-26;}}
.hero-stats { display:flex; gap:24px; }.stat { min-width:74px; }.stat-label { color:var(--muted); text-transform:lowercase; font-size:10px; letter-spacing:.08em; }.stat-value { color:var(--text); font-size:16px; margin-top:3px; }
.panel { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px; margin-bottom:14px; }.panel-title { color:var(--text); font-family:"Space Grotesk",Arial,sans-serif; font-size:13px; letter-spacing:.05em; margin-bottom:15px; text-transform:lowercase; }
.alert-table { width:100%; border-collapse:collapse; font-size:12px; }.alert-table th { text-align:left; color:var(--muted); font-size:10px; font-weight:500; padding:0 9px 10px; text-transform:lowercase; }.alert-table td { padding:10px 9px; border-top:1px solid var(--border); }.alert-table tr:hover td { background:var(--raised); }.confidence { display:flex; align-items:center; gap:7px; }.confidence-track { width:58px; height:4px; background:#313844; border-radius:8px; overflow:hidden; }.confidence-fill { height:100%; background:var(--amber); }.severity { display:inline-block; padding:3px 8px; border-radius:999px; font-family:"Space Grotesk",Arial,sans-serif; font-size:10px; text-transform:uppercase; letter-spacing:.06em; }.severity-critical { background:rgba(229,72,77,.18); color:var(--critical); }.severity-high { background:rgba(232,163,61,.18); color:var(--high); }.severity-medium { background:rgba(216,184,79,.18); color:var(--medium); }.severity-low { background:rgba(107,147,176,.18); color:var(--low); }
.source-row { display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid var(--border); color:var(--text); }.source-row span:last-child { color:var(--muted); }.ingest { display:flex; align-items:center; justify-content:space-between; gap:4px; color:var(--signal); font-family:"IBM Plex Mono",Consolas,monospace; font-size:10px; }.ingest-node { color:var(--text); background:var(--raised); border:1px solid var(--border); padding:7px 6px; border-radius:5px; }.ingest-note { color:var(--muted); font-size:11px; margin:13px 0 0; }
button:focus-visible, select:focus-visible { outline:2px solid var(--amber)!important; outline-offset:2px; }
</style>
"""
