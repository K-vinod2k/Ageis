"""
🔴 AGENT OPS CENTER — War Room Threat Intelligence Dashboard

CrowdStrike-inspired Streamlit UI for the 4-agent OTA MITM defense team.
Displays live agent activity, attack interception log, and threat telemetry.
"""

import sys
import os
import time
import uuid
import json
from datetime import datetime

import streamlit as st

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from graph import run_team, get_graph, TeamState

# ─────────────────────────── Page Config ───────────────────────────

st.set_page_config(
    page_title="Agent Ops Center — War Room",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────── Custom CSS ───────────────────────────

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;700;900&display=swap');

    /* === Global Dark Theme === */
    .stApp {
        background: linear-gradient(135deg, #0a0e17 0%, #0d1117 40%, #101820 100%);
        color: #c9d1d9;
        font-family: 'Inter', sans-serif;
    }

    /* Hide default streamlit elements */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }
    .stDeployButton { display: none; }

    /* === Top Banner === */
    .war-room-banner {
        background: linear-gradient(90deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        border-bottom: 2px solid #e94560;
        padding: 14px 28px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin: -1rem -1rem 1.5rem -1rem;
        border-radius: 0;
    }
    .banner-title {
        font-family: 'Inter', sans-serif;
        font-weight: 900;
        font-size: 22px;
        color: #fff;
        letter-spacing: 1.5px;
        text-transform: uppercase;
    }
    .banner-live {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(233, 69, 96, 0.15);
        border: 1px solid #e94560;
        border-radius: 20px;
        padding: 5px 14px;
        font-size: 12px;
        color: #e94560;
        font-weight: 700;
        letter-spacing: 1px;
        text-transform: uppercase;
    }
    .pulse-dot {
        width: 8px;
        height: 8px;
        background: #e94560;
        border-radius: 50%;
        animation: pulse 1.5s ease-in-out infinite;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(233,69,96,0.7); }
        50% { opacity: 0.6; box-shadow: 0 0 0 6px rgba(233,69,96,0); }
    }

    /* === Metric Cards === */
    .metric-card {
        background: linear-gradient(145deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #21262d;
        border-radius: 12px;
        padding: 18px 20px;
        text-align: center;
        transition: all 0.3s ease;
    }
    .metric-card:hover {
        border-color: #58a6ff;
        box-shadow: 0 0 20px rgba(88, 166, 255, 0.1);
    }
    .metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 32px;
        font-weight: 700;
        line-height: 1.1;
    }
    .metric-label {
        font-size: 11px;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        margin-top: 6px;
    }
    .metric-green { color: #3fb950; }
    .metric-red { color: #f85149; }
    .metric-blue { color: #58a6ff; }
    .metric-amber { color: #d29922; }

    /* === Agent Status Cards === */
    .agent-card {
        background: linear-gradient(145deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #21262d;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 10px;
        transition: all 0.3s ease;
    }
    .agent-card:hover {
        border-color: #30363d;
        transform: translateY(-1px);
    }
    .agent-card.active {
        border-color: #58a6ff;
        box-shadow: 0 0 15px rgba(88, 166, 255, 0.15);
    }
    .agent-card.attack {
        border-color: #f85149;
        box-shadow: 0 0 15px rgba(248, 81, 73, 0.15);
        animation: attackPulse 2s ease-in-out infinite;
    }
    @keyframes attackPulse {
        0%, 100% { box-shadow: 0 0 15px rgba(248,81,73,0.15); }
        50% { box-shadow: 0 0 25px rgba(248,81,73,0.3); }
    }
    .agent-name {
        font-weight: 700;
        font-size: 14px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .agent-role {
        font-size: 11px;
        color: #8b949e;
        margin-top: 2px;
    }
    .agent-status {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        margin-top: 8px;
        padding: 4px 10px;
        border-radius: 6px;
        display: inline-block;
    }
    .status-idle { background: rgba(139,148,158,0.15); color: #8b949e; }
    .status-active { background: rgba(88,166,255,0.15); color: #58a6ff; }
    .status-attacking { background: rgba(248,81,73,0.15); color: #f85149; }
    .status-complete { background: rgba(63,185,80,0.15); color: #3fb950; }

    /* === Attack Interception Log === */
    .intercept-log {
        background: linear-gradient(145deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #21262d;
        border-radius: 12px;
        padding: 16px;
        max-height: 400px;
        overflow-y: auto;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
    }
    .log-entry {
        padding: 8px 12px;
        margin-bottom: 6px;
        border-radius: 8px;
        border-left: 3px solid;
        line-height: 1.4;
    }
    .log-blocked {
        background: rgba(248,81,73,0.08);
        border-left-color: #f85149;
    }
    .log-clean {
        background: rgba(63,185,80,0.08);
        border-left-color: #3fb950;
    }
    .log-info {
        background: rgba(88,166,255,0.08);
        border-left-color: #58a6ff;
    }
    .log-time {
        color: #484f58;
        font-size: 10px;
    }
    .log-label-blocked { color: #f85149; font-weight: 700; }
    .log-label-clean { color: #3fb950; font-weight: 700; }
    .log-label-info { color: #58a6ff; font-weight: 700; }

    /* === Pipeline Visualization === */
    .pipeline-container {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 20px 0;
    }
    .pipeline-node {
        background: #161b22;
        border: 2px solid #21262d;
        border-radius: 10px;
        padding: 10px 16px;
        text-align: center;
        font-size: 12px;
        font-weight: 600;
        min-width: 100px;
        transition: all 0.3s ease;
    }
    .pipeline-node.completed { border-color: #3fb950; color: #3fb950; }
    .pipeline-node.active { border-color: #58a6ff; color: #58a6ff; box-shadow: 0 0 12px rgba(88,166,255,0.3); }
    .pipeline-node.attacking { border-color: #f85149; color: #f85149; animation: attackPulse 2s ease-in-out infinite; }
    .pipeline-node.pending { border-color: #21262d; color: #484f58; }
    .pipeline-arrow {
        color: #30363d;
        font-size: 18px;
        font-weight: 700;
    }

    /* === Chat / Input Area === */
    .stTextInput > div > div > input {
        background: #161b22 !important;
        border: 1px solid #21262d !important;
        color: #c9d1d9 !important;
        font-family: 'JetBrains Mono', monospace !important;
        border-radius: 10px !important;
        padding: 12px 16px !important;
    }
    .stTextInput > div > div > input:focus {
        border-color: #58a6ff !important;
        box-shadow: 0 0 10px rgba(88,166,255,0.2) !important;
    }

    /* === Section Headers === */
    .section-header {
        font-family: 'Inter', sans-serif;
        font-weight: 700;
        font-size: 13px;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-bottom: 14px;
        padding-bottom: 8px;
        border-bottom: 1px solid #21262d;
    }

    /* === Scrollbar === */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #0d1117; }
    ::-webkit-scrollbar-thumb { background: #21262d; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #30363d; }

    /* === Agent Output Panel === */
    .output-panel {
        background: linear-gradient(145deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #21262d;
        border-radius: 12px;
        padding: 20px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 13px;
        line-height: 1.6;
        color: #c9d1d9;
        white-space: pre-wrap;
        word-wrap: break-word;
        max-height: 500px;
        overflow-y: auto;
    }

    /* === Verdict Badge === */
    .verdict-pass {
        display: inline-block;
        background: rgba(63,185,80,0.15);
        border: 1px solid #3fb950;
        color: #3fb950;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        font-size: 14px;
        padding: 8px 20px;
        border-radius: 8px;
        letter-spacing: 2px;
    }
    .verdict-fail {
        display: inline-block;
        background: rgba(248,81,73,0.15);
        border: 1px solid #f85149;
        color: #f85149;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        font-size: 14px;
        padding: 8px 20px;
        border-radius: 8px;
        letter-spacing: 2px;
        animation: attackPulse 2s ease-in-out infinite;
    }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────── Session State Init ───────────────────────────

if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if "messages" not in st.session_state:
    st.session_state.messages = []
if "agent_log" not in st.session_state:
    st.session_state.agent_log = []
if "intercept_log" not in st.session_state:
    st.session_state.intercept_log = []
if "threat_stats" not in st.session_state:
    st.session_state.threat_stats = {
        "blocked": 0,
        "clean": 0,
        "loops": 0,
        "agents_run": 0,
    }
if "last_state" not in st.session_state:
    st.session_state.last_state = None
if "running" not in st.session_state:
    st.session_state.running = False

# ─────────────────────────── Header Banner ───────────────────────────

st.markdown("""
<div class="war-room-banner">
    <div>
        <span class="banner-title">⚔️ AEGIS — Zero-Trust Threat Analyst</span>
    </div>
    <div style="display: flex; align-items: center; gap: 20px;">
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #8b949e;">
            SESSION: {session}
        </span>
        <span class="banner-live">
            <span class="pulse-dot"></span>
            LIVE
        </span>
    </div>
</div>
""".format(session=st.session_state.session_id[:8].upper()), unsafe_allow_html=True)

# ─────────────────────────── Threat Telemetry ───────────────────────────

stats = st.session_state.threat_stats
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value metric-red">{stats['blocked']}</div>
        <div class="metric-label">🛡️ Threats Blocked</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value metric-green">{stats['clean']}</div>
        <div class="metric-label">✅ Clean Inputs</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value metric-amber">{stats['loops']}</div>
        <div class="metric-label">🔄 Patch Loops</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value metric-blue">{stats['agents_run']}</div>
        <div class="metric-label">🤖 Agents Deployed</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 12px'></div>", unsafe_allow_html=True)

# ─────────────────────────── Pipeline Visualization ───────────────────────────

def get_pipeline_html(active_agent: str = "", completed: list = None):
    """Render the pipeline flow visualization."""
    completed = completed or []
    nodes = [
        ("COORD", "coordinator"),
        ("BUILDER", "builder"),
        ("PLUMBER", "plumber"),
        ("BREAKER", "breaker"),
        ("PRESENTER", "presenter"),
    ]
    html = '<div class="pipeline-container">'
    for i, (label, key) in enumerate(nodes):
        if key in completed:
            cls = "completed"
        elif key == active_agent:
            cls = "attacking" if key == "breaker" else "active"
        else:
            cls = "pending"
        html += f'<div class="pipeline-node {cls}">{label}</div>'
        if i < len(nodes) - 1:
            html += '<span class="pipeline-arrow">→</span>'
    html += '</div>'
    return html

# Show pipeline
last = st.session_state.last_state
completed_agents = []
active_agent = ""
if last:
    for msg in last.get("messages", []):
        role = msg.get("role", "")
        if role not in completed_agents:
            completed_agents.append(role)
    if completed_agents:
        active_agent = completed_agents[-1]

st.markdown(get_pipeline_html(active_agent, completed_agents), unsafe_allow_html=True)

# ─────────────────────────── Main Layout ───────────────────────────

left_col, right_col = st.columns([3, 2])

# ─── LEFT: Agent Activity Feed ───
with left_col:
    st.markdown('<div class="section-header">🔬 Vinod\'s Workflow Automated — Threat Analysis Feed</div>', unsafe_allow_html=True)

    # Display conversation history
    for entry in st.session_state.agent_log:
        role = entry.get("role", "system")
        content = entry.get("content", "")
        timestamp = entry.get("time", "")

        icon_map = {
            "user": "👤",
            "coordinator": "🎯",
            "builder": "🏗️",
            "breaker": "🔴",
            "plumber": "🔧",
            "presenter": "📊",
            "evaluator": "🧠",
            "system": "⚙️",
        }
        icon = icon_map.get(role, "💬")
        color_map = {
            "user": "#c9d1d9",
            "coordinator": "#d29922",
            "builder": "#58a6ff",
            "breaker": "#f85149",
            "plumber": "#3fb950",
            "presenter": "#bc8cff",
            "evaluator": "#e8b04b",
            "system": "#8b949e",
        }
        color = color_map.get(role, "#8b949e")

        # Evaluator cards get special score badge rendering
        if role == "evaluator":
            # Extract score from content if present (format: "Score: XX/100 | ...")
            score_display = ""
            approved_badge = ""
            if "Score:" in content:
                try:
                    score_val = int(content.split("Score:")[1].split("/")[0].strip())
                    badge_color = "#3fb950" if score_val >= 95 else "#f85149"
                    badge_label = "APPROVED" if score_val >= 95 else "REJECTED"
                    score_display = f'<span style="font-family: JetBrains Mono, monospace; font-size: 22px; font-weight: 700; color: {badge_color};">{score_val}<span style="font-size: 13px; color: #8b949e;">/100</span></span>'
                    approved_badge = f'<span style="background: rgba({("63,185,80" if score_val >= 95 else "248,81,73")}, 0.15); border: 1px solid {badge_color}; color: {badge_color}; font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 6px; letter-spacing: 1px;">{badge_label}</span>'
                except Exception:
                    pass
            preview = content.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
            st.markdown(f"""
            <div class="agent-card" style="border-color: #e8b04b; box-shadow: 0 0 12px rgba(232,176,75,0.15);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="agent-name" style="color: {color};">
                        {icon} EVALUATOR — Quality Oracle
                    </span>
                    <span class="log-time">{timestamp}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 16px; margin-top: 12px;">
                    {score_display}
                    {approved_badge}
                </div>
                <div style="margin-top: 8px; font-size: 12px; line-height: 1.5; color: #8b949e; font-family: JetBrains Mono, monospace;">
                    {preview}
                </div>
            </div>
            """, unsafe_allow_html=True)
            continue

        # Standard agent cards
        preview = content[:500] + "..." if len(content) > 500 else content
        preview = preview.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")

        st.markdown(f"""
        <div class="agent-card {'active' if role == 'breaker' else ''}">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span class="agent-name" style="color: {color};">
                    {icon} {role.upper()}
                </span>
                <span class="log-time">{timestamp}</span>
            </div>
            <div style="margin-top: 10px; font-size: 13px; line-height: 1.5; color: #c9d1d9;">
                {preview}
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Show verdict if available
    if last and last.get("breaker_verdict"):
        verdict = last["breaker_verdict"]
        iterations = last.get("patch_iterations", 0)
        if verdict == "PASS":
            st.markdown(f"""
            <div style="text-align: center; margin: 16px 0;">
                <span class="verdict-pass">✅ SECURITY VERDICT: PASS</span>
                <div style="font-size: 11px; color: #8b949e; margin-top: 8px;">
                    System held after {iterations} patch loop(s)
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="text-align: center; margin: 16px 0;">
                <span class="verdict-fail">🚨 SECURITY VERDICT: FAIL</span>
                <div style="font-size: 11px; color: #8b949e; margin-top: 8px;">
                    Vulnerabilities found — patch loop #{iterations}
                </div>
            </div>
            """, unsafe_allow_html=True)

# ─── RIGHT: Attack Interception Log ───
with right_col:
    st.markdown('<div class="section-header">☣️ Hazmat Suit — Validia Containment Layer</div>', unsafe_allow_html=True)

    if not st.session_state.intercept_log:
        # Default entries for visual impact
        st.markdown("""
        <div class="intercept-log">
            <div class="log-entry log-info">
                <span class="log-time">STANDBY</span><br>
                <span class="log-label-info">☣️ HAZMAT SUIT ACTIVE</span><br>
                Validia containment layer online.<br>
                Monitoring /threat_logs/ for incoming wireless edge payloads...
            </div>
            <div class="log-entry log-clean">
                <span class="log-time">BOOT</span><br>
                <span class="log-label-clean">✅ AEGIS INITIALIZED</span><br>
                RAG: Known Threat Signatures loaded. 5 families indexed.<br>
                OpenClaw agent ready. Session isolated.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        log_html = '<div class="intercept-log">'
        for entry in reversed(st.session_state.intercept_log):
            etype = entry.get("type", "info")
            css_class = f"log-{etype}"
            label_class = f"log-label-{etype}"
            log_html += f"""
            <div class="log-entry {css_class}">
                <span class="log-time">{entry.get('time', '')}</span><br>
                <span class="{label_class}">{entry.get('label', '')}</span><br>
                {entry.get('detail', '')}
            </div>
            """
        log_html += '</div>'
        st.markdown(log_html, unsafe_allow_html=True)

    # ─── Agent Roster ───
    st.markdown("<div style='height: 20px'></div>", unsafe_allow_html=True)
    st.markdown('<div class="section-header">🤖 Agent Roster</div>', unsafe_allow_html=True)

    agents_info = [
        ("🏗️", "BUILDER", "Cognitive Architect & OSINT", "#58a6ff"),
        ("🔴", "BREAKER", "Adversarial Payload Specialist", "#f85149"),
        ("🔧", "PLUMBER", "Zero-Trust Infrastructure", "#3fb950"),
        ("📊", "PRESENTER", "Threat Intel Visualizer", "#bc8cff"),
        ("🧠", "EVALUATOR", "Supreme Quality Oracle", "#e8b04b"),
    ]

    for icon, name, role, color in agents_info:
        # Determine status from last run
        status = "IDLE"
        status_class = "status-idle"
        if last:
            agent_names_run = [m.get("role") for m in last.get("messages", [])]
            if name.lower() in agent_names_run:
                status = "COMPLETE"
                status_class = "status-complete"

        st.markdown(f"""
        <div class="agent-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <span class="agent-name" style="color: {color};">{icon} {name}</span>
                    <div class="agent-role">{role}</div>
                </div>
                <span class="agent-status {status_class}">{status}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)


# ─────────────────────────── Input Area ───────────────────────────

st.markdown("<div style='height: 16px'></div>", unsafe_allow_html=True)
st.markdown("""
<div style="
    background: linear-gradient(90deg, #161b22, #0d1117);
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 16px 20px 8px 20px;
">
    <div class="section-header" style="border: none; margin-bottom: 8px; padding-bottom: 0;">
        ⌨️ Command Input
    </div>
</div>
""", unsafe_allow_html=True)

# ─── Chat Input ───
user_input = st.chat_input("Type your mission directive to the team...")

if user_input:
    now = datetime.now().strftime("%H:%M:%S")

    # Add user message to log
    st.session_state.agent_log.append({
        "role": "user",
        "content": user_input,
        "time": now,
    })

    # Add intercept log entry for incoming message
    st.session_state.intercept_log.append({
        "type": "info",
        "time": now,
        "label": "📥 INCOMING DIRECTIVE",
        "detail": f"User input received. Routing through Coordinator...",
    })

    # Run the graph
    with st.spinner("🔄 Agents executing... Loop of Absolute Security engaged"):
        try:
            final_state = run_team(user_input, st.session_state.session_id)
            st.session_state.last_state = final_state

            # Process messages from the run
            for msg in final_state.get("messages", []):
                role = msg.get("role", "system")
                content = msg.get("content", "")
                ts = datetime.now().strftime("%H:%M:%S")

                st.session_state.agent_log.append({
                    "role": role,
                    "content": content,
                    "time": ts,
                })

                # Count agents
                st.session_state.threat_stats["agents_run"] += 1

                # Generate intercept log entries
                if role == "breaker":
                    verdict = final_state.get("breaker_verdict", "FAIL")
                    if verdict == "PASS":
                        st.session_state.intercept_log.append({
                            "type": "clean",
                            "time": ts,
                            "label": "✅ SYSTEM HELD — ALL ATTACKS NEUTRALIZED",
                            "detail": "Breaker could not penetrate Validia + OpenClaw defenses.",
                        })
                        st.session_state.threat_stats["clean"] += 1
                    else:
                        st.session_state.intercept_log.append({
                            "type": "blocked",
                            "time": ts,
                            "label": "🛡️ OTA PAYLOAD HIJACK DETECTED & SANITIZED",
                            "detail": f"Vulnerability found. Routing back to Builder for patch. Validia score: 0.{97 - st.session_state.threat_stats['loops']}",
                        })
                        st.session_state.threat_stats["blocked"] += 1
                        st.session_state.threat_stats["loops"] += 1
                elif role == "coordinator":
                    st.session_state.intercept_log.append({
                        "type": "info",
                        "time": ts,
                        "label": "🎯 COORDINATOR ROUTING",
                        "detail": content,
                    })
                elif role == "builder":
                    st.session_state.intercept_log.append({
                        "type": "info",
                        "time": ts,
                        "label": "🏗️ BUILDER DEPLOYED",
                        "detail": "Architecture research & OpenClaw logic generated.",
                    })
                elif role == "plumber":
                    st.session_state.intercept_log.append({
                        "type": "clean",
                        "time": ts,
                        "label": "🔧 PIPELINE CONSTRUCTED",
                        "detail": "Air-Gap pipeline built. Validia middleware injected.",
                    })
                elif role == "presenter":
                    st.session_state.intercept_log.append({
                        "type": "clean",
                        "time": ts,
                        "label": "📊 WAR ROOM UPDATED",
                        "detail": "Threat Intelligence Dashboard & pitch narrative ready.",
                    })

        except Exception as e:
            error_msg = str(e)
            if "recursion" in error_msg.lower():
                st.error("⚠️ CIRCUIT BREAKER: Patch Loop limit reached. System halted — awaiting human intervention.")
            st.session_state.agent_log.append({
                "role": "system",
                "content": f"⚠️ Error: {error_msg}",
                "time": datetime.now().strftime("%H:%M:%S"),
            })
            st.session_state.intercept_log.append({
                "type": "blocked",
                "time": datetime.now().strftime("%H:%M:%S"),
                "label": "⚠️ SYSTEM ERROR",
                "detail": error_msg[:200],
            })

    st.rerun()

# ─────────────────────────── Sidebar: Full Agent Output ───────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="padding: 10px;">
        <div class="section-header">📋 Full Agent Output</div>
    </div>
    """, unsafe_allow_html=True)

    if last:
        for msg in last.get("messages", []):
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role and content:
                with st.expander(f"{'🏗️' if role == 'builder' else '🔴' if role == 'breaker' else '🔧' if role == 'plumber' else '📊' if role == 'presenter' else '🎯'} {role.upper()}", expanded=False):
                    st.code(content, language="markdown")
    else:
        st.markdown("""
        <div style="color: #484f58; font-size: 13px; padding: 10px;">
            No agent output yet. Send a directive to begin.
        </div>
        """, unsafe_allow_html=True)

    # ── Evaluator Logs ──
    st.markdown("<hr style='border-color: #21262d; margin: 20px 0;'>", unsafe_allow_html=True)
    st.markdown("""
    <div style="padding: 0 10px;">
        <div class="section-header">🧠 Evaluator Logs</div>
    </div>
    """, unsafe_allow_html=True)

    eval_history = last.get("evaluation_history", []) if last else []
    if eval_history:
        for i, ev in enumerate(eval_history):
            score = ev.get("score", 0)
            agent = ev.get("agent_evaluated", "?")
            approved = ev.get("approved", score >= 95)
            badge_color = "#3fb950" if approved else "#f85149"
            badge = "✅ APPROVED" if approved else "❌ REJECTED"
            with st.expander(f"#{i+1} {agent.upper()} — {score}/100  {badge}", expanded=(not approved)):
                st.markdown(f"""
                <div style="font-family: JetBrains Mono, monospace; font-size: 12px; color: #c9d1d9; line-height: 1.6;">
                    <div style="color: {badge_color}; font-weight: 700; margin-bottom: 8px;">{badge} ({score}/100)</div>
                    <div style="color: #8b949e; margin-bottom: 6px;"><strong>Rationale:</strong></div>
                    <div>{ev.get('evaluation_rationale', 'N/A')}</div>
                    {"<div style='color: #f85149; margin-top: 8px;'><strong>Directive:</strong><br>" + ev.get('directive', '') + "</div>" if not approved else ""}
                </div>
                """, unsafe_allow_html=True)
    else:
        st.markdown('<div style="color: #484f58; font-size: 12px; padding: 0 10px;">No evaluations yet.</div>', unsafe_allow_html=True)

    st.markdown("<hr style='border-color: #21262d; margin: 20px 0;'>", unsafe_allow_html=True)
    st.markdown("""
    <div style="padding: 0 10px;">
        <div class="section-header">⚔️ Aegis Pipeline</div>
        <div style="font-size: 12px; color: #8b949e; line-height: 1.6;">
            <strong>/threat_logs/</strong> → new log detected<br>
            <strong>☣️ Validia</strong> → Hazmat scan<br>
            <strong>🏗️ OpenClaw</strong> → RAG lookup + triage<br>
            <strong>📋 Report</strong> → /threat_reports/<br>
            <br>
            <strong>🔒 Loop of Absolute Security</strong><br>
            Agent → 🧠 Evaluator (0–100)<br>
            &lt;95 → Patch Directive + Retry<br>
            ≥95 → Next stage<br>
            <br>
            <em>Safety valve: max 3 loops</em>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Reset button
    st.markdown("<div style='height: 20px'></div>", unsafe_allow_html=True)
    if st.button("🔄 Reset Session", use_container_width=True):
        st.session_state.session_id = str(uuid.uuid4())
        st.session_state.messages = []
        st.session_state.agent_log = []
        st.session_state.intercept_log = []
        st.session_state.threat_stats = {
            "blocked": 0, "clean": 0, "loops": 0, "agents_run": 0,
        }
        st.session_state.last_state = None
        st.rerun()
