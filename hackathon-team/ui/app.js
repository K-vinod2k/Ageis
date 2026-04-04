const sessionId = crypto.randomUUID().slice(0,8).toUpperCase();
document.getElementById("sessionIdDisplay").innerText = `SESSION: ${sessionId}`;

let stats = { blocked: 0, loops: 0, agents: 0, clean: 0 };
let fullSessionId = crypto.randomUUID();

const colorMap = {
    "user": "#c9d1d9", "coordinator": "#d29922", "builder": "#58a6ff",
    "breaker": "#f85149", "plumber": "#3fb950", "presenter": "#bc8cff",
    "evaluator": "#e8b04b", "system": "#8b949e"
};
const iconMap = {
    "user": "👤", "coordinator": "🎯", "builder": "🏗️", "breaker": "🔴",
    "plumber": "🔧", "presenter": "📊", "evaluator": "🧠", "system": "⚙️"
};

const sendBtn = document.getElementById('sendBtn');
const chatInput = document.getElementById('chatInput');
const loadingInd = document.getElementById('loadingIndicator');

chatInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendMission();
});
sendBtn.addEventListener('click', sendMission);

async function sendMission() {
    const text = chatInput.value.trim();
    if (!text) return;
    
    chatInput.value = '';
    chatInput.disabled = true;
    sendBtn.disabled = true;
    loadingInd.style.display = 'block';

    appendAgentLog("user", text);
    
    // Animate roster
    document.querySelectorAll('.status-badge').forEach(b => {
        b.className = 'status-badge status-active';
        b.innerText = 'WORKING';
    });
    document.getElementById('badge-breaker').className = 'status-badge status-attacking';
    document.getElementById('badge-breaker').innerText = 'ATTACKING';

    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ message: text, session_id: fullSessionId })
        });
        
        const data = await response.json();
        
        document.querySelectorAll('.empty-state').forEach(e => e.remove());

        if (response.ok) {
            stats.agents += data.messages.length;
            stats.loops += data.iterations;
            updateMetrics();

            data.messages.forEach(msg => {
                appendAgentLog(msg.role, msg.content);
            });
            
            if (data.verdict === "PASS") {
                appendInterceptLog('info', '✅ SYSTEM HELD', `Breaker failed. Pipeline secured after ${data.iterations} loops.`);
            } else {
                appendInterceptLog('blocked', '🚨 SYSTEM BREACHED', `Vulnerabilities persist after ${data.iterations} loops.`);
            }

        } else {
            appendAgentLog("system", `System Error: ${data.error}`);
            appendInterceptLog('blocked', '⚠️ ERROR', data.error);
        }
    } catch (err) {
        appendAgentLog("system", `Network Error: ${err.message}`);
    } finally {
        chatInput.disabled = false;
        sendBtn.disabled = false;
        loadingInd.style.display = 'none';
        chatInput.focus();
        
        // Reset Roster
        document.querySelectorAll('.status-badge').forEach(b => {
            b.className = 'status-badge';
            b.innerText = 'IDLE';
        });
    }
}

function appendAgentLog(role, content) {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const col = colorMap[role] || "#c9d1d9";
    const ico = iconMap[role] || "💬";
    
    let formattedContent = escapeHtml(content);
    
    // Fast evaluator check
    if(role === 'evaluator' && content.includes('Score:')) {
        formattedContent = `<div style="padding: 10px; background: rgba(232,176,75,0.1); border-radius: 6px; border: 1px solid #e8b04b;">${formattedContent}</div>`;
    } else {
        // truncate huge messages visually
        if(formattedContent.length > 800) {
            formattedContent = formattedContent.substring(0, 800) + '...\n\n[TRUNCATED FOR UI]';
        }
    }
    
    const html = `
        <div class="agent-card" style="border-color: ${col}40;">
            <div class="agent-card-header">
                <span class="agent-card-title" style="color: ${col};">${ico} ${role.toUpperCase()}</span>
                <span class="agent-card-time">${time}</span>
            </div>
            <div class="agent-card-content">${formattedContent}</div>
        </div>
    `;
    const cont = document.getElementById('agentLogContainer');
    cont.insertAdjacentHTML('beforeend', html);
    cont.scrollTo({ top: cont.scrollHeight, behavior: 'smooth' });
}

function appendInterceptLog(type, label, detail) {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const cont = document.getElementById('interceptLogContainer');
    
    const html = `
        <div class="log-entry log-${type}">
            <span class="log-time">${time}</span><br>
            <span class="log-label-${type}">${label}</span><br>
            ${escapeHtml(detail)}
        </div>
    `;
    cont.insertAdjacentHTML('afterbegin', html); // insert top
}

async function fetchTelemetry() {
    try {
        const res = await fetch('/telemetry');
        const data = await res.json();
        
        if (data.total !== undefined) {
            stats.blocked = data.blocked;
            stats.clean = data.clean;
            updateMetrics();
            
            // Rebuild intercept log
            const cont = document.getElementById('interceptLogContainer');
            cont.innerHTML = '';
            data.events.slice().reverse().forEach(ev => {
                let isBlocked = ev.blocked;
                appendInterceptLog(
                    isBlocked ? 'blocked' : 'info', 
                    isBlocked ? '🛡️ THREAT BLOCKED' : '✅ PAYLOAD FORWARDED', 
                    `Score: ${ev.threat_score} | ${ev.reason || ''}`
                );
            });
        }
    } catch(e) {}
}

function updateMetrics() {
    document.getElementById('metric-blocked').innerText = stats.blocked;
    document.getElementById('metric-loops').innerText = stats.loops;
    document.getElementById('metric-agents').innerText = stats.agents;
    document.getElementById('metric-clean').innerText = stats.clean;
}

function escapeHtml(text) {
    return text.toString()
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;");
}

// Poll telemetry every 3 seconds
setInterval(fetchTelemetry, 3000);
fetchTelemetry();
