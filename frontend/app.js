const API_URL = "http://127.0.0.1:8000";
const WS_URL = "ws://127.0.0.1:8000/ws/logs";

let ws;
let isSuricataRunning = false;
let isYaraRunning = false;

const suriLogs = document.getElementById('suricata-logs');
const yaraLogs = document.getElementById('yara-logs');
const wsStatus = document.getElementById('ws-status');

function connectWS() {
    ws = new WebSocket(WS_URL);
    
    ws.onopen = () => {
        wsStatus.textContent = "🟢 Live Connected";
        wsStatus.className = "online";
        fetchStatus();
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        const msg = `[${data.timestamp}] ${data.message}`;
        const p = document.createElement('div');
        p.textContent = msg;
        p.style.marginBottom = "5px";
        
        if (data.source === 'suricata') {
            suriLogs.appendChild(p);
            suriLogs.scrollTop = suriLogs.scrollHeight;
        } else if (data.source === 'yara') {
            yaraLogs.appendChild(p);
            yaraLogs.scrollTop = yaraLogs.scrollHeight;
        }
    };

    ws.onclose = () => {
        wsStatus.textContent = "🔴 Disconnected - Retrying...";
        wsStatus.className = "offline";
        setTimeout(connectWS, 3000);
    };
    
    ws.onerror = (err) => {
        console.error("WebSocket Error:", err);
        ws.close();
    };
}

async function fetchStatus() {
    try {
        const res = await fetch(`${API_URL}/api/status`);
        const data = await res.json();
        updateSuricataUI(data.suricata_running);
        updateYaraUI(data.yara_running);
    } catch (e) {
        console.error("API Offline", e);
    }
}

async function toggleSuricata() {
    const endpoint = isSuricataRunning ? "/api/suricata/stop" : "/api/suricata/start";
    try {
        await fetch(`${API_URL}${endpoint}`, { method: 'POST' });
        updateSuricataUI(!isSuricataRunning);
    } catch (e) {
        alert("백엔드 서버에 연결할 수 없습니다. (Python 서버가 켜져있는지 확인하세요)");
    }
}

async function toggleYara() {
    const endpoint = isYaraRunning ? "/api/yara/stop" : "/api/yara/start";
    try {
        await fetch(`${API_URL}${endpoint}`, { method: 'POST' });
        updateYaraUI(!isYaraRunning);
    } catch (e) {
        alert("백엔드 서버에 연결할 수 없습니다. (Python 서버가 켜져있는지 확인하세요)");
    }
}

function updateSuricataUI(isRunning) {
    isSuricataRunning = isRunning;
    const btn = document.getElementById('btn-suricata');
    if (isRunning) {
        btn.textContent = "⏹️ Stop Suricata (F1)";
        btn.classList.add("active-suri");
    } else {
        btn.textContent = "🚀 Start Suricata (F1)";
        btn.classList.remove("active-suri");
    }
}

function updateYaraUI(isRunning) {
    isYaraRunning = isRunning;
    const btn = document.getElementById('btn-yara');
    if (isRunning) {
        btn.textContent = "⏹️ Stop Yara (F2)";
        btn.classList.add("active-yara");
    } else {
        btn.textContent = "🦠 Start Yara (F2)";
        btn.classList.remove("active-yara");
    }
}

// Modal Logic
const modal = document.getElementById('log-modal');
const select = document.getElementById('log-date-select');
const historyLogs = document.getElementById('historical-logs');

async function openLogViewer() {
    modal.style.display = "block";
    select.innerHTML = "<option>로딩 중...</option>";
    historyLogs.textContent = "";
    
    try {
        const res = await fetch(`${API_URL}/api/logs`);
        const data = await res.json();
        
        if (data.logs.length === 0) {
            select.innerHTML = "<option>기록 없음</option>";
            historyLogs.textContent = "저장된 탐지 기록이 없습니다.";
            return;
        }
        
        select.innerHTML = "";
        data.logs.forEach(date => {
            const opt = document.createElement('option');
            opt.value = date;
            opt.textContent = date;
            select.appendChild(opt);
        });
        
        fetchLogContent(); // load the first one
    } catch (e) {
        select.innerHTML = "<option>서버 연결 실패</option>";
        historyLogs.textContent = "백엔드 서버가 응답하지 않습니다.";
    }
}

async function fetchLogContent() {
    const date = select.value;
    if (!date || date === "기록 없음" || date === "서버 연결 실패") return;
    
    try {
        const res = await fetch(`${API_URL}/api/logs/${date}`);
        const data = await res.json();
        historyLogs.textContent = data.content;
    } catch (e) {
        historyLogs.textContent = "로그 내용을 불러오는데 실패했습니다.";
    }
}

function closeLogViewer() {
    modal.style.display = "none";
}

// Close modal if clicked outside
window.onclick = function(event) {
    if (event.target == modal) {
        closeLogViewer();
    }
}

// Hotkeys
document.addEventListener('keydown', (e) => {
    if (e.key === 'F1') { e.preventDefault(); toggleSuricata(); }
    if (e.key === 'F2') { e.preventDefault(); toggleYara(); }
    if (e.key === 'F3') { e.preventDefault(); openLogViewer(); }
});

// Init
suriLogs.innerHTML = "<div style='color: #8b949e'>대기 중... (F1을 눌러 시작하세요)</div>";
yaraLogs.innerHTML = "<div style='color: #8b949e'>대기 중... (F2를 눌러 시작하세요)</div>";
connectWS();
