/* ============================================================
 * EDR 통합 보안 대시보드 - app.js (v4 - PRODUCTION)
 * 백엔드 완전 연동 + 자동 대응 정책 작동
 * - 인증: X-Session-Token 헤더 (Bearer 아님)
 * - 자동 대응: WebSocket response 메시지를 파싱해서 토글 따라 실행
 * - 데모 모드 OFF (완성형)
 * ============================================================ */

const API_URL = window.location.origin;
const WS_URL  = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/logs`;
const DEMO_MODE = false; // 프로덕션: 항상 false

let ws = null;
let wsReconnectTimer = null;
let authMode = 'login';
let authToken = localStorage.getItem('edrSessionToken') || '';
let currentUsername = localStorage.getItem('edrUsername') || '';
let currentUserIsAdmin = localStorage.getItem('edrIsAdmin') === 'true';
let currentView = 'dashboard';

let isWazuhRunning = false;
let isYaraRunning = false;
let isYaraScanRunning = false;
let wazuhRuntime = null;
let wazuhCount = 0;
let yaraCount = 0;
let responseCount = 0;
let lastWazuhTs = null;
let lastYaraTs = null;
let wazuhLogPath = '';
let yaraTargetPaths = [];
let incidentRefreshTimer = null;
let statusRefreshTimer = null;
let incidentViewDate = null;
const selectedScanDirs = new Set();
const processedIncidentIds = new Set(); // 자동 대응 중복 방지

/* ───── 통계 / 메모리 ───── */
const stats = {
    high: 0, medium: 0, low: 0,
    total: 0,
    events: [],
    incidents: [],
    notifications: [],
    autoActions: []  // 자동 대응 실행 이력
};
const timelineFilter = { sev: 'all', src: 'all', q: '' };
let notifFilter = 'all';
let desktopNotifEnabled = false;

/* ───── 자동 대응 정책 (localStorage에 저장) ───── */
const autoPolicy = {
    quarantine: localStorage.getItem('edrPolicyAutoQuarantine') === 'true',
    blockIp:    localStorage.getItem('edrPolicyAutoBlockIp') === 'true',
    terminate:  localStorage.getItem('edrPolicyAutoTerminate') === 'true'
};

/* ───── DOM 헬퍼 ───── */
const $ = (id) => document.getElementById(id);
const $$ = (sel) => document.querySelectorAll(sel);

/* ============================================================
 * AUTH
 * ============================================================ */
function setAuthFeedback(msg, type = 'info') {
    $('auth-feedback').textContent = msg;
    $('auth-feedback').className = 'auth-feedback' + (type !== 'info' ? ' ' + type : '');
}
function switchAuthMode(mode) {
    authMode = mode;
    $('tab-login').classList.toggle('active', mode === 'login');
    $('tab-register').classList.toggle('active', mode === 'register');
    $('auth-submit').textContent = mode === 'login' ? '로그인' : '회원가입';
    setAuthFeedback(mode === 'login' ? '기본 관리자 계정: admin / admin1234' : '새 계정을 생성합니다.');
}
async function submitAuth() {
    const username = $('auth-username').value.trim();
    const password = $('auth-password').value;
    if (!username || !password) return setAuthFeedback('아이디와 비밀번호를 모두 입력해주세요.', 'error');
    const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
    try {
        const res = await fetch(API_URL + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) return setAuthFeedback(data.detail || '인증에 실패했습니다.', 'error');
        if (authMode === 'register') {
            setAuthFeedback('회원가입이 완료되었습니다. 로그인해주세요.', 'success');
            switchAuthMode('login');
            return;
        }
        // 백엔드 응답 형식에 따라 토큰 추출 (token / access_token / session_token)
        authToken = data.token || data.access_token || data.session_token || '';
        const userInfo = data.user || {};
        currentUsername = userInfo.username || data.username || username;
        currentUserIsAdmin = !!(userInfo.is_admin ?? data.is_admin);
        if (!authToken) {
            setAuthFeedback('서버 응답에 토큰이 없습니다.', 'error');
            return;
        }
        localStorage.setItem('edrSessionToken', authToken);
        localStorage.setItem('edrUsername', currentUsername);
        localStorage.setItem('edrIsAdmin', currentUserIsAdmin ? 'true' : 'false');
        enterApp();
    } catch (err) {
        setAuthFeedback('백엔드 서버에 연결할 수 없습니다. 백엔드가 실행 중인지 확인하세요.', 'error');
    }
}
function enterApp() {
    $('auth-shell').classList.add('app-hidden');
    $('app-shell').classList.remove('app-hidden');
    $('user-chip').textContent = (currentUsername || 'USER').toUpperCase();
    $('user-role').textContent = currentUserIsAdmin ? '관리자' : '사용자';
    $('set-username').textContent = currentUsername;
    $('set-role').textContent = currentUserIsAdmin ? '관리자 (admin)' : '일반 사용자';
    $('set-token').textContent = authToken ? authToken.slice(0, 12) + '...' : '―';
    if (currentUserIsAdmin) $('settings-admin-card').classList.remove('hidden');

    // 자동 대응 정책 토글 복원
    if ($('auto-quarantine')) $('auto-quarantine').checked = autoPolicy.quarantine;
    if ($('auto-block-ip')) $('auto-block-ip').checked = autoPolicy.blockIp;
    if ($('auto-terminate')) $('auto-terminate').checked = autoPolicy.terminate;
    bindPolicyToggles();

    incidentViewDate = todayISO();
    connectWS();
    fetchStatus();
    loadIncidents();
    renderDashboard();

    // 주기적 상태 폴링 (8초)
    if (statusRefreshTimer) clearInterval(statusRefreshTimer);
    statusRefreshTimer = setInterval(() => {
        if (!authToken) return;
        resetDailyIncidentStateIfNeeded();
        fetchStatus();
        // 위협 탐지 뷰에 있으면 인시던트도 갱신
        if (currentView === 'threats') loadIncidents();
    }, 8000);
}
async function logout() {
    if (authToken) {
        try { await fetchAuthed('/api/auth/logout', { method: 'POST' }); } catch (_) {}
    }
    localStorage.removeItem('edrSessionToken');
    localStorage.removeItem('edrUsername');
    localStorage.removeItem('edrIsAdmin');
    authToken = ''; currentUsername = ''; currentUserIsAdmin = false;
    if (statusRefreshTimer) clearInterval(statusRefreshTimer);
    if (ws) try { ws.close(); } catch (_) {}
    $('app-shell').classList.add('app-hidden');
    $('auth-shell').classList.remove('app-hidden');
    $('auth-username').value = ''; $('auth-password').value = '';
}

/* 🔑 핵심: X-Session-Token 헤더 사용 (Bearer 아님) */
function fetchAuthed(path, options = {}) {
    const opts = { ...options };
    opts.headers = {
        ...(opts.headers || {}),
        'X-Session-Token': authToken
    };
    return fetch(API_URL + path, opts);
}
async function readApiResponse(res) {
    const text = await res.text();
    if (!text) return {};
    try {
        return JSON.parse(text);
    } catch (_) {
        return {
            result_type: 'error',
            result_message: text || `HTTP ${res.status}`
        };
    }
}

/* ============================================================
 * WebSocket
 * ============================================================ */
function setWsStatus(connected) {
    $('ws-status-text').textContent = connected ? '실시간 연결됨' : '연결 안 됨';
    $('ws-status').parentElement.classList.toggle('on', connected);
    $('ws-status').classList.toggle('offline', !connected);
}
function connectWS() {
    if (!authToken) { setWsStatus(false); return; }
    if (ws) try { ws.close(); } catch (_) {}
    try {
        ws = new WebSocket(`${WS_URL}?token=${encodeURIComponent(authToken)}`);
    } catch (e) { setWsStatus(false); return; }

    ws.onopen = () => {
        setWsStatus(true);
        if (wsReconnectTimer) { clearTimeout(wsReconnectTimer); wsReconnectTimer = null; }
    };
    ws.onmessage = (event) => {
        try { handleLogEvent(JSON.parse(event.data)); }
        catch (e) { console.error('WS 파싱 오류', e); }
    };
    ws.onclose = () => {
        setWsStatus(false);
        if (authToken) {
            wsReconnectTimer = setTimeout(connectWS, 3000);
        }
    };
    ws.onerror = () => { try { ws.close(); } catch (_) {} };
}

/* WebSocket payload (백엔드 broadcast_log):
   { source: "wazuh"|"yara"|"response",
     message, timestamp: "HH:MM:SS", username } */
function handleLogEvent(data) {
    const sev = inferSeverity(data);
    const timeStr = data.timestamp || nowHMS();
    const ev = {
        id: 'ev_' + Math.random().toString(36).slice(2, 10),
        sev,
        source: data.source || 'system',
        title: extractTitle(data),
        message: data.message || '',
        username: data.username || '',
        host: extractHost(data) || data.username || 'localhost',
        time: timeStr,
        timestamp: timeStr,
        date: todayISO(),
        read: false,
        raw: data
    };

    stats.events.unshift(ev);
    if (stats.events.length > 500) stats.events.pop();
    stats.total++;
    if (sev === 'high') stats.high++;
    else if (sev === 'medium') stats.medium++;
    else stats.low++;

    if (ev.source === 'wazuh') { wazuhCount++; lastWazuhTs = timeStr; }
    else if (ev.source === 'yara') { yaraCount++; lastYaraTs = timeStr; }
    else if (ev.source === 'response') {
        responseCount++;
        scheduleIncidentRefresh();
        // 🤖 Response 메시지에서 자동 대응 트리거 검사
        checkAutoResponseTrigger(ev);
    }
    if (data.details && data.details.kind === 'incident_created') {
        scheduleIncidentRefresh();
    }

    appendToLogStream(ev);

    if (ev.source === 'yara' && /MATCH|DETECT|matched/i.test(ev.message)) {
        appendScanResult(ev);
    }
    if (ev.source === 'yara' && /Initial Yara scan complete/i.test(ev.message)) {
        isYaraScanRunning = false;
        const scanStatus = $('scan-status');
        if (scanStatus) {
            scanStatus.textContent = ev.message.replace(/^.*Initial Yara scan complete\.\s*/i, '') || '스캔 완료';
            scanStatus.classList.remove('running');
            scanStatus.classList.add('completed');
        }
        updateDeepScanStatus();
    }
    if (ev.source === 'yara' && /Stopping Yara deep scan/i.test(ev.message)) {
        isYaraScanRunning = false;
        const scanStatus = $('scan-status');
        if (scanStatus) {
            scanStatus.textContent = '중지됨';
            scanStatus.classList.remove('running', 'completed');
        }
        updateDeepScanStatus();
    }

    if (sev === 'high' || (sev === 'medium' && /MATCH|DETECT/i.test(ev.message))) {
        addNotification(ev);
    }

    if (currentView === 'dashboard') {
        refreshDashboardKPIs();
        renderDashboardTimeline();
        renderRecent();
        updateFeaturedDetection(stats.events[0]);
        refreshDashboardEngineState();
        refreshEngineBars();
    }
    if (currentView === 'timeline') renderTimelineView();
    if (currentView === 'realtime') refreshRealtimeStats();

    updateSidebarBadges();
}

function inferSeverity(data) {
    if (data.severity) return data.severity;
    const msg = data.message || '';
    if (/yara\s*(match|detect)|malware|trojan|ransom|cobalt|mimikatz|matched|risk\s*high|level\s*1[0-9]|level\s*[2-9][0-9]/i.test(msg)) return 'high';
    if (/suspicious|warning|powershell|encoded|registry|risk\s*medium|verify\s*hit|level\s*[4-9]/i.test(msg)) return 'medium';
    return 'low';
}
function extractTitle(data) {
    let msg = data.message || '이벤트';
    msg = msg.replace(/^\[[^\]]+\]\s*/, '');
    return msg.length > 90 ? msg.slice(0, 90) + '...' : msg;
}
function extractHost(data) {
    const m = (data.message || '').match(/host\s*[:=]\s*([\w\-\.]+)/i);
    return m ? m[1] : null;
}
function nowHMS() { return new Date().toTimeString().slice(0, 8); }
function todayISO() {
    const now = new Date();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    return `${now.getFullYear()}-${month}-${day}`;
}
function resetDailyIncidentStateIfNeeded() {
    const today = todayISO();
    if (!incidentViewDate) {
        incidentViewDate = today;
        return false;
    }
    if (incidentViewDate === today) return false;

    incidentViewDate = today;
    stats.incidents = [];
    processedIncidentIds.clear();
    updateSidebarBadges();
    refreshDashboardKPIs();
    refreshDashboardSummary();
    if (currentView === 'threats') renderIncidents();
    return true;
}
function shortPath(path) {
    if (!path) return '';
    const parts = String(path).split(/[\\/]/).filter(Boolean);
    if (parts.length <= 2) return String(path);
    return `${parts[0]}\\...\\${parts.slice(-2).join('\\')}`;
}
function formatBytes(bytes) {
    const value = Number(bytes);
    if (!Number.isFinite(value)) return '―';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = value;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit++;
    }
    return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}
function getYaraDetails(ev) {
    return (ev.raw && ev.raw.details && ev.raw.details.kind === 'yara_match') ? ev.raw.details : null;
}

/* ============================================================
 * 🤖 자동 대응 정책 (핵심 기능)
 * ============================================================ */
function bindPolicyToggles() {
    const aq = $('auto-quarantine');
    const ab = $('auto-block-ip');
    const at = $('auto-terminate');
    if (aq) aq.addEventListener('change', e => {
        autoPolicy.quarantine = e.target.checked;
        localStorage.setItem('edrPolicyAutoQuarantine', autoPolicy.quarantine);
        toast(autoPolicy.quarantine ? '자동 격리가 활성화되었습니다' : '자동 격리가 비활성화되었습니다',
              autoPolicy.quarantine ? 'success' : 'info');
    });
    if (ab) ab.addEventListener('change', e => {
        autoPolicy.blockIp = e.target.checked;
        localStorage.setItem('edrPolicyAutoBlockIp', autoPolicy.blockIp);
        toast(autoPolicy.blockIp ? '자동 IP 차단이 활성화되었습니다' : '자동 IP 차단이 비활성화되었습니다',
              autoPolicy.blockIp ? 'success' : 'info');
    });
    if (at) at.addEventListener('change', e => {
        autoPolicy.terminate = e.target.checked;
        localStorage.setItem('edrPolicyAutoTerminate', autoPolicy.terminate);
        toast(autoPolicy.terminate ? '자동 프로세스 종료가 활성화되었습니다' : '자동 프로세스 종료가 비활성화되었습니다',
              autoPolicy.terminate ? 'success' : 'info');
    });
}

/* Response 메시지 파싱:
   "[Response] Risk HIGH (85) | Suggested decision: QUARANTINE | ..." */
function checkAutoResponseTrigger(ev) {
    const m = (ev.message || '').match(/Suggested decision:\s*(QUARANTINE|TERMINATE_PROCESS|BLOCK_IP|KEEP)/i);
    if (!m) return;
    const suggested = m[1].toLowerCase();
    // 정책에 따라 자동 실행할지 결정
    const shouldExecute =
        (suggested === 'quarantine' && autoPolicy.quarantine) ||
        (suggested === 'block_ip' && autoPolicy.blockIp) ||
        (suggested === 'terminate_process' && autoPolicy.terminate);
    if (!shouldExecute) return;

    // 0.5초 후 인시던트 목록 받아와서 가장 최근 pending 인시던트에 액션 적용
    setTimeout(() => triggerAutoAction(suggested), 800);
}

async function triggerAutoAction(action) {
    if (!authToken) return;
    try {
        const res = await fetchAuthed('/api/incidents');
        if (!res.ok) return;
        const data = await res.json();
        const incidents = data.incidents || [];
        // 가장 최근의 pending 인시던트 + suggested_decision 일치 + 중복 안된 것 찾기
        const target = incidents.find(i =>
            i.status === 'pending' &&
            !i.decision &&
            !processedIncidentIds.has(i.id) &&
            (i.suggested_decision || '').toLowerCase() === action
        );
        if (!target) return;
        processedIncidentIds.add(target.id);

        // 자동 대응 실행
        const res2 = await fetchAuthed(`/api/incidents/${encodeURIComponent(target.id)}/decision`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action })
        });
        const result = await readApiResponse(res2);
        const ok = res2.ok && result.result_type !== 'error';
        if (ok && result.incident) mergeIncidentUpdate(result.incident);

        // 자동 대응 이력 기록
        const policyLabel = {
            quarantine: '자동 격리',
            block_ip: '자동 IP 차단',
            terminate_process: '자동 프로세스 종료'
        }[action] || action;
        stats.autoActions.unshift({
            time: nowHMS(),
            action: policyLabel,
            target: target.file_path || target.destination_ip || target.process_image || target.id.slice(0, 8),
            result: result.result_message || '실행됨',
            ok: ok
        });
        if (stats.autoActions.length > 30) stats.autoActions.pop();
        renderAutoPolicyLog();

        // 토스트
        toast(`🤖 ${policyLabel} 실행됨: ${(result.result_message || '').slice(0, 60)}`, ok ? 'success' : 'warn');

        // 위협 탐지 뷰 자동 갱신
        await loadIncidents();
    } catch (e) {
        console.error('자동 대응 실패', e);
    }
}

function renderAutoPolicyLog() {
    const el = $('auto-policy-log');
    if (!el) return;
    if (!stats.autoActions.length) {
        el.innerHTML = '<div class="auto-policy-empty">아직 자동 대응 실행 이력이 없습니다.</div>';
        return;
    }
    el.innerHTML = '';
    stats.autoActions.forEach(a => {
        const div = document.createElement('div');
        div.className = 'auto-policy-entry';
        const icCls = a.ok ? 'ok' : 'err';
        const icCh = a.ok ? '✓' : '✕';
        div.innerHTML = `
            <span class="pe-ic ${icCls}">${icCh}</span>
            <div class="pe-body">
                <div class="pe-title">${esc(a.action)}</div>
                <div class="pe-meta">${esc(a.time)} · ${esc(a.target)}</div>
            </div>`;
        el.appendChild(div);
    });
}

/* ============================================================
 * 백엔드 상태 폴링
 * ============================================================ */
async function fetchStatus() {
    if (!authToken) return;
    try {
        const res = await fetchAuthed('/api/status');
        if (!res.ok) {
            if (res.status === 401) {
                toast('세션이 만료되었습니다', 'warn');
                logout();
            }
            return;
        }
        const data = await res.json();
        isWazuhRunning = !!data.wazuh_running;
        isYaraRunning = !!data.yara_running;
        isYaraScanRunning = !!data.yara_scan_running;
        wazuhRuntime = data.wazuh_runtime || null;
        wazuhLogPath = data.wazuh_log_path || '';
        yaraTargetPaths = Array.isArray(data.yara_target_paths) ? data.yara_target_paths : [];
        updateDeepScanStatus();
        refreshRealtimeStats();
        updateAgentStatus();
        refreshDashboardEngineState();
    } catch (_) {}
}
function updateAgentStatus() {
    const count = (isWazuhRunning ? 1 : 0) + (isYaraRunning ? 1 : 0);
    const st = $('agent-status');
    if (count === 2) { st.textContent = '정상'; st.className = 'sb-status-value good'; }
    else if (count === 1) { st.textContent = '부분 가동'; st.className = 'sb-status-value warn'; }
    else { st.textContent = '중지됨'; st.className = 'sb-status-value bad'; }
    $('agent-status-sub').textContent = `엔진 ${count}/2 실행 중`;
    $('sb-realtime-dot').classList.toggle('on', count > 0);
}

/* ============================================================
 * 뷰 전환
 * ============================================================ */
function switchView(name) {
    currentView = name;
    $$('.sb-nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === name));
    $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));

    const titles = {
        dashboard: ['EDR 통합 보안 대시보드', '시스템 전체 보안 상태를 주요 KPI로 요약합니다.'],
        timeline:  ['이벤트 타임라인', '시간순으로 모든 보안 이벤트를 확인합니다.'],
        realtime:  ['실시간 탐지', '행위 탐지 / YARA 엔진을 직접 제어하고 라이브 스트림을 확인합니다.'],
        analysis:  ['분석 결과', 'YARA 심층 스캔으로 의심 파일을 정밀 검사합니다.'],
        threats:   ['위협 탐지', '인시던트를 검토하고 격리·차단 등 대응 조치를 수행합니다.'],
        reports:   ['보고서', '날짜·엔진별로 보관된 로그를 조회하고 관리합니다.'],
        settings:  ['설정', '계정 정보, 알림, 자동 대응 정책을 설정합니다.']
    };
    const [t, s] = titles[name] || titles.dashboard;
    $('topbar-title').textContent = t;
    $('topbar-section-label').textContent = s;

    if (name === 'dashboard') renderDashboard();
    if (name === 'timeline') renderTimelineView();
    if (name === 'realtime') { fetchStatus(); refreshRealtimeStats(); }
    if (name === 'analysis') prepareScanDirectoryPicker();
    if (name === 'threats') loadIncidents();
    if (name === 'reports') loadReportDates();
    if (name === 'settings') {
        renderAutoPolicyLog();
        if (currentUserIsAdmin) loadUserList();
    }

    closeNotifPanel();
}

/* ============================================================
 * VIEW 1: 대시보드
 * ============================================================ */
function renderDashboard() {
    refreshDashboardKPIs();
    renderDashboardTimeline();
    renderRecent();
    if (stats.events.length) updateFeaturedDetection(stats.events[0]);
    refreshDashboardEngineState();
    refreshEngineBars();
    refreshDashboardSummary();
}
function refreshDashboardKPIs() {
    $('kpi-total').textContent  = stats.total.toLocaleString();
    $('kpi-high').textContent   = stats.high;
    $('kpi-medium').textContent = stats.medium;
    $('kpi-low').textContent    = stats.low;
    const pending = stats.incidents.filter(isIncidentOpen).length;
    $('kpi-pending').textContent = pending;
    updateDonut();
}
function updateDonut() {
    const total = stats.high + stats.medium + stats.low || 1;
    const c = 2 * Math.PI * 78;
    const hi = (stats.high / total) * c;
    const md = (stats.medium / total) * c;
    const lo = (stats.low / total) * c;
    const circles = document.querySelectorAll('.donut circle');
    if (circles.length >= 4) {
        circles[1].setAttribute('stroke-dasharray', `${hi} ${c - hi}`);
        circles[1].setAttribute('stroke-dashoffset', '0');
        circles[2].setAttribute('stroke-dasharray', `${md} ${c - md}`);
        circles[2].setAttribute('stroke-dashoffset', `-${hi}`);
        circles[3].setAttribute('stroke-dasharray', `${lo} ${c - lo}`);
        circles[3].setAttribute('stroke-dashoffset', `-${hi + md}`);
    }
    $('donut-total').textContent = stats.high + stats.medium + stats.low;
    const lg = document.querySelector('.donut-legend');
    if (lg) {
        lg.children[0].innerHTML = `<span class="dot red"></span> 높음 <b>${stats.high}</b>`;
        lg.children[1].innerHTML = `<span class="dot orange"></span> 중간 <b>${stats.medium}</b>`;
        lg.children[2].innerHTML = `<span class="dot blue"></span> 낮음 <b>${stats.low}</b>`;
    }
}
function renderRecent() {
    const recent = $('recent-list');
    if (!recent) return;
    const map = {
        high:   { cls: 'red',    ic: '!' },
        medium: { cls: 'orange', ic: '⚡' },
        low:    { cls: 'blue',   ic: '▶' }
    };
    recent.innerHTML = '';
    if (!stats.events.length) {
        recent.innerHTML = '<li class="empty-state" style="padding:20px;">아직 이벤트가 없습니다.</li>';
        return;
    }
    stats.events.slice(0, 6).forEach(ev => {
        const m = map[ev.sev] || map.low;
        const li = document.createElement('li');
        li.className = 'recent-item';
        li.innerHTML = `
            <span class="recent-ic ${m.cls}">${m.ic}</span>
            <div class="recent-body">
                <div class="recent-title">${esc(ev.title)}</div>
                <div class="recent-meta">${esc(ev.source.toUpperCase())} · ${esc(ev.host)}</div>
            </div>
            <div class="recent-time">${ev.time}</div>`;
        li.addEventListener('click', () => openEventDetail(ev));
        recent.appendChild(li);
    });
}
function renderDashboardTimeline() {
    const track = $('timeline-track');
    if (!track) return;
    track.innerHTML = '';
    [0,4,8,12,16,20,23].forEach(h => {
        const l = document.createElement('span');
        l.className = 'hour-label';
        l.style.left = `${(h/23)*100}%`;
        l.textContent = `${String(h).padStart(2,'0')}:00`;
        track.appendChild(l);
    });
    stats.events.slice(0, 80).forEach(ev => {
        const parts = (ev.time || '00:00:00').split(':').map(Number);
        const hh = parts[0] || 0, mm = parts[1] || 0;
        const pct = ((hh + mm/60) / 23) * 100;
        const d = document.createElement('span');
        const sevClass = ev.sev === 'medium' ? 'med' : ev.sev;
        d.className = `timeline-dot ${sevClass}${ev.sev === 'high' ? ' big' : ''}`;
        d.style.left = `${Math.max(1, Math.min(99, pct))}%`;
        d.title = `${ev.time} · ${ev.title}`;
        d.addEventListener('click', () => openEventDetail(ev));
        track.appendChild(d);
    });
}
function updateFeaturedDetection(ev) {
    if (!ev) return;
    $('featured-time').textContent = `${ev.date} ${ev.time}`;
    $('featured-host').textContent = ev.host || 'localhost';
    $('featured-user').textContent = ev.username || currentUsername || '―';
    $('featured-source').textContent = ev.source.toUpperCase();
    $('featured-message').textContent = ev.message || '―';
    const badge = $('featured-badge');
    if (ev.sev === 'high') { badge.textContent = '긴급 위협 탐지'; badge.className = 'sev-badge crit'; }
    else if (ev.sev === 'medium') { badge.textContent = '주의 이벤트'; badge.className = 'sev-badge high'; }
    else { badge.textContent = '일반 이벤트'; badge.className = 'sev-badge low'; }
}
function refreshDashboardEngineState() {
    $('mini-wazuh-state').textContent = isWazuhRunning ? '실행 중' : '중지됨';
    $('mini-wazuh-state').className = 'state-tag ' + (isWazuhRunning ? 'on' : 'off');
    $('mini-yara-state').textContent = isYaraRunning ? '실행 중' : '중지됨';
    $('mini-yara-state').className = 'state-tag ' + (isYaraRunning ? 'on' : 'off');
}
function refreshEngineBars() {
    const total = wazuhCount + yaraCount + responseCount || 1;
    const pct = (n) => Math.round((n / total) * 100);
    $('bar-wazuh').style.width = pct(wazuhCount) + '%';
    $('bar-yara').style.width = pct(yaraCount) + '%';
    $('bar-response').style.width = pct(responseCount) + '%';
    $('bar-wazuh-count').textContent = wazuhCount;
    $('bar-yara-count').textContent = yaraCount;
    $('bar-response-count').textContent = responseCount;
}
function refreshDashboardSummary() {
    const active = stats.incidents.filter(isActiveThreatIncident).length;
    const resolved = stats.incidents.filter(isContainedIncident).length;
    const pending = stats.incidents.filter(inc => isIncidentOpen(inc) && !isActiveThreatIncident(inc)).length;
    $('featured-active').textContent = active + '건';
    $('featured-resolved').textContent = resolved + '건';
    $('featured-pending').textContent = pending + '건';
}

/* ============================================================
 * VIEW 2: 이벤트 타임라인
 * ============================================================ */
function filterTimeline(kind, value, btn) {
    timelineFilter[kind] = value;
    btn.parentElement.querySelectorAll('.chip-btn').forEach(b => b.classList.toggle('active', b === btn));
    renderTimelineView();
}
function renderTimelineView() {
    const list = $('timeline-list');
    if (!list) return;
    const q = ($('timeline-search')?.value || '').toLowerCase();
    timelineFilter.q = q;
    const filtered = stats.events.filter(ev => {
        if (timelineFilter.sev !== 'all' && ev.sev !== timelineFilter.sev) return false;
        if (timelineFilter.src !== 'all' && ev.source !== timelineFilter.src) return false;
        if (q && !(`${ev.title} ${ev.host} ${ev.message}`.toLowerCase().includes(q))) return false;
        return true;
    });
    $('timeline-count').textContent = filtered.length;
    $('ts-high').textContent = filtered.filter(e => e.sev === 'high').length;
    $('ts-medium').textContent = filtered.filter(e => e.sev === 'medium').length;
    $('ts-low').textContent = filtered.filter(e => e.sev === 'low').length;

    list.innerHTML = '';
    if (!filtered.length) {
        list.innerHTML = '<li class="empty-state">조건에 맞는 이벤트가 없습니다.</li>';
        return;
    }
    const icMap = { high: '!', medium: '⚡', low: '▶' };
    filtered.slice(0, 200).forEach(ev => {
        const li = document.createElement('li');
        li.className = 'event-stream-item';
        li.innerHTML = `
            <div class="event-stream-time">${ev.time}<small>${ev.date}</small></div>
            <div class="event-stream-icon ${ev.sev}">${icMap[ev.sev] || '·'}</div>
            <div class="event-stream-body">
                <div class="event-stream-title">${esc(ev.title)}</div>
                <div class="event-stream-meta">
                    <span class="event-stream-badge ${ev.source}">${ev.source.toUpperCase()}</span>
                    <span>호스트 <span class="mono">${esc(ev.host)}</span></span>
                    ${ev.username ? `<span>사용자 ${esc(ev.username)}</span>` : ''}
                </div>
            </div>
            <div class="event-stream-arrow">›</div>`;
        li.addEventListener('click', () => openEventDetail(ev));
        list.appendChild(li);
    });
}

/* ============================================================
 * VIEW 3: 실시간 탐지
 * ============================================================ */
function refreshRealtimeStats() {
    const wPill = $('wazuh-status-pill');
    if (!wPill) return;
    wPill.textContent = isWazuhRunning ? '실행 중' : '중지됨';
    wPill.classList.toggle('running', isWazuhRunning);
    $('wazuh-state').textContent = isWazuhRunning ? '실행 중' : '중지됨';
    $('wazuh-counter').textContent = `${wazuhCount}건`;
    $('wazuh-last').textContent = lastWazuhTs || (wazuhLogPath ? `감시: ${shortPath(wazuhLogPath)}` : '―');
    const wBtn = $('btn-wazuh-toggle');
    wBtn.classList.toggle('danger', isWazuhRunning);
    wBtn.innerHTML = isWazuhRunning
        ? `<span class="btn-icon">■</span><span>행위 탐지 중지</span>`
        : `<span class="btn-icon">▶</span><span>행위 탐지 시작</span>`;
    $('wazuh-card').classList.toggle('active-engine', isWazuhRunning);
    $('wazuh-stream-count').textContent = `${wazuhCount}건`;

    const yPill = $('yara-status-pill');
    yPill.textContent = isYaraRunning ? '실행 중' : '중지됨';
    yPill.classList.toggle('running', isYaraRunning);
    $('yara-state').textContent = isYaraRunning ? '실행 중' : '중지됨';
    $('yara-counter').textContent = `${yaraCount}건`;
    $('yara-last').textContent = lastYaraTs || (yaraTargetPaths.length ? `감시: ${yaraTargetPaths.length}개 경로` : '―');
    const yBtn = $('btn-yara-toggle');
    yBtn.classList.toggle('danger', isYaraRunning);
    yBtn.innerHTML = isYaraRunning
        ? `<span class="btn-icon">■</span><span>YARA 중지</span>`
        : `<span class="btn-icon">▶</span><span>YARA 시작</span>`;
    $('yara-card').classList.toggle('active-engine', isYaraRunning);
    $('yara-stream-count').textContent = `${yaraCount}건`;

    const banner = $('realtime-banner');
    if (isWazuhRunning && isYaraRunning) {
        banner.classList.add('all-on');
        banner.classList.remove('partial');
        banner.querySelector('.rb-title').textContent = '✓ 실시간 탐지 가동 중';
        banner.querySelector('.rb-sub').textContent = `행위 탐지 ${shortPath(wazuhLogPath) || 'Sysmon'} · YARA ${yaraTargetPaths.length || 0}개 경로 감시 중`;
        banner.querySelector('button').textContent = '전체 엔진 중지';
        banner.querySelector('button').onclick = stopAllEngines;
    } else if (isWazuhRunning || isYaraRunning) {
        banner.classList.add('partial');
        banner.classList.remove('all-on');
        banner.querySelector('.rb-title').textContent = '⚠ 일부 엔진만 실행 중';
        banner.querySelector('.rb-sub').textContent = isWazuhRunning
            ? `행위 탐지 감시 중: ${shortPath(wazuhLogPath) || 'Sysmon/프로세스'}`
            : `YARA ${yaraTargetPaths.length || 0}개 경로 감시 중`;
        banner.querySelector('button').textContent = '나머지 엔진 시작';
        banner.querySelector('button').onclick = startAllEngines;
    } else {
        banner.classList.remove('all-on', 'partial');
        banner.querySelector('.rb-title').textContent = '실시간 탐지를 시작하려면 아래 엔진을 켜세요';
        banner.querySelector('.rb-sub').textContent = '행위 탐지와 YARA 파일 매칭을 실시간 감시합니다.';
        banner.querySelector('button').textContent = '전체 엔진 시작';
        banner.querySelector('button').onclick = startAllEngines;
    }
}

async function ensureSysmonReadyForBehaviorDetection() {
    try {
        const statusRes = await fetchAuthed('/api/behavior/sysmon-status');
        const statusData = await statusRes.json().catch(() => ({}));
        if (statusData.installed && statusData.running && statusData.event_log && statusData.event_log_readable) return true;

        const approved = confirm(
            'Sysmon이 설치되어 있지 않거나 앱에서 이벤트 로그를 읽을 수 없습니다.\n\n' +
            '행위 탐지를 제대로 사용하려면 Sysmon 설치/권한 보정이 필요합니다.\n' +
            'Microsoft Sysinternals Sysmon을 다운로드하거나 로그 권한을 보정하시겠습니까?'
        );
        if (!approved) {
            toast('Sysmon 설치가 취소되어 제한 모드로 행위 탐지를 시작합니다.', 'warn');
            return true;
        }

        toast('Sysmon 설치를 시작합니다. Windows 관리자 권한 창에서 확인을 눌러주세요.', 'info');
        const installRes = await fetchAuthed('/api/behavior/install-sysmon', { method: 'POST' });
        const installData = await installRes.json().catch(() => ({}));
        if (!installRes.ok || installData.result_type === 'error') {
            toast(installData.result_message || installData.detail || 'Sysmon 설치에 실패했습니다.', 'error');
            return false;
        }
        toast(installData.result_message || 'Sysmon 설치가 완료되었습니다.', 'success');
        await fetchStatus();
        return true;
    } catch (e) {
        toast('Sysmon 상태 확인 중 백엔드 연결에 실패했습니다.', 'error');
        return false;
    }
}

async function toggleWazuh() {
    const btn = $('btn-wazuh-toggle');
    btn.disabled = true;
    const endpoint = isWazuhRunning ? '/api/wazuh/stop' : '/api/wazuh/start';
    try {
        if (!isWazuhRunning) {
            const ready = await ensureSysmonReadyForBehaviorDetection();
            if (!ready) return;
        }
        const res = await fetchAuthed(endpoint, { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            toast(data.detail?.message || data.detail || '행위 탐지 제어 실패', 'error');
            return;
        }
        await fetchStatus();
        const action = isWazuhRunning ? '시작' : '중지';
        toast(`행위 탐지가 ${action}되었습니다`, isWazuhRunning ? 'success' : 'info');
    } catch (e) { toast('백엔드 연결 실패', 'error'); }
    finally { btn.disabled = false; }
}

async function selectWazuhAlertLogAndStart() {
    toast('행위 탐지는 별도 alert 파일 선택 없이 시작됩니다.', 'info');
    try {
        const res = await fetchAuthed('/api/wazuh/select-alert-log', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            toast(data.detail || 'alert 로그 선택에 실패했습니다.', 'error');
            return;
        }
        if (data.status === 'cancelled') {
            toast('alert 로그 선택이 취소되었습니다.', 'info');
            return;
        }
        toast(`alert 로그 선택됨: ${shortPath(data.log_path)}`, 'success');
        await fetchStatus();
        await toggleWazuh();
    } catch (e) {
        toast('alert 로그 선택 중 백엔드 연결에 실패했습니다.', 'error');
    }
}

async function toggleYara() {
    const btn = $('btn-yara-toggle');
    btn.disabled = true;
    const endpoint = isYaraRunning ? '/api/yara/stop' : '/api/yara/start';
    try {
        const res = await fetchAuthed(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode: 'realtime' })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            toast(data.detail || 'YARA 제어 실패', 'error');
            return;
        }
        await fetchStatus();
        const action = isYaraRunning ? '시작' : '중지';
        toast(`YARA 모니터가 ${action}되었습니다`, isYaraRunning ? 'success' : 'info');
    } catch (e) { toast('백엔드 연결 실패', 'error'); }
    finally { btn.disabled = false; }
}

async function startAllEngines() {
    if (!isWazuhRunning) await toggleWazuh();
    setTimeout(async () => {
        if (!isYaraRunning) await toggleYara();
    }, 400);
}
async function stopAllEngines() {
    if (isWazuhRunning) await toggleWazuh();
    setTimeout(async () => {
        if (isYaraRunning) await toggleYara();
    }, 400);
}

function appendToLogStream(ev) {
    const container = ev.source === 'wazuh' ? $('wazuh-logs')
                    : ev.source === 'yara' ? $('yara-logs')
                    : null;
    if (!container) return;
    const ph = container.querySelector('.log-placeholder');
    if (ph) ph.remove();

    const div = document.createElement('div');
    div.className = `log-line ${ev.sev}`;
    div.innerHTML = `<span class="log-time">${esc(ev.time)}</span> ${esc(ev.message)}`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    while (container.children.length > 300) container.removeChild(container.firstChild);
}
function clearStream(which) {
    const el = which === 'wazuh' ? $('wazuh-logs') : $('yara-logs');
    if (el) el.innerHTML = `<div class="log-placeholder">${which === 'wazuh' ? '행위 탐지' : 'YARA'} 스트림이 비워졌습니다.</div>`;
    if (which === 'wazuh') { wazuhCount = 0; lastWazuhTs = null; }
    else { yaraCount = 0; lastYaraTs = null; }
    refreshRealtimeStats();
}

/* ============================================================
 * VIEW 4: 분석 결과 (YARA 심층 스캔)
 * ============================================================ */
function prepareScanDirectoryPicker() {
    updateScanSelectionUI();
}
function addScanDirectoryPath(path, notify = true) {
    const selectedPath = String(path || '').trim();
    if (!selectedPath) return false;

    if (selectedScanDirs.has(selectedPath)) {
        if (notify) toast('이미 선택된 폴더입니다.', 'info');
        updateScanSelectionUI();
        return false;
    }

    selectedScanDirs.add(selectedPath);
    updateScanSelectionUI();
    if (notify) toast(`스캔 대상 추가: ${shortPath(selectedPath)}`, 'success');
    return true;
}
function removeScanDirectoryPath(path) {
    if (isYaraScanRunning) {
        toast('스캔 중에는 선택을 변경할 수 없습니다.', 'warn');
        return;
    }
    selectedScanDirs.delete(path);
    updateScanSelectionUI();
}
async function pickScanDirectory() {
    if (isYaraScanRunning) {
        toast('스캔 중에는 폴더를 추가할 수 없습니다.', 'warn');
        return;
    }

    const btn = $('btn-pick-scan-dir');
    if (btn) {
        btn.disabled = true;
        btn.textContent = '폴더 선택 중...';
    }

    let selectedPath = null;
    let desktopPickerTried = false;

    try {
        if (window.pywebview && window.pywebview.api && window.pywebview.api.choose_scan_folder) {
            desktopPickerTried = true;
            selectedPath = await window.pywebview.api.choose_scan_folder();
        }

        if (!desktopPickerTried) {
            const res = await fetchAuthed('/api/yara/directories/pick', { method: 'POST' });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.detail || '폴더 선택에 실패했습니다.');
            selectedPath = data.path || (data.directory && data.directory.path) || null;
        }

        if (!selectedPath) {
            toast('폴더 선택이 취소되었습니다.', 'info');
            return;
        }

        addScanDirectoryPath(selectedPath);
    } catch (e) {
        toast(e.message || '폴더 선택에 실패했습니다.', 'error');
    } finally {
        if (btn) {
            btn.disabled = isYaraScanRunning;
            btn.textContent = '폴더 선택';
        }
    }
}
function updateScanSelectionUI() {
    const sum = $('dir-summary');
    const btn = $('btn-start-scan');
    const stopBtn = $('btn-stop-scan');
    const pickBtn = $('btn-pick-scan-dir');
    if (selectedScanDirs.size === 0) {
        sum.textContent = '선택된 폴더 없음';
        sum.classList.remove('has-selection');
        btn.disabled = true;
    } else {
        const selectedPaths = Array.from(selectedScanDirs);
        sum.innerHTML = `
            <div>${selectedPaths.length}개 폴더 선택됨</div>
            <div class="selected-dir-list">
                ${selectedPaths.map(path => `
                    <div class="selected-dir-chip" title="${esc(path)}">
                        <span>${esc(shortPath(path))}</span>
                        <button type="button" data-remove-scan-dir="${esc(path)}" ${isYaraScanRunning ? 'disabled' : ''} title="선택 해제">x</button>
                    </div>
                `).join('')}
            </div>`;
        sum.querySelectorAll('[data-remove-scan-dir]').forEach(removeBtn => {
            removeBtn.addEventListener('click', () => removeScanDirectoryPath(removeBtn.getAttribute('data-remove-scan-dir')));
        });
        sum.classList.add('has-selection');
        btn.disabled = isYaraScanRunning;
    }
    if (stopBtn) stopBtn.disabled = !isYaraScanRunning;
    if (pickBtn) pickBtn.disabled = isYaraScanRunning;
}
function clearScanSelection() {
    if (isYaraScanRunning) {
        toast('스캔 중에는 선택을 변경할 수 없습니다.', 'warn');
        return;
    }
    selectedScanDirs.clear();
    updateScanSelectionUI();
}
function updateDeepScanStatus() {
    const status = $('scan-status');
    const startBtn = $('btn-start-scan');
    const stopBtn = $('btn-stop-scan');
    const pickBtn = $('btn-pick-scan-dir');
    if (!status) return;
    status.classList.toggle('running', isYaraScanRunning);
    if (startBtn) startBtn.disabled = isYaraScanRunning || selectedScanDirs.size === 0;
    if (stopBtn) stopBtn.disabled = !isYaraScanRunning;
    if (pickBtn) pickBtn.disabled = isYaraScanRunning;
    $$('#dir-summary [data-remove-scan-dir]').forEach(btn => { btn.disabled = isYaraScanRunning; });
    if (isYaraScanRunning) {
        status.classList.remove('completed');
        status.textContent = '스캔 중...';
    }
}
async function startDeepScan() {
    if (selectedScanDirs.size === 0) return;
    $('scan-status').textContent = '스캔 중...';
    $('scan-status').classList.add('running');
    $('scan-status').classList.remove('completed');
    try {
        const res = await fetchAuthed('/api/yara/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                mode: 'deep',
                target_paths: Array.from(selectedScanDirs),
                rule_source: 'external'
            })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            toast(data.detail || '스캔 시작 실패', 'error');
            $('scan-status').textContent = '실패';
            $('scan-status').classList.remove('running');
            updateDeepScanStatus();
            return;
        }
        isYaraScanRunning = true;
        updateDeepScanStatus();
        toast(`${selectedScanDirs.size}개 폴더 심층 스캔 시작`, 'success');
        await fetchStatus();
    } catch (e) {
        $('scan-status').textContent = '실패';
        $('scan-status').classList.remove('running');
        updateDeepScanStatus();
        toast('백엔드 연결 실패', 'error');
    }
}
async function stopDeepScan() {
    const stopBtn = $('btn-stop-scan');
    const status = $('scan-status');
    if (!isYaraScanRunning) return;
    if (stopBtn) stopBtn.disabled = true;
    if (status) status.textContent = '중지 요청 중...';
    try {
        const res = await fetchAuthed('/api/yara/scan/stop', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            toast(data.detail || '스캔 중지 실패', 'error');
            updateDeepScanStatus();
            return;
        }
        isYaraScanRunning = false;
        if (status) {
            status.textContent = data.status === 'stopped' ? '중지됨' : '실행 중인 스캔 없음';
            status.classList.remove('running', 'completed');
        }
        updateDeepScanStatus();
        toast(data.status === 'stopped' ? '심층 스캔을 중지했습니다' : '실행 중인 심층 스캔이 없습니다', 'info');
        await fetchStatus();
    } catch (e) {
        toast('백엔드 연결 실패', 'error');
        updateDeepScanStatus();
    }
}
function appendScanResult(ev) {
    const list = $('scan-results');
    if (!list) return;
    const emptyEl = list.querySelector('.empty-state');
    if (emptyEl) emptyEl.remove();
    const li = document.createElement('li');
    li.className = 'match-list-item';
    const details = getYaraDetails(ev);
    const matches = details && Array.isArray(details.matches) ? details.matches : [];
    const ruleNames = matches.map(m => m.rule).filter(Boolean);
    const primaryRule = ruleNames[0] || ev.title;
    const metaRows = matches.slice(0, 3).map(match => {
        const meta = match.meta || {};
        const desc = meta.description || meta.Description || meta.info || '';
        const author = meta.author || meta.Author || '';
        const tags = Array.isArray(match.tags) && match.tags.length ? ` · tags: ${match.tags.join(', ')}` : '';
        return `<div class="match-rule-detail"><b>${esc(match.rule || 'unknown')}</b>${desc ? ` · ${esc(desc)}` : ''}${author ? ` · ${esc(author)}` : ''}${esc(tags)}</div>`;
    }).join('');
    const filePath = details ? (details.file_path || ev.message) : ev.message;
    const fileFacts = details
        ? `크기 ${formatBytes(details.file_size)} · SHA256 ${details.sha256 ? esc(details.sha256) : '―'}`
        : `호스트 ${esc(ev.host)} · 사용자 ${esc(ev.username || '―')}`;
    li.innerHTML = `
        <div class="match-ic">!</div>
        <div class="match-list-body">
            <div class="match-list-rule">${esc(primaryRule)}</div>
            <div class="match-list-file">${esc(filePath)}</div>
            <div class="match-list-meta">${fileFacts}</div>
            ${ruleNames.length > 1 ? `<div class="match-list-meta">매칭 룰 ${esc(ruleNames.join(', '))}</div>` : ''}
            ${metaRows ? `<div class="match-rule-box">${metaRows}</div>` : ''}
        </div>
        <div class="match-list-time">${ev.time}</div>`;
    li.addEventListener('click', () => openEventDetail(ev));
    list.insertBefore(li, list.firstChild);
    while (list.children.length > 100) list.removeChild(list.lastChild);
    $('scan-status').textContent = isYaraScanRunning ? `${list.children.length}건 탐지 · 스캔 중...` : `${list.children.length}건 탐지`;
    $('scan-status').classList.toggle('running', isYaraScanRunning);
    $('scan-status').classList.toggle('completed', !isYaraScanRunning);
}

/* ============================================================
 * VIEW 5: 위협 탐지 (인시던트)
 * ============================================================ */
async function loadIncidents(manual = false) {
    resetDailyIncidentStateIfNeeded();
    const list = $('incident-list');
    const refreshBtn = $('incident-refresh-btn');
    if (!authToken) {
        list.innerHTML = '<div class="empty-state">로그인이 필요합니다.</div>';
        return;
    }
    if (manual && refreshBtn) {
        refreshBtn.disabled = true;
        refreshBtn.textContent = '새로고침 중...';
    }
    try {
        const res = await fetchAuthed('/api/incidents');
        if (!res.ok) throw new Error();
        const data = await res.json();
        stats.incidents = data.incidents || [];
        renderIncidents();
        refreshDashboardKPIs();
        refreshDashboardSummary();
        updateSidebarBadges();
        if (manual) toast('인시던트 목록을 새로고침했습니다.', 'success');
    } catch (e) {
        list.innerHTML = '<div class="empty-state">인시던트를 가져오지 못했습니다.</div>';
        if (manual) toast('인시던트를 가져오지 못했습니다.', 'error');
    } finally {
        if (manual && refreshBtn) {
            refreshBtn.disabled = false;
            refreshBtn.textContent = '새로고침';
        }
    }
}
function scheduleIncidentRefresh() {
    if (incidentRefreshTimer) clearTimeout(incidentRefreshTimer);
    incidentRefreshTimer = setTimeout(() => { loadIncidents(); }, 800);
}
const RESOLVED_INCIDENT_STATUSES = ['quarantined', 'terminated', 'blocked'];
function hasQuarantineStoragePath(inc) {
    const paths = [inc.file_path, inc.quarantine_path, inc.quarantine_original_path].filter(Boolean);
    return paths.some(path => /(^|[\\/])quarantine([\\/]|$)/i.test(String(path)));
}
function isResolvedIncident(inc) {
    return RESOLVED_INCIDENT_STATUSES.includes((inc.status || '').toLowerCase()) ||
        hasQuarantineStoragePath(inc);
}
function isKeptIncident(inc) {
    return (inc.status || '').toLowerCase() === 'kept' ||
        (inc.decision || '').toLowerCase() === 'keep';
}
function isIncidentOpen(inc) {
    const status = (inc.status || '').toLowerCase();
    return !isResolvedIncident(inc) &&
        !isKeptIncident(inc) &&
        status === 'pending';
}
function isActiveThreatIncident(inc) {
    const riskLabel = (inc.risk_label || '').toLowerCase();
    const suggested = (inc.suggested_decision || '').toLowerCase();
    return isIncidentOpen(inc) && (
        ['critical', 'high'].includes(riskLabel) ||
        ['quarantine', 'terminate_process', 'block_ip'].includes(suggested)
    );
}
function isContainedIncident(inc) {
    return isResolvedIncident(inc) && !isKeptIncident(inc);
}
function mergeIncidentUpdate(updatedIncident) {
    if (!updatedIncident || !updatedIncident.id) return;

    const index = stats.incidents.findIndex(inc => inc.id === updatedIncident.id);
    if (index >= 0) stats.incidents.splice(index, 1, updatedIncident);
    else stats.incidents.unshift(updatedIncident);

    renderIncidents();
    refreshDashboardKPIs();
    refreshDashboardSummary();
    updateSidebarBadges();
}
function groupIncidents(incidents) {
    const grouped = {
        active: incidents.filter(isActiveThreatIncident),
        contained: incidents.filter(isContainedIncident),
        pending: incidents.filter(inc => isIncidentOpen(inc) && !isActiveThreatIncident(inc)),
        kept: incidents.filter(isKeptIncident),
        other: []
    };
    const shownIds = new Set([
        ...grouped.active,
        ...grouped.contained,
        ...grouped.pending,
        ...grouped.kept
    ].map(inc => inc.id));
    grouped.other = incidents.filter(inc => !shownIds.has(inc.id));
    return grouped;
}
function renderIncidents() {
    const list = $('incident-list');
    const incidents = stats.incidents;
    const grouped = groupIncidents(incidents);
    $('th-active').textContent = grouped.active.length;
    $('th-contained').textContent = grouped.contained.length;
    $('th-pending').textContent = grouped.pending.length;
    $('th-kept').textContent = grouped.kept.length;

    list.innerHTML = '';
    if (!incidents.length) {
        list.innerHTML = `
            <div class="empty-state">
                현재 인시던트가 없습니다.<br>
                YARA는 룰 매칭([Yara DETECT])이 발생해야 생성되고, 행위 탐지는 의심 이벤트가 발견되면 생성됩니다.
            </div>`;
        return;
    }
    const sections = [
        ['active', '활성 위협', '즉시 대응이 필요한 미조치 인시던트', grouped.active],
        ['contained', '격리/대응 완료', '격리, 차단, 프로세스 종료가 완료된 인시던트', grouped.contained],
        ['pending', '분석 대기', '추가 확인 후 조치할 미결정 인시던트', grouped.pending],
        ['kept', '유지 관찰', '운영자가 관찰 대상으로 남긴 인시던트', grouped.kept]
    ];
    if (grouped.other.length) {
        sections.push(['other', '기타 인시던트', '분류 조건 밖의 상태를 가진 인시던트', grouped.other]);
    }
    sections.forEach(([key, title, subtitle, items]) => {
        list.appendChild(renderIncidentGroup(key, title, subtitle, items));
    });
}
function renderIncidentGroup(key, title, subtitle, incidents) {
    const section = document.createElement('section');
    section.className = `incident-group ${key}`;
    section.innerHTML = `
        <div class="incident-group-head">
            <div>
                <h4>${title}</h4>
                <p>${subtitle}</p>
            </div>
            <span>${incidents.length}건</span>
        </div>
        <div class="incident-group-body"></div>`;
    const body = section.querySelector('.incident-group-body');
    if (!incidents.length) {
        body.innerHTML = '<div class="empty-state compact">해당 인시던트가 없습니다.</div>';
        return section;
    }
    incidents.forEach(inc => body.appendChild(renderIncidentCard(inc)));
    return section;
}
function renderIncidentCard(inc) {
    const riskLabel = (inc.risk_label || '').toLowerCase();
    const sevClass = ['critical', 'high'].includes(riskLabel) ? 'high' : riskLabel === 'medium' ? 'medium' : 'low';
    const sevText = riskLabel === 'critical' ? '긴급' : riskLabel === 'high' ? '높음' : riskLabel === 'medium' ? '중간' : '낮음';
    const statusMap = {
        pending: ['대응 대기', 'detected'],
        quarantined: ['격리 완료', 'quarantined'],
        terminated: ['프로세스 종료', 'terminated'],
        blocked: ['IP 차단', 'terminated'],
        kept: ['관찰 중', 'kept']
    };
    const [statusLabel, statusCls] = statusMap[inc.status] || ['처리 중', 'detected'];
    const decided = inc.decision && inc.decision !== null;
    const title = inc.rule_description || inc.wazuh_message || '의심 위협';
    const yaraRules = (inc.yara_matches || []).map(m => typeof m === 'string' ? m : (m.rule || '')).filter(Boolean).join(', ');
    const suggested = (inc.suggested_decision || '').toLowerCase();

    const card = document.createElement('div');
    card.className = `incident-card ${sevClass}`;
    card.innerHTML = `
        <div class="stripe"></div>
        <div class="incident-body">
            <div class="incident-head">
                <span class="sev-badge ${sevClass === 'high' ? 'crit' : sevClass}">${sevText}</span>
                <span class="inc-status-tag ${statusCls}">${statusLabel}</span>
                ${inc.risk_score != null ? `<span class="risk-score">위험도 ${esc(inc.risk_score)}</span>` : ''}
                ${suggested && suggested !== 'keep' ? `<span class="suggest-tag">권장: ${esc(suggested.toUpperCase())}</span>` : ''}
                <span class="incident-time mono">${esc(inc.created_at || '')}</span>
            </div>
            <div class="incident-title">${esc(title)}</div>
            <div class="incident-meta">
                <div><div class="inc-k">파일 경로</div><div class="inc-v mono">${esc(inc.file_path || '―')}</div></div>
                <div><div class="inc-k">탐지 레벨</div><div class="inc-v">${esc(inc.wazuh_level || '―')}</div></div>
                <div><div class="inc-k">매칭 룰 (YARA)</div><div class="inc-v mono">${esc(yaraRules || '―')}</div></div>
                <div><div class="inc-k">프로세스</div><div class="inc-v mono">${esc(inc.process_image || '―')} ${inc.process_id ? '<span style="color:var(--text-3)">(PID '+esc(inc.process_id)+')</span>' : ''}</div></div>
                ${inc.destination_ip ? `<div><div class="inc-k">목적지 IP</div><div class="inc-v mono">${esc(inc.destination_ip)}${inc.destination_port ? ':'+esc(inc.destination_port) : ''}</div></div>` : ''}
                ${inc.command_line ? `<div><div class="inc-k">커맨드라인</div><div class="inc-v mono">${esc((inc.command_line || '').slice(0, 80))}</div></div>` : ''}
            </div>
            <div class="incident-actions">
                <button class="inc-btn primary" onclick="openIncidentFolder('${esc(inc.id)}')" ${!inc.file_exists ? 'disabled title="파일을 찾을 수 없습니다"' : ''}>폴더 열기</button>
                <button class="inc-btn danger ${suggested === 'quarantine' ? 'recommended' : ''}" onclick="decideIncident('${esc(inc.id)}', 'quarantine')" ${decided || !inc.file_exists ? 'disabled title="격리할 파일을 찾을 수 없습니다"' : ''}>파일 격리</button>
                <button class="inc-btn warn ${suggested === 'terminate_process' ? 'recommended' : ''}" onclick="decideIncident('${esc(inc.id)}', 'terminate_process')" ${decided || !inc.process_id ? 'disabled' : ''}>프로세스 종료</button>
                <button class="inc-btn warn ${suggested === 'block_ip' ? 'recommended' : ''}" onclick="decideIncident('${esc(inc.id)}', 'block_ip')" ${decided || !inc.destination_ip ? 'disabled' : ''}>IP 차단</button>
                <button class="inc-btn" onclick="decideIncident('${esc(inc.id)}', 'keep')" ${decided ? 'disabled' : ''}>유지 관찰</button>
            </div>
            ${inc.decision_note ? `<div class="incident-note">📝 ${esc(inc.decision_note)}</div>` : ''}
        </div>`;
    return card;
}
async function decideIncident(id, action) {
    try {
        const needsElevation = action === 'terminate_process' || action === 'block_ip';
        if (needsElevation) toast('권한이 부족하면 Windows 관리자 승인 창이 표시됩니다.', 'info');
        const res = await fetchAuthed(`/api/incidents/${encodeURIComponent(id)}/decision`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action,
                allow_elevation: needsElevation
            })
        });
        const data = await readApiResponse(res);
        const type = !res.ok || data.result_type === 'error' ? 'error' : data.result_type === 'warning' ? 'warn' : 'success';
        toast(data.result_message || `${action} 처리 완료`, type);
        if (res.ok && data.result_type !== 'error' && data.incident) mergeIncidentUpdate(data.incident);
        await loadIncidents();
    } catch (e) { toast('백엔드 연결 실패', 'error'); }
}
async function openIncidentFolder(id) {
    try {
        const res = await fetchAuthed(`/api/incidents/${encodeURIComponent(id)}/open-folder`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'opened') toast(`폴더 열림: ${data.folder}`, 'success');
        else if (data.status === 'missing folder') toast('폴더를 찾을 수 없습니다', 'warn');
        else if (data.status === 'missing path') toast('파일 경로가 없습니다', 'warn');
        else toast('폴더를 열 수 없습니다.', 'warn');
    } catch (e) { toast('백엔드 연결 실패', 'error'); }
}
function updateSidebarBadges() {
    const active = stats.incidents.filter(isActiveThreatIncident).length;
    const badge = $('sb-threats-badge');
    badge.textContent = active;
    badge.classList.toggle('zero', active === 0);
    const unread = stats.notifications.filter(n => !n.read).length;
    const nb = $('notif-badge');
    nb.textContent = unread > 99 ? '99+' : unread;
    nb.classList.toggle('hidden', unread === 0);
}

/* ============================================================
 * VIEW 6: 보고서
 * ============================================================ */
async function loadReportDates() {
    if (currentUserIsAdmin) $('report-admin-user-wrap').classList.remove('hidden');
    if (!authToken) {
        $('report-content').textContent = '로그인이 필요합니다.';
        return;
    }
    try {
        const params = new URLSearchParams();
        const sel = $('report-user');
        if (currentUserIsAdmin && sel.value) params.set('username', sel.value);
        const res = await fetchAuthed('/api/logs' + (params.toString() ? '?' + params : ''));
        if (!res.ok) throw new Error();
        const data = await res.json();
        let source = $('report-source').value;
        const dateSelect = $('report-date');
        const cur = dateSelect.value;
        dateSelect.innerHTML = '<option value="">날짜를 선택하세요</option>';
        const allLogs = normalizeReportLogs(data);
        let dates = allLogs.filter(l => l.source === source);
        if (!dates.length) {
            const fallback = allLogs.find(l => l.source);
            if (fallback) {
                source = fallback.source;
                $('report-source').value = source;
                dates = allLogs.filter(l => l.source === source);
            }
        }
        dates.forEach(l => {
            const opt = document.createElement('option');
            opt.value = l.date;
            opt.textContent = `${l.date} (${l.count || 0}건)`;
            dateSelect.appendChild(opt);
        });
        dateSelect.value = dates.some(l => l.date === cur) ? cur : '';
        if (!dates.length) {
            $('report-content').textContent = `${source.toUpperCase()} 저장 로그가 없습니다. 실시간 탐지에서 이벤트가 발생하면 자동 저장됩니다.`;
            $('report-meta-text').textContent = '조회 가능한 날짜가 없습니다.';
            $('report-line-count').textContent = '';
            $('btn-clear-day').disabled = true;
        } else if (!dateSelect.value) {
            $('report-content').textContent = '';
            $('report-meta-text').textContent = '날짜를 선택하면 로그를 표시합니다.';
            $('report-line-count').textContent = '';
            $('btn-clear-day').disabled = true;
        }
        if (currentUserIsAdmin) await loadUsersForReport();
    } catch (e) {
        $('report-content').textContent = '로그 목록을 가져오지 못했습니다.';
    }
}
function normalizeReportLogs(data) {
    if (Array.isArray(data.logs)) return data.logs;
    const bySource = data.logs_by_source || data.logs || {};
    const rows = [];
    Object.entries(bySource).forEach(([source, dates]) => {
        if (!Array.isArray(dates)) return;
        dates.forEach(date => {
            if (typeof date === 'string') rows.push({ source, date, count: 0 });
            else if (date && typeof date === 'object') rows.push({ source, date: date.date, count: date.count || 0 });
        });
    });
    return rows.filter(row => row.source && row.date);
}
async function loadUsersForReport() {
    try {
        const res = await fetchAuthed('/api/users');
        if (!res.ok) return;
        const data = await res.json();
        const sel = $('report-user');
        const cur = sel.value;
        sel.innerHTML = '<option value="">내 로그</option>';
        const users = data.users || data || [];
        users.forEach(u => {
            const name = typeof u === 'string' ? u : u.username;
            if (!name) return;
            const opt = document.createElement('option');
            opt.value = name; opt.textContent = name;
            sel.appendChild(opt);
        });
        sel.value = cur;
    } catch (_) {}
}
async function loadReportLog() {
    const source = $('report-source').value;
    const date = $('report-date').value;
    if (!source || !date) {
        $('report-content').textContent = '';
        $('report-meta-text').textContent = '날짜를 선택하면 로그를 표시합니다.';
        $('report-line-count').textContent = '';
        $('btn-clear-day').disabled = true;
        return;
    }
    try {
        const params = new URLSearchParams();
        const u = $('report-user').value;
        if (currentUserIsAdmin && u) params.set('username', u);
        const res = await fetchAuthed(`/api/logs/${source}/${date}` + (params.toString() ? '?' + params : ''));
        const data = await res.json();
        const content = (!data.content || data.content === 'Log file not found.') ? '(로그 없음)' : data.content;
        $('report-content').textContent = content;
        const lines = content === '(로그 없음)' ? 0 : (content.match(/\n/g) || []).length + 1;
        $('report-meta-text').textContent = `${source.toUpperCase()} · ${date}${u ? ` · ${u}` : ''}`;
        $('report-line-count').textContent = `${lines.toLocaleString()} 라인`;
        $('btn-clear-day').disabled = false;
    } catch (e) {
        $('report-content').textContent = '로그를 가져오지 못했습니다.';
    }
}
async function clearReportDay() {
    const source = $('report-source').value;
    const date = $('report-date').value;
    if (!source || !date) return;
    if (!confirm(`${date} ${source} 로그를 삭제하시겠습니까?`)) return;
    try {
        const res = await fetchAuthed(`/api/logs/${source}/${date}/clear`, { method: 'POST' });
        if (res.ok) {
            toast('해당 날짜의 로그가 삭제되었습니다.', 'success');
            loadReportDates();
            $('report-content').textContent = '';
        } else toast('삭제 실패', 'error');
    } catch (e) { toast('백엔드 연결 실패', 'error'); }
}
async function clearAllLogs() {
    if (!confirm('내 모든 로그를 영구 삭제하시겠습니까? 이 작업은 되돌릴 수 없습니다.')) return;
    try {
        const res = await fetchAuthed('/api/logs/clear', { method: 'POST' });
        if (res.ok) {
            const data = await res.json();
            toast(`로그 삭제 완료 (${data.deleted_db_rows || 0}개 DB / ${data.deleted_files || 0}개 파일)`, 'success');
            loadReportDates();
        } else toast('삭제 실패', 'error');
    } catch (e) { toast('백엔드 연결 실패', 'error'); }
}

/* ============================================================
 * VIEW 7: 설정
 * ============================================================ */
async function loadUserList() {
    try {
        const res = await fetchAuthed('/api/users');
        if (!res.ok) return;
        const data = await res.json();
        const list = $('user-list');
        list.innerHTML = '';
        (data.users || data || []).forEach(u => {
            const name = typeof u === 'string' ? u : u.username;
            if (!name) return;
            const isAdmin = name === 'admin' || (typeof u === 'object' && u.is_admin);
            const li = document.createElement('li');
            li.innerHTML = `<span class="name">${esc(name)}</span>
                <span class="role ${isAdmin ? 'admin' : ''}">${isAdmin ? '관리자' : '사용자'}</span>`;
            list.appendChild(li);
        });
    } catch (_) {}
}
function toggleDesktopNotif(el) {
    if (el.checked) {
        if (!('Notification' in window)) {
            toast('이 브라우저는 데스크톱 알림을 지원하지 않습니다.', 'warn');
            el.checked = false; return;
        }
        Notification.requestPermission().then(permission => {
            desktopNotifEnabled = (permission === 'granted');
            if (!desktopNotifEnabled) {
                el.checked = false;
                toast('알림 권한이 거부되었습니다.', 'warn');
            } else {
                toast('데스크톱 알림이 활성화되었습니다.', 'success');
            }
        });
    } else {
        desktopNotifEnabled = false;
    }
}

/* ============================================================
 * 알림 패널
 * ============================================================ */
function addNotification(ev) {
    const notif = {
        id: ev.id, sev: ev.sev, source: ev.source,
        title: ev.title, time: ev.time, date: ev.date,
        host: ev.host, message: ev.message,
        read: false, ev: ev
    };
    stats.notifications.unshift(notif);
    if (stats.notifications.length > 50) stats.notifications.pop();
    updateSidebarBadges();
    renderNotifList();

    if (!$('notif-panel').classList.contains('open') && ev.sev === 'high') {
        toast(`🚨 긴급: ${ev.title}`, 'error');
    }
    if (desktopNotifEnabled && ev.sev === 'high' && Notification.permission === 'granted') {
        try {
            new Notification('EDR 긴급 위협 탐지', { body: ev.title, tag: ev.id });
        } catch (_) {}
    }
}
function toggleNotifPanel() {
    const panel = $('notif-panel');
    panel.classList.toggle('open');
    if (panel.classList.contains('open')) renderNotifList();
}
function closeNotifPanel() { $('notif-panel').classList.remove('open'); }
function filterNotif(kind, btn) {
    notifFilter = kind;
    $$('.notif-filter-chip').forEach(b => b.classList.toggle('active', b === btn));
    renderNotifList();
}
function renderNotifList() {
    const list = $('notif-list');
    let items = stats.notifications;
    if (notifFilter === 'high') items = items.filter(n => n.sev === 'high');
    else if (notifFilter === 'medium') items = items.filter(n => n.sev === 'medium');
    else if (notifFilter === 'unread') items = items.filter(n => !n.read);

    $('notif-subhead').textContent = `최근 24시간 · ${stats.notifications.length}건 · ${stats.notifications.filter(n => !n.read).length} 안 읽음`;

    list.innerHTML = '';
    if (!items.length) {
        list.innerHTML = '<li class="notif-empty">표시할 알림이 없습니다.</li>';
        return;
    }
    items.slice(0, 30).forEach(n => {
        const li = document.createElement('li');
        li.className = `notif-item ${n.sev}${n.read ? ' read' : ''}`;
        const icon = n.sev === 'high' ? '!' : n.sev === 'medium' ? '⚡' : '▶';
        li.innerHTML = `
            <div class="notif-icon ${n.sev}">${icon}</div>
            <div class="notif-body">
                <div class="notif-title">${esc(n.title)}</div>
                <div class="notif-meta">
                    <span class="notif-src">${esc(n.source.toUpperCase())}</span>
                    <span>${esc(n.host)}</span>
                    <span class="mono">${esc(n.time)}</span>
                </div>
            </div>
            ${!n.read ? '<span class="notif-unread-dot"></span>' : ''}`;
        li.addEventListener('click', () => {
            n.read = true;
            renderNotifList();
            updateSidebarBadges();
            openEventDetail(n.ev);
        });
        list.appendChild(li);
    });
}
function markAllRead() {
    stats.notifications.forEach(n => n.read = true);
    renderNotifList();
    updateSidebarBadges();
}
function clearNotifications() {
    stats.notifications = [];
    renderNotifList();
    updateSidebarBadges();
}
document.addEventListener('click', (e) => {
    const panel = $('notif-panel');
    const btn = $('notif-btn');
    if (panel && panel.classList.contains('open') &&
        !panel.contains(e.target) && !btn.contains(e.target)) {
        closeNotifPanel();
    }
});

/* ============================================================
 * 모달 / 토스트 / 유틸
 * ============================================================ */
function openEventDetail(ev) {
    const modal = $('detail-modal');
    $('modal-sev').textContent = ev.sev === 'high' ? '높음 위협' : ev.sev === 'medium' ? '중간 경고' : '정보';
    $('modal-sev').className = `sev-badge ${ev.sev === 'high' ? 'crit' : ev.sev}`;
    $('modal-title').textContent = ev.title;
    $('modal-body').innerHTML = `
        <div class="modal-grid">
            <div>
                <h5 class="mini-head">이벤트 정보</h5>
                <div class="kv"><span>시각</span><span class="mono">${esc(ev.date)} ${esc(ev.time)}</span></div>
                <div class="kv"><span>엔진</span><span>${esc(ev.source.toUpperCase())}</span></div>
                <div class="kv"><span>심각도</span><span>${ev.sev}</span></div>
                <div class="kv"><span>호스트</span><span>${esc(ev.host)}</span></div>
                <div class="kv"><span>사용자</span><span>${esc(ev.username || '―')}</span></div>
            </div>
            <div>
                <h5 class="mini-head">원본 메시지</h5>
                <pre style="background: var(--bg); padding: 12px; border-radius: 8px;
                    font-family: var(--font-mono); font-size: 11.5px;
                    white-space: pre-wrap; word-break: break-all; max-height: 240px;
                    overflow: auto; margin: 0; color: var(--text-2); line-height: 1.55;">${esc(ev.message)}</pre>
            </div>
        </div>`;
    modal.classList.add('open');
}
function closeDetail() { $('detail-modal').classList.remove('open'); }
window.addEventListener('keydown', e => {
    if (e.key === 'Escape') { closeDetail(); closeNotifPanel(); }
});

function toast(msg, type = 'info') {
    const c = $('toast-container');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    const icons = { success: '✓', error: '✕', warn: '!', info: 'ℹ' };
    t.innerHTML = `<div class="toast-ic">${icons[type] || 'ℹ'}</div><div>${esc(msg)}</div>`;
    c.appendChild(t);
    setTimeout(() => {
        t.style.opacity = '0';
        t.style.transform = 'translateX(20px)';
        setTimeout(() => t.remove(), 200);
    }, 3500);
}
function esc(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

Object.assign(window, {
    clearAllLogs,
    clearNotifications,
    clearReportDay,
    clearScanSelection,
    clearStream,
    closeDetail,
    filterNotif,
    filterTimeline,
    loadIncidents,
    loadReportDates,
    loadReportLog,
    logout,
    markAllRead,
    pickScanDirectory,
    renderTimelineView,
    startAllEngines,
    startDeepScan,
    stopDeepScan,
    submitAuth,
    switchAuthMode,
    switchView,
    toggleDesktopNotif,
    toggleNotifPanel,
    toggleWazuh,
    toggleYara,
});

/* ============================================================
 * 부팅
 * ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
    if (authToken && currentUsername) enterApp();
    else switchAuthMode('login');
    [$('auth-username'), $('auth-password')].forEach(el => {
        el && el.addEventListener('keydown', e => { if (e.key === 'Enter') submitAuth(); });
    });
});
