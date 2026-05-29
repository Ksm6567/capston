/* ============================================================
 * EDR ?듯빀 蹂댁븞 ??쒕낫??- app.js (v4 - PRODUCTION)
 * 諛깆뿏???꾩쟾 ?곕룞 + ?먮룞 ????뺤콉 ?묐룞
 * - ?몄쬆: X-Session-Token ?ㅻ뜑 (Bearer ?꾨떂)
 * - ?먮룞 ??? WebSocket response 硫붿떆吏瑜??뚯떛?댁꽌 ?좉? ?곕씪 ?ㅽ뻾
 * - ?곕え 紐⑤뱶 OFF (?꾩꽦??
 * ============================================================ */

const API_URL = window.location.origin;
const WS_URL  = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/logs`;
const DEMO_MODE = false; // ?꾨줈?뺤뀡: ??긽 false

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
const processedIncidentIds = new Set(); // ?먮룞 ???以묐났 諛⑹?

/* ????? ?듦퀎 / 硫붾え由?????? */
const stats = {
    high: 0, medium: 0, low: 0,
    total: 0,
    events: [],
    incidents: [],
    notifications: [],
    autoActions: []  // ?먮룞 ????ㅽ뻾 ?대젰
};
const timelineFilter = { sev: 'all', src: 'all', q: '' };
let notifFilter = 'all';
let desktopNotifEnabled = false;

/* ????? ?먮룞 ????뺤콉 (localStorage????? ????? */
const autoPolicy = {
    quarantine: localStorage.getItem('edrPolicyAutoQuarantine') === 'true',
    blockIp:    localStorage.getItem('edrPolicyAutoBlockIp') === 'true',
    terminate:  localStorage.getItem('edrPolicyAutoTerminate') === 'true'
};

/* ????? DOM ?ы띁 ????? */
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
    $('auth-submit').textContent = mode === 'login' ? '濡쒓렇?? : '?뚯썝媛??;
    setAuthFeedback(mode === 'login' ? '湲곕낯 愿由ъ옄 怨꾩젙: admin / admin1234' : '??怨꾩젙???앹꽦?⑸땲??');
}
async function submitAuth() {
    const username = $('auth-username').value.trim();
    const password = $('auth-password').value;
    if (!username || !password) return setAuthFeedback('?꾩씠?붿? 鍮꾨?踰덊샇瑜?紐⑤몢 ?낅젰?댁＜?몄슂.', 'error');
    const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
    try {
        const res = await fetch(API_URL + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) return setAuthFeedback(data.detail || '?몄쬆???ㅽ뙣?덉뒿?덈떎.', 'error');
        if (authMode === 'register') {
            setAuthFeedback('?뚯썝媛?낆씠 ?꾨즺?섏뿀?듬땲?? 濡쒓렇?명빐二쇱꽭??', 'success');
            switchAuthMode('login');
            return;
        }
        // 諛깆뿏???묐떟 ?뺤떇???곕씪 ?좏겙 異붿텧 (token / access_token / session_token)
        authToken = data.token || data.access_token || data.session_token || '';
        const userInfo = data.user || {};
        currentUsername = userInfo.username || data.username || username;
        currentUserIsAdmin = !!(userInfo.is_admin ?? data.is_admin);
        if (!authToken) {
            setAuthFeedback('?쒕쾭 ?묐떟???좏겙???놁뒿?덈떎.', 'error');
            return;
        }
        localStorage.setItem('edrSessionToken', authToken);
        localStorage.setItem('edrUsername', currentUsername);
        localStorage.setItem('edrIsAdmin', currentUserIsAdmin ? 'true' : 'false');
        enterApp();
    } catch (err) {
        setAuthFeedback('諛깆뿏???쒕쾭???곌껐?????놁뒿?덈떎. 諛깆뿏?쒓? ?ㅽ뻾 以묒씤吏 ?뺤씤?섏꽭??', 'error');
    }
}
function enterApp() {
    $('auth-shell').classList.add('app-hidden');
    $('app-shell').classList.remove('app-hidden');
    $('user-chip').textContent = (currentUsername || 'USER').toUpperCase();
    $('user-role').textContent = currentUserIsAdmin ? '愿由ъ옄' : '?ъ슜??;
    $('set-username').textContent = currentUsername;
    $('set-role').textContent = currentUserIsAdmin ? '愿由ъ옄 (admin)' : '?쇰컲 ?ъ슜??;
    $('set-token').textContent = authToken ? authToken.slice(0, 12) + '...' : '??;
    if (currentUserIsAdmin) $('settings-admin-card').classList.remove('hidden');

    // ?먮룞 ????뺤콉 ?좉? 蹂듭썝
    if ($('auto-quarantine')) $('auto-quarantine').checked = autoPolicy.quarantine;
    if ($('auto-block-ip')) $('auto-block-ip').checked = autoPolicy.blockIp;
    if ($('auto-terminate')) $('auto-terminate').checked = autoPolicy.terminate;
    bindPolicyToggles();

    incidentViewDate = todayISO();
    connectWS();
    fetchStatus();
    loadIncidents();
    renderDashboard();

    // 二쇨린???곹깭 ?대쭅 (8珥?
    if (statusRefreshTimer) clearInterval(statusRefreshTimer);
    statusRefreshTimer = setInterval(() => {
        if (!authToken) return;
        resetDailyIncidentStateIfNeeded();
        fetchStatus();
        // ?꾪삊 ?먯? 酉곗뿉 ?덉쑝硫??몄떆?섑듃??媛깆떊
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

/* ?뵎 ?듭떖: X-Session-Token ?ㅻ뜑 ?ъ슜 (Bearer ?꾨떂) */
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
    $('ws-status-text').textContent = connected ? '?ㅼ떆媛??곌껐?? : '?곌껐 ????;
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
        catch (e) { console.error('WS ?뚯떛 ?ㅻ쪟', e); }
    };
    ws.onclose = () => {
        setWsStatus(false);
        if (authToken) {
            wsReconnectTimer = setTimeout(connectWS, 3000);
        }
    };
    ws.onerror = () => { try { ws.close(); } catch (_) {} };
}

/* WebSocket payload (諛깆뿏??broadcast_log):
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
        // ?쨼 Response 硫붿떆吏?먯꽌 ?먮룞 ????몃━嫄?寃??        checkAutoResponseTrigger(ev);
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
            scanStatus.textContent = ev.message.replace(/^.*Initial Yara scan complete\.\s*/i, '') || '?ㅼ틪 ?꾨즺';
            scanStatus.classList.remove('running');
            scanStatus.classList.add('completed');
        }
        updateDeepScanStatus();
    }
    if (ev.source === 'yara' && /Stopping Yara deep scan/i.test(ev.message)) {
        isYaraScanRunning = false;
        const scanStatus = $('scan-status');
        if (scanStatus) {
            scanStatus.textContent = '以묒???;
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
    let msg = data.message || '?대깽??;
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
    if (!Number.isFinite(value)) return '??;
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
 * ?쨼 ?먮룞 ????뺤콉 (?듭떖 湲곕뒫)
 * ============================================================ */
function bindPolicyToggles() {
    const aq = $('auto-quarantine');
    const ab = $('auto-block-ip');
    const at = $('auto-terminate');
    if (aq) aq.addEventListener('change', e => {
        autoPolicy.quarantine = e.target.checked;
        localStorage.setItem('edrPolicyAutoQuarantine', autoPolicy.quarantine);
        toast(autoPolicy.quarantine ? '?먮룞 寃⑸━媛 ?쒖꽦?붾릺?덉뒿?덈떎' : '?먮룞 寃⑸━媛 鍮꾪솢?깊솕?섏뿀?듬땲??,
              autoPolicy.quarantine ? 'success' : 'info');
    });
    if (ab) ab.addEventListener('change', e => {
        autoPolicy.blockIp = e.target.checked;
        localStorage.setItem('edrPolicyAutoBlockIp', autoPolicy.blockIp);
        toast(autoPolicy.blockIp ? '?먮룞 IP 李⑤떒???쒖꽦?붾릺?덉뒿?덈떎' : '?먮룞 IP 李⑤떒??鍮꾪솢?깊솕?섏뿀?듬땲??,
              autoPolicy.blockIp ? 'success' : 'info');
    });
    if (at) at.addEventListener('change', e => {
        autoPolicy.terminate = e.target.checked;
        localStorage.setItem('edrPolicyAutoTerminate', autoPolicy.terminate);
        toast(autoPolicy.terminate ? '?먮룞 ?꾨줈?몄뒪 醫낅즺媛 ?쒖꽦?붾릺?덉뒿?덈떎' : '?먮룞 ?꾨줈?몄뒪 醫낅즺媛 鍮꾪솢?깊솕?섏뿀?듬땲??,
              autoPolicy.terminate ? 'success' : 'info');
    });
}

/* Response 硫붿떆吏 ?뚯떛:
   "[Response] Risk HIGH (85) | Suggested decision: QUARANTINE | ..." */
function checkAutoResponseTrigger(ev) {
    const m = (ev.message || '').match(/Suggested decision:\s*(QUARANTINE|TERMINATE_PROCESS|BLOCK_IP|KEEP)/i);
    if (!m) return;
    const suggested = m[1].toLowerCase();
    // ?뺤콉???곕씪 ?먮룞 ?ㅽ뻾?좎? 寃곗젙
    const shouldExecute =
        (suggested === 'quarantine' && autoPolicy.quarantine) ||
        (suggested === 'block_ip' && autoPolicy.blockIp) ||
        (suggested === 'terminate_process' && autoPolicy.terminate);
    if (!shouldExecute) return;

    // 0.5珥????몄떆?섑듃 紐⑸줉 諛쏆븘???媛??理쒓렐 pending ?몄떆?섑듃???≪뀡 ?곸슜
    setTimeout(() => triggerAutoAction(suggested), 800);
}

async function triggerAutoAction(action) {
    if (!authToken) return;
    try {
        const res = await fetchAuthed('/api/incidents');
        if (!res.ok) return;
        const data = await res.json();
        const incidents = data.incidents || [];
        // 媛??理쒓렐??pending ?몄떆?섑듃 + suggested_decision ?쇱튂 + 以묐났 ?덈맂 寃?李얘린
        const target = incidents.find(i =>
            i.status === 'pending' &&
            !i.decision &&
            !processedIncidentIds.has(i.id) &&
            (i.suggested_decision || '').toLowerCase() === action
        );
        if (!target) return;
        processedIncidentIds.add(target.id);

        // ?먮룞 ????ㅽ뻾
        const res2 = await fetchAuthed(`/api/incidents/${encodeURIComponent(target.id)}/decision`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action })
        });
        const result = await readApiResponse(res2);
        const ok = res2.ok && result.result_type !== 'error';
        if (ok && result.incident) mergeIncidentUpdate(result.incident);

        // ?먮룞 ????대젰 湲곕줉
        const policyLabel = {
            quarantine: '?먮룞 寃⑸━',
            block_ip: '?먮룞 IP 李⑤떒',
            terminate_process: '?먮룞 ?꾨줈?몄뒪 醫낅즺'
        }[action] || action;
        stats.autoActions.unshift({
            time: nowHMS(),
            action: policyLabel,
            target: target.file_path || target.destination_ip || target.process_image || target.id.slice(0, 8),
            result: result.result_message || '?ㅽ뻾??,
            ok: ok
        });
        if (stats.autoActions.length > 30) stats.autoActions.pop();
        renderAutoPolicyLog();

        // ?좎뒪??        toast(`?쨼 ${policyLabel} ?ㅽ뻾?? ${(result.result_message || '').slice(0, 60)}`, ok ? 'success' : 'warn');

        // ?꾪삊 ?먯? 酉??먮룞 媛깆떊
        await loadIncidents();
    } catch (e) {
        console.error('?먮룞 ????ㅽ뙣', e);
    }
}

function renderAutoPolicyLog() {
    const el = $('auto-policy-log');
    if (!el) return;
    if (!stats.autoActions.length) {
        el.innerHTML = '<div class="auto-policy-empty">?꾩쭅 ?먮룞 ????ㅽ뻾 ?대젰???놁뒿?덈떎.</div>';
        return;
    }
    el.innerHTML = '';
    stats.autoActions.forEach(a => {
        const div = document.createElement('div');
        div.className = 'auto-policy-entry';
        const icCls = a.ok ? 'ok' : 'err';
        const icCh = a.ok ? '?? : '??;
        div.innerHTML = `
            <span class="pe-ic ${icCls}">${icCh}</span>
            <div class="pe-body">
                <div class="pe-title">${esc(a.action)}</div>
                <div class="pe-meta">${esc(a.time)} 쨌 ${esc(a.target)}</div>
            </div>`;
        el.appendChild(div);
    });
}

/* ============================================================
 * 諛깆뿏???곹깭 ?대쭅
 * ============================================================ */
async function fetchStatus() {
    if (!authToken) return;
    try {
        const res = await fetchAuthed('/api/status');
        if (!res.ok) {
            if (res.status === 401) {
                toast('?몄뀡??留뚮즺?섏뿀?듬땲??, 'warn');
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
    if (count === 2) { st.textContent = '?뺤긽'; st.className = 'sb-status-value good'; }
    else if (count === 1) { st.textContent = '遺遺?媛??; st.className = 'sb-status-value warn'; }
    else { st.textContent = '以묒???; st.className = 'sb-status-value bad'; }
    $('agent-status-sub').textContent = `?붿쭊 ${count}/2 ?ㅽ뻾 以?;
    $('sb-realtime-dot').classList.toggle('on', count > 0);
}

/* ============================================================
 * 酉??꾪솚
 * ============================================================ */
function switchView(name) {
    currentView = name;
    $$('.sb-nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === name));
    $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));

    const titles = {
        dashboard: ['EDR ?듯빀 蹂댁븞 ??쒕낫??, '?쒖뒪???꾩껜 蹂댁븞 ?곹깭瑜?二쇱슂 KPI濡??붿빟?⑸땲??'],
        timeline:  ['?대깽????꾨씪??, '?쒓컙?쒖쑝濡?紐⑤뱺 蹂댁븞 ?대깽?몃? ?뺤씤?⑸땲??'],
        realtime:  ['?ㅼ떆媛??먯?', '?됱쐞 ?먯? / YARA ?붿쭊??吏곸젒 ?쒖뼱?섍퀬 ?쇱씠釉??ㅽ듃由쇱쓣 ?뺤씤?⑸땲??'],
        analysis:  ['遺꾩꽍 寃곌낵', 'YARA ?ъ링 ?ㅼ틪?쇰줈 ?섏떖 ?뚯씪???뺣? 寃?ы빀?덈떎.'],
        threats:   ['?꾪삊 ?먯?', '?몄떆?섑듃瑜?寃?좏븯怨?寃⑸━쨌李⑤떒 ?????議곗튂瑜??섑뻾?⑸땲??'],
        reports:   ['蹂닿퀬??, '?좎쭨쨌?붿쭊蹂꾨줈 蹂닿???濡쒓렇瑜?議고쉶?섍퀬 愿由ы빀?덈떎.'],
        settings:  ['?ㅼ젙', '怨꾩젙 ?뺣낫, ?뚮┝, ?먮룞 ????뺤콉???ㅼ젙?⑸땲??']
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
 * VIEW 1: ??쒕낫?? * ============================================================ */
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
        lg.children[0].innerHTML = `<span class="dot red"></span> ?믪쓬 <b>${stats.high}</b>`;
        lg.children[1].innerHTML = `<span class="dot orange"></span> 以묎컙 <b>${stats.medium}</b>`;
        lg.children[2].innerHTML = `<span class="dot blue"></span> ??쓬 <b>${stats.low}</b>`;
    }
}
function renderRecent() {
    const recent = $('recent-list');
    if (!recent) return;
    const map = {
        high:   { cls: 'red',    ic: '!' },
        medium: { cls: 'orange', ic: '?? },
        low:    { cls: 'blue',   ic: '?? }
    };
    recent.innerHTML = '';
    if (!stats.events.length) {
        recent.innerHTML = '<li class="empty-state" style="padding:20px;">?꾩쭅 ?대깽?멸? ?놁뒿?덈떎.</li>';
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
                <div class="recent-meta">${esc(ev.source.toUpperCase())} 쨌 ${esc(ev.host)}</div>
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
        d.title = `${ev.time} 쨌 ${ev.title}`;
        d.addEventListener('click', () => openEventDetail(ev));
        track.appendChild(d);
    });
}
function updateFeaturedDetection(ev) {
    if (!ev) return;
    $('featured-time').textContent = `${ev.date} ${ev.time}`;
    $('featured-host').textContent = ev.host || 'localhost';
    $('featured-user').textContent = ev.username || currentUsername || '??;
    $('featured-source').textContent = ev.source.toUpperCase();
    $('featured-message').textContent = ev.message || '??;
    const badge = $('featured-badge');
    if (ev.sev === 'high') { badge.textContent = '湲닿툒 ?꾪삊 ?먯?'; badge.className = 'sev-badge crit'; }
    else if (ev.sev === 'medium') { badge.textContent = '二쇱쓽 ?대깽??; badge.className = 'sev-badge high'; }
    else { badge.textContent = '?쇰컲 ?대깽??; badge.className = 'sev-badge low'; }
}
function refreshDashboardEngineState() {
    $('mini-wazuh-state').textContent = isWazuhRunning ? '?ㅽ뻾 以? : '以묒???;
    $('mini-wazuh-state').className = 'state-tag ' + (isWazuhRunning ? 'on' : 'off');
    $('mini-yara-state').textContent = isYaraRunning ? '?ㅽ뻾 以? : '以묒???;
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
    $('featured-active').textContent = active + '嫄?;
    $('featured-resolved').textContent = resolved + '嫄?;
    $('featured-pending').textContent = pending + '嫄?;
}

/* ============================================================
 * VIEW 2: ?대깽????꾨씪?? * ============================================================ */
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
        list.innerHTML = '<li class="empty-state">議곌굔??留욌뒗 ?대깽?멸? ?놁뒿?덈떎.</li>';
        return;
    }
    const icMap = { high: '!', medium: '??, low: '?? };
    filtered.slice(0, 200).forEach(ev => {
        const li = document.createElement('li');
        li.className = 'event-stream-item';
        li.innerHTML = `
            <div class="event-stream-time">${ev.time}<small>${ev.date}</small></div>
            <div class="event-stream-icon ${ev.sev}">${icMap[ev.sev] || '쨌'}</div>
            <div class="event-stream-body">
                <div class="event-stream-title">${esc(ev.title)}</div>
                <div class="event-stream-meta">
                    <span class="event-stream-badge ${ev.source}">${ev.source.toUpperCase()}</span>
                    <span>?몄뒪??<span class="mono">${esc(ev.host)}</span></span>
                    ${ev.username ? `<span>?ъ슜??${esc(ev.username)}</span>` : ''}
                </div>
            </div>
            <div class="event-stream-arrow">??/div>`;
        li.addEventListener('click', () => openEventDetail(ev));
        list.appendChild(li);
    });
}

/* ============================================================
 * VIEW 3: ?ㅼ떆媛??먯?
 * ============================================================ */
function refreshRealtimeStats() {
    const wPill = $('wazuh-status-pill');
    if (!wPill) return;
    wPill.textContent = isWazuhRunning ? '?ㅽ뻾 以? : '以묒???;
    wPill.classList.toggle('running', isWazuhRunning);
    $('wazuh-state').textContent = isWazuhRunning ? '?ㅽ뻾 以? : '以묒???;
    $('wazuh-counter').textContent = `${wazuhCount}嫄?;
    $('wazuh-last').textContent = lastWazuhTs || (wazuhLogPath ? `媛먯떆: ${shortPath(wazuhLogPath)}` : '??);
    const wBtn = $('btn-wazuh-toggle');
    wBtn.classList.toggle('danger', isWazuhRunning);
    wBtn.innerHTML = isWazuhRunning
        ? `<span class="btn-icon">??/span><span>?됱쐞 ?먯? 以묒?</span>`
        : `<span class="btn-icon">??/span><span>?됱쐞 ?먯? ?쒖옉</span>`;
    $('wazuh-card').classList.toggle('active-engine', isWazuhRunning);
    $('wazuh-stream-count').textContent = `${wazuhCount}嫄?;

    const yPill = $('yara-status-pill');
    yPill.textContent = isYaraRunning ? '?ㅽ뻾 以? : '以묒???;
    yPill.classList.toggle('running', isYaraRunning);
    $('yara-state').textContent = isYaraRunning ? '?ㅽ뻾 以? : '以묒???;
    $('yara-counter').textContent = `${yaraCount}嫄?;
    $('yara-last').textContent = lastYaraTs || (yaraTargetPaths.length ? `媛먯떆: ${yaraTargetPaths.length}媛?寃쎈줈` : '??);
    const yBtn = $('btn-yara-toggle');
    yBtn.classList.toggle('danger', isYaraRunning);
    yBtn.innerHTML = isYaraRunning
        ? `<span class="btn-icon">??/span><span>YARA 以묒?</span>`
        : `<span class="btn-icon">??/span><span>YARA ?쒖옉</span>`;
    $('yara-card').classList.toggle('active-engine', isYaraRunning);
    $('yara-stream-count').textContent = `${yaraCount}嫄?;

    const banner = $('realtime-banner');
    if (isWazuhRunning && isYaraRunning) {
        banner.classList.add('all-on');
        banner.classList.remove('partial');
        banner.querySelector('.rb-title').textContent = '???ㅼ떆媛??먯? 媛??以?;
        banner.querySelector('.rb-sub').textContent = `?됱쐞 ?먯? ${shortPath(wazuhLogPath) || 'Sysmon'} 쨌 YARA ${yaraTargetPaths.length || 0}媛?寃쎈줈 媛먯떆 以?;
        banner.querySelector('button').textContent = '?꾩껜 ?붿쭊 以묒?';
        banner.querySelector('button').onclick = stopAllEngines;
    } else if (isWazuhRunning || isYaraRunning) {
        banner.classList.add('partial');
        banner.classList.remove('all-on');
        banner.querySelector('.rb-title').textContent = '???쇰? ?붿쭊留??ㅽ뻾 以?;
        banner.querySelector('.rb-sub').textContent = isWazuhRunning
            ? `?됱쐞 ?먯? 媛먯떆 以? ${shortPath(wazuhLogPath) || 'Sysmon/?꾨줈?몄뒪'}`
            : `YARA ${yaraTargetPaths.length || 0}媛?寃쎈줈 媛먯떆 以?;
        banner.querySelector('button').textContent = '?섎㉧吏 ?붿쭊 ?쒖옉';
        banner.querySelector('button').onclick = startAllEngines;
    } else {
        banner.classList.remove('all-on', 'partial');
        banner.querySelector('.rb-title').textContent = '?ㅼ떆媛??먯?瑜??쒖옉?섎젮硫??꾨옒 ?붿쭊??耳쒖꽭??;
        banner.querySelector('.rb-sub').textContent = '?됱쐞 ?먯?? YARA ?뚯씪 留ㅼ묶???ㅼ떆媛?媛먯떆?⑸땲??';
        banner.querySelector('button').textContent = '?꾩껜 ?붿쭊 ?쒖옉';
        banner.querySelector('button').onclick = startAllEngines;
    }
}

async function ensureSysmonReadyForBehaviorDetection() {
    try {
        const statusRes = await fetchAuthed('/api/behavior/sysmon-status');
        const statusData = await statusRes.json().catch(() => ({}));
        if (statusData.installed && statusData.running && statusData.event_log && statusData.event_log_readable) return true;

        const approved = confirm(
            'Sysmon???ㅼ튂?섏뼱 ?덉? ?딄굅???깆뿉???대깽??濡쒓렇瑜??쎌쓣 ???놁뒿?덈떎.\n\n' +
            '?됱쐞 ?먯?瑜??쒕?濡??ъ슜?섎젮硫?Sysmon ?ㅼ튂/沅뚰븳 蹂댁젙???꾩슂?⑸땲??\n' +
            'Microsoft Sysinternals Sysmon???ㅼ슫濡쒕뱶?섍굅??濡쒓렇 沅뚰븳??蹂댁젙?섏떆寃좎뒿?덇퉴?'
        );
        if (!approved) {
            toast('Sysmon ?ㅼ튂媛 痍⑥냼?섏뼱 ?쒗븳 紐⑤뱶濡??됱쐞 ?먯?瑜??쒖옉?⑸땲??', 'warn');
            return true;
        }

        toast('Sysmon ?ㅼ튂瑜??쒖옉?⑸땲?? Windows 愿由ъ옄 沅뚰븳 李쎌뿉???뺤씤???뚮윭二쇱꽭??', 'info');
        const installRes = await fetchAuthed('/api/behavior/install-sysmon', { method: 'POST' });
        const installData = await installRes.json().catch(() => ({}));
        if (!installRes.ok || installData.result_type === 'error') {
            toast(installData.result_message || installData.detail || 'Sysmon ?ㅼ튂???ㅽ뙣?덉뒿?덈떎.', 'error');
            return false;
        }
        toast(installData.result_message || 'Sysmon ?ㅼ튂媛 ?꾨즺?섏뿀?듬땲??', 'success');
        await fetchStatus();
        return true;
    } catch (e) {
        toast('Sysmon ?곹깭 ?뺤씤 以?諛깆뿏???곌껐???ㅽ뙣?덉뒿?덈떎.', 'error');
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
            toast(data.detail?.message || data.detail || '?됱쐞 ?먯? ?쒖뼱 ?ㅽ뙣', 'error');
            return;
        }
        await fetchStatus();
        const action = isWazuhRunning ? '?쒖옉' : '以묒?';
        toast(`?됱쐞 ?먯?媛 ${action}?섏뿀?듬땲??, isWazuhRunning ? 'success' : 'info');
    } catch (e) { toast('諛깆뿏???곌껐 ?ㅽ뙣', 'error'); }
    finally { btn.disabled = false; }
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
            toast(data.detail || 'YARA ?쒖뼱 ?ㅽ뙣', 'error');
            return;
        }
        await fetchStatus();
        const action = isYaraRunning ? '?쒖옉' : '以묒?';
        toast(`YARA 紐⑤땲?곌? ${action}?섏뿀?듬땲??, isYaraRunning ? 'success' : 'info');
    } catch (e) { toast('諛깆뿏???곌껐 ?ㅽ뙣', 'error'); }
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
    if (el) el.innerHTML = `<div class="log-placeholder">${which === 'wazuh' ? '?됱쐞 ?먯?' : 'YARA'} ?ㅽ듃由쇱씠 鍮꾩썙議뚯뒿?덈떎.</div>`;
    if (which === 'wazuh') { wazuhCount = 0; lastWazuhTs = null; }
    else { yaraCount = 0; lastYaraTs = null; }
    refreshRealtimeStats();
}

/* ============================================================
 * VIEW 4: 遺꾩꽍 寃곌낵 (YARA ?ъ링 ?ㅼ틪)
 * ============================================================ */
function prepareScanDirectoryPicker() {
    updateScanSelectionUI();
}
function addScanDirectoryPath(path, notify = true) {
    const selectedPath = String(path || '').trim();
    if (!selectedPath) return false;

    if (selectedScanDirs.has(selectedPath)) {
        if (notify) toast('?대? ?좏깮???대뜑?낅땲??', 'info');
        updateScanSelectionUI();
        return false;
    }

    selectedScanDirs.add(selectedPath);
    updateScanSelectionUI();
    if (notify) toast(`?ㅼ틪 ???異붽?: ${shortPath(selectedPath)}`, 'success');
    return true;
}
function removeScanDirectoryPath(path) {
    if (isYaraScanRunning) {
        toast('?ㅼ틪 以묒뿉???좏깮??蹂寃쏀븷 ???놁뒿?덈떎.', 'warn');
        return;
    }
    selectedScanDirs.delete(path);
    updateScanSelectionUI();
}
async function pickScanDirectory() {
    if (isYaraScanRunning) {
        toast('?ㅼ틪 以묒뿉???대뜑瑜?異붽??????놁뒿?덈떎.', 'warn');
        return;
    }

    const btn = $('btn-pick-scan-dir');
    if (btn) {
        btn.disabled = true;
        btn.textContent = '?대뜑 ?좏깮 以?..';
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
            if (!res.ok) throw new Error(data.detail || '?대뜑 ?좏깮???ㅽ뙣?덉뒿?덈떎.');
            selectedPath = data.path || (data.directory && data.directory.path) || null;
        }

        if (!selectedPath) {
            toast('?대뜑 ?좏깮??痍⑥냼?섏뿀?듬땲??', 'info');
            return;
        }

        addScanDirectoryPath(selectedPath);
    } catch (e) {
        toast(e.message || '?대뜑 ?좏깮???ㅽ뙣?덉뒿?덈떎.', 'error');
    } finally {
        if (btn) {
            btn.disabled = isYaraScanRunning;
            btn.textContent = '?대뜑 ?좏깮';
        }
    }
}
function updateScanSelectionUI() {
    const sum = $('dir-summary');
    const btn = $('btn-start-scan');
    const stopBtn = $('btn-stop-scan');
    const pickBtn = $('btn-pick-scan-dir');
    if (selectedScanDirs.size === 0) {
        sum.textContent = '?좏깮???대뜑 ?놁쓬';
        sum.classList.remove('has-selection');
        btn.disabled = true;
    } else {
        const selectedPaths = Array.from(selectedScanDirs);
        sum.innerHTML = `
            <div>${selectedPaths.length}媛??대뜑 ?좏깮??/div>
            <div class="selected-dir-list">
                ${selectedPaths.map(path => `
                    <div class="selected-dir-chip" title="${esc(path)}">
                        <span>${esc(shortPath(path))}</span>
                        <button type="button" data-remove-scan-dir="${esc(path)}" ${isYaraScanRunning ? 'disabled' : ''} title="?좏깮 ?댁젣">x</button>
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
        toast('?ㅼ틪 以묒뿉???좏깮??蹂寃쏀븷 ???놁뒿?덈떎.', 'warn');
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
        status.textContent = '?ㅼ틪 以?..';
    }
}
async function startDeepScan() {
    if (selectedScanDirs.size === 0) return;
    $('scan-status').textContent = '?ㅼ틪 以?..';
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
            toast(data.detail || '?ㅼ틪 ?쒖옉 ?ㅽ뙣', 'error');
            $('scan-status').textContent = '?ㅽ뙣';
            $('scan-status').classList.remove('running');
            updateDeepScanStatus();
            return;
        }
        isYaraScanRunning = true;
        updateDeepScanStatus();
        toast(`${selectedScanDirs.size}媛??대뜑 ?ъ링 ?ㅼ틪 ?쒖옉`, 'success');
        await fetchStatus();
    } catch (e) {
        $('scan-status').textContent = '?ㅽ뙣';
        $('scan-status').classList.remove('running');
        updateDeepScanStatus();
        toast('諛깆뿏???곌껐 ?ㅽ뙣', 'error');
    }
}
async function stopDeepScan() {
    const stopBtn = $('btn-stop-scan');
    const status = $('scan-status');
    if (!isYaraScanRunning) return;
    if (stopBtn) stopBtn.disabled = true;
    if (status) status.textContent = '以묒? ?붿껌 以?..';
    try {
        const res = await fetchAuthed('/api/yara/scan/stop', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            toast(data.detail || '?ㅼ틪 以묒? ?ㅽ뙣', 'error');
            updateDeepScanStatus();
            return;
        }
        isYaraScanRunning = false;
        if (status) {
            status.textContent = data.status === 'stopped' ? '以묒??? : '?ㅽ뻾 以묒씤 ?ㅼ틪 ?놁쓬';
            status.classList.remove('running', 'completed');
        }
        updateDeepScanStatus();
        toast(data.status === 'stopped' ? '?ъ링 ?ㅼ틪??以묒??덉뒿?덈떎' : '?ㅽ뻾 以묒씤 ?ъ링 ?ㅼ틪???놁뒿?덈떎', 'info');
        await fetchStatus();
    } catch (e) {
        toast('諛깆뿏???곌껐 ?ㅽ뙣', 'error');
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
        const tags = Array.isArray(match.tags) && match.tags.length ? ` 쨌 tags: ${match.tags.join(', ')}` : '';
        return `<div class="match-rule-detail"><b>${esc(match.rule || 'unknown')}</b>${desc ? ` 쨌 ${esc(desc)}` : ''}${author ? ` 쨌 ${esc(author)}` : ''}${esc(tags)}</div>`;
    }).join('');
    const filePath = details ? (details.file_path || ev.message) : ev.message;
    const fileFacts = details
        ? `?ш린 ${formatBytes(details.file_size)} 쨌 SHA256 ${details.sha256 ? esc(details.sha256) : '??}`
        : `?몄뒪??${esc(ev.host)} 쨌 ?ъ슜??${esc(ev.username || '??)}`;
    li.innerHTML = `
        <div class="match-ic">!</div>
        <div class="match-list-body">
            <div class="match-list-rule">${esc(primaryRule)}</div>
            <div class="match-list-file">${esc(filePath)}</div>
            <div class="match-list-meta">${fileFacts}</div>
            ${ruleNames.length > 1 ? `<div class="match-list-meta">留ㅼ묶 猷?${esc(ruleNames.join(', '))}</div>` : ''}
            ${metaRows ? `<div class="match-rule-box">${metaRows}</div>` : ''}
        </div>
        <div class="match-list-time">${ev.time}</div>`;
    li.addEventListener('click', () => openEventDetail(ev));
    list.insertBefore(li, list.firstChild);
    while (list.children.length > 100) list.removeChild(list.lastChild);
    $('scan-status').textContent = isYaraScanRunning ? `${list.children.length}嫄??먯? 쨌 ?ㅼ틪 以?..` : `${list.children.length}嫄??먯?`;
    $('scan-status').classList.toggle('running', isYaraScanRunning);
    $('scan-status').classList.toggle('completed', !isYaraScanRunning);
}

/* ============================================================
 * VIEW 5: ?꾪삊 ?먯? (?몄떆?섑듃)
 * ============================================================ */
async function loadIncidents(manual = false) {
    resetDailyIncidentStateIfNeeded();
    const list = $('incident-list');
    const refreshBtn = $('incident-refresh-btn');
    if (!authToken) {
        list.innerHTML = '<div class="empty-state">濡쒓렇?몄씠 ?꾩슂?⑸땲??</div>';
        return;
    }
    if (manual && refreshBtn) {
        refreshBtn.disabled = true;
        refreshBtn.textContent = '?덈줈怨좎묠 以?..';
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
        if (manual) toast('?몄떆?섑듃 紐⑸줉???덈줈怨좎묠?덉뒿?덈떎.', 'success');
    } catch (e) {
        list.innerHTML = '<div class="empty-state">?몄떆?섑듃瑜?媛?몄삤吏 紐삵뻽?듬땲??</div>';
        if (manual) toast('?몄떆?섑듃瑜?媛?몄삤吏 紐삵뻽?듬땲??', 'error');
    } finally {
        if (manual && refreshBtn) {
            refreshBtn.disabled = false;
            refreshBtn.textContent = '?덈줈怨좎묠';
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
                ?꾩옱 ?몄떆?섑듃媛 ?놁뒿?덈떎.<br>
                YARA??猷?留ㅼ묶([Yara DETECT])??諛쒖깮?댁빞 ?앹꽦?섍퀬, ?됱쐞 ?먯????섏떖 ?대깽?멸? 諛쒓껄?섎㈃ ?앹꽦?⑸땲??
            </div>`;
        return;
    }
    const sections = [
        ['active', '?쒖꽦 ?꾪삊', '利됱떆 ??묒씠 ?꾩슂??誘몄“移??몄떆?섑듃', grouped.active],
        ['contained', '寃⑸━/????꾨즺', '寃⑸━, 李⑤떒, ?꾨줈?몄뒪 醫낅즺媛 ?꾨즺???몄떆?섑듃', grouped.contained],
        ['pending', '遺꾩꽍 ?湲?, '異붽? ?뺤씤 ??議곗튂??誘멸껐???몄떆?섑듃', grouped.pending],
        ['kept', '?좎? 愿李?, '?댁쁺?먭? 愿李???곸쑝濡??④릿 ?몄떆?섑듃', grouped.kept]
    ];
    if (grouped.other.length) {
        sections.push(['other', '湲고? ?몄떆?섑듃', '遺꾨쪟 議곌굔 諛뽰쓽 ?곹깭瑜?媛吏??몄떆?섑듃', grouped.other]);
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
            <span>${incidents.length}嫄?/span>
        </div>
        <div class="incident-group-body"></div>`;
    const body = section.querySelector('.incident-group-body');
    if (!incidents.length) {
        body.innerHTML = '<div class="empty-state compact">?대떦 ?몄떆?섑듃媛 ?놁뒿?덈떎.</div>';
        return section;
    }
    incidents.forEach(inc => body.appendChild(renderIncidentCard(inc)));
    return section;
}
function renderIncidentCard(inc) {
    const riskLabel = (inc.risk_label || '').toLowerCase();
    const sevClass = ['critical', 'high'].includes(riskLabel) ? 'high' : riskLabel === 'medium' ? 'medium' : 'low';
    const sevText = riskLabel === 'critical' ? '湲닿툒' : riskLabel === 'high' ? '?믪쓬' : riskLabel === 'medium' ? '以묎컙' : '??쓬';
    const statusMap = {
        pending: ['????湲?, 'detected'],
        quarantined: ['寃⑸━ ?꾨즺', 'quarantined'],
        terminated: ['?꾨줈?몄뒪 醫낅즺', 'terminated'],
        blocked: ['IP 李⑤떒', 'terminated'],
        kept: ['愿李?以?, 'kept']
    };
    const [statusLabel, statusCls] = statusMap[inc.status] || ['泥섎━ 以?, 'detected'];
    const decided = inc.decision && inc.decision !== null;
    const title = inc.rule_description || inc.wazuh_message || '?섏떖 ?꾪삊';
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
                ${inc.risk_score != null ? `<span class="risk-score">?꾪뿕??${esc(inc.risk_score)}</span>` : ''}
                ${suggested && suggested !== 'keep' ? `<span class="suggest-tag">沅뚯옣: ${esc(suggested.toUpperCase())}</span>` : ''}
                <span class="incident-time mono">${esc(inc.created_at || '')}</span>
            </div>
            <div class="incident-title">${esc(title)}</div>
            <div class="incident-meta">
                <div><div class="inc-k">?뚯씪 寃쎈줈</div><div class="inc-v mono">${esc(inc.file_path || '??)}</div></div>
                <div><div class="inc-k">?먯? ?덈꺼</div><div class="inc-v">${esc(inc.wazuh_level || '??)}</div></div>
                <div><div class="inc-k">留ㅼ묶 猷?(YARA)</div><div class="inc-v mono">${esc(yaraRules || '??)}</div></div>
                <div><div class="inc-k">?꾨줈?몄뒪</div><div class="inc-v mono">${esc(inc.process_image || '??)} ${inc.process_id ? '<span style="color:var(--text-3)">(PID '+esc(inc.process_id)+')</span>' : ''}</div></div>
                ${inc.destination_ip ? `<div><div class="inc-k">紐⑹쟻吏 IP</div><div class="inc-v mono">${esc(inc.destination_ip)}${inc.destination_port ? ':'+esc(inc.destination_port) : ''}</div></div>` : ''}
                ${inc.command_line ? `<div><div class="inc-k">而ㅻ㎤?쒕씪??/div><div class="inc-v mono">${esc((inc.command_line || '').slice(0, 80))}</div></div>` : ''}
            </div>
            <div class="incident-actions">
                <button class="inc-btn primary" onclick="openIncidentFolder('${esc(inc.id)}')" ${!inc.file_exists ? 'disabled title="?뚯씪??李얠쓣 ???놁뒿?덈떎"' : ''}>?대뜑 ?닿린</button>
                <button class="inc-btn danger ${suggested === 'quarantine' ? 'recommended' : ''}" onclick="decideIncident('${esc(inc.id)}', 'quarantine')" ${decided || !inc.file_exists ? 'disabled title="寃⑸━???뚯씪??李얠쓣 ???놁뒿?덈떎"' : ''}>?뚯씪 寃⑸━</button>
                <button class="inc-btn warn ${suggested === 'terminate_process' ? 'recommended' : ''}" onclick="decideIncident('${esc(inc.id)}', 'terminate_process')" ${decided || !inc.process_id ? 'disabled' : ''}>?꾨줈?몄뒪 醫낅즺</button>
                <button class="inc-btn warn ${suggested === 'block_ip' ? 'recommended' : ''}" onclick="decideIncident('${esc(inc.id)}', 'block_ip')" ${decided || !inc.destination_ip ? 'disabled' : ''}>IP 李⑤떒</button>
                <button class="inc-btn" onclick="decideIncident('${esc(inc.id)}', 'keep')" ${decided ? 'disabled' : ''}>?좎? 愿李?/button>
            </div>
            ${inc.decision_note ? `<div class="incident-note">?뱷 ${esc(inc.decision_note)}</div>` : ''}
        </div>`;
    return card;
}
async function decideIncident(id, action) {
    try {
        const needsElevation = action === 'terminate_process' || action === 'block_ip';
        if (needsElevation) toast('沅뚰븳??遺議깊븯硫?Windows 愿由ъ옄 ?뱀씤 李쎌씠 ?쒖떆?⑸땲??', 'info');
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
        toast(data.result_message || `${action} 泥섎━ ?꾨즺`, type);
        if (res.ok && data.result_type !== 'error' && data.incident) mergeIncidentUpdate(data.incident);
        await loadIncidents();
    } catch (e) { toast('諛깆뿏???곌껐 ?ㅽ뙣', 'error'); }
}
async function openIncidentFolder(id) {
    try {
        const res = await fetchAuthed(`/api/incidents/${encodeURIComponent(id)}/open-folder`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'opened') toast(`?대뜑 ?대┝: ${data.folder}`, 'success');
        else if (data.status === 'missing folder') toast('?대뜑瑜?李얠쓣 ???놁뒿?덈떎', 'warn');
        else if (data.status === 'missing path') toast('?뚯씪 寃쎈줈媛 ?놁뒿?덈떎', 'warn');
        else toast('?대뜑瑜??????놁뒿?덈떎.', 'warn');
    } catch (e) { toast('諛깆뿏???곌껐 ?ㅽ뙣', 'error'); }
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
 * VIEW 6: 蹂닿퀬?? * ============================================================ */
async function loadReportDates() {
    if (currentUserIsAdmin) $('report-admin-user-wrap').classList.remove('hidden');
    if (!authToken) {
        $('report-content').textContent = '濡쒓렇?몄씠 ?꾩슂?⑸땲??';
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
        dateSelect.innerHTML = '<option value="">?좎쭨瑜??좏깮?섏꽭??/option>';
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
            opt.textContent = `${l.date} (${l.count || 0}嫄?`;
            dateSelect.appendChild(opt);
        });
        dateSelect.value = dates.some(l => l.date === cur) ? cur : '';
        if (!dates.length) {
            $('report-content').textContent = `${source.toUpperCase()} ???濡쒓렇媛 ?놁뒿?덈떎. ?ㅼ떆媛??먯??먯꽌 ?대깽?멸? 諛쒖깮?섎㈃ ?먮룞 ??λ맗?덈떎.`;
            $('report-meta-text').textContent = '議고쉶 媛?ν븳 ?좎쭨媛 ?놁뒿?덈떎.';
            $('report-line-count').textContent = '';
            $('btn-clear-day').disabled = true;
        } else if (!dateSelect.value) {
            $('report-content').textContent = '';
            $('report-meta-text').textContent = '?좎쭨瑜??좏깮?섎㈃ 濡쒓렇瑜??쒖떆?⑸땲??';
            $('report-line-count').textContent = '';
            $('btn-clear-day').disabled = true;
        }
        if (currentUserIsAdmin) await loadUsersForReport();
    } catch (e) {
        $('report-content').textContent = '濡쒓렇 紐⑸줉??媛?몄삤吏 紐삵뻽?듬땲??';
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
        sel.innerHTML = '<option value="">??濡쒓렇</option>';
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
        $('report-meta-text').textContent = '?좎쭨瑜??좏깮?섎㈃ 濡쒓렇瑜??쒖떆?⑸땲??';
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
        const content = (!data.content || data.content === 'Log file not found.') ? '(濡쒓렇 ?놁쓬)' : data.content;
        $('report-content').textContent = content;
        const lines = content === '(濡쒓렇 ?놁쓬)' ? 0 : (content.match(/\n/g) || []).length + 1;
        $('report-meta-text').textContent = `${source.toUpperCase()} 쨌 ${date}${u ? ` 쨌 ${u}` : ''}`;
        $('report-line-count').textContent = `${lines.toLocaleString()} ?쇱씤`;
        $('btn-clear-day').disabled = false;
    } catch (e) {
        $('report-content').textContent = '濡쒓렇瑜?媛?몄삤吏 紐삵뻽?듬땲??';
    }
}
async function clearReportDay() {
    const source = $('report-source').value;
    const date = $('report-date').value;
    if (!source || !date) return;
    if (!confirm(`${date} ${source} 濡쒓렇瑜???젣?섏떆寃좎뒿?덇퉴?`)) return;
    try {
        const res = await fetchAuthed(`/api/logs/${source}/${date}/clear`, { method: 'POST' });
        if (res.ok) {
            toast('?대떦 ?좎쭨??濡쒓렇媛 ??젣?섏뿀?듬땲??', 'success');
            loadReportDates();
            $('report-content').textContent = '';
        } else toast('??젣 ?ㅽ뙣', 'error');
    } catch (e) { toast('諛깆뿏???곌껐 ?ㅽ뙣', 'error'); }
}
async function clearAllLogs() {
    if (!confirm('??紐⑤뱺 濡쒓렇瑜??곴뎄 ??젣?섏떆寃좎뒿?덇퉴? ???묒뾽? ?섎룎由????놁뒿?덈떎.')) return;
    try {
        const res = await fetchAuthed('/api/logs/clear', { method: 'POST' });
        if (res.ok) {
            const data = await res.json();
            toast(`濡쒓렇 ??젣 ?꾨즺 (${data.deleted_db_rows || 0}媛?DB / ${data.deleted_files || 0}媛??뚯씪)`, 'success');
            loadReportDates();
        } else toast('??젣 ?ㅽ뙣', 'error');
    } catch (e) { toast('諛깆뿏???곌껐 ?ㅽ뙣', 'error'); }
}

/* ============================================================
 * VIEW 7: ?ㅼ젙
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
                <span class="role ${isAdmin ? 'admin' : ''}">${isAdmin ? '愿由ъ옄' : '?ъ슜??}</span>`;
            list.appendChild(li);
        });
    } catch (_) {}
}
function toggleDesktopNotif(el) {
    if (el.checked) {
        if (!('Notification' in window)) {
            toast('??釉뚮씪?곗????곗뒪?ы넲 ?뚮┝??吏?먰븯吏 ?딆뒿?덈떎.', 'warn');
            el.checked = false; return;
        }
        Notification.requestPermission().then(permission => {
            desktopNotifEnabled = (permission === 'granted');
            if (!desktopNotifEnabled) {
                el.checked = false;
                toast('?뚮┝ 沅뚰븳??嫄곕??섏뿀?듬땲??', 'warn');
            } else {
                toast('?곗뒪?ы넲 ?뚮┝???쒖꽦?붾릺?덉뒿?덈떎.', 'success');
            }
        });
    } else {
        desktopNotifEnabled = false;
    }
}

/* ============================================================
 * ?뚮┝ ?⑤꼸
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
        toast(`?슚 湲닿툒: ${ev.title}`, 'error');
    }
    if (desktopNotifEnabled && ev.sev === 'high' && Notification.permission === 'granted') {
        try {
            new Notification('EDR 湲닿툒 ?꾪삊 ?먯?', { body: ev.title, tag: ev.id });
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

    $('notif-subhead').textContent = `理쒓렐 24?쒓컙 쨌 ${stats.notifications.length}嫄?쨌 ${stats.notifications.filter(n => !n.read).length} ???쎌쓬`;

    list.innerHTML = '';
    if (!items.length) {
        list.innerHTML = '<li class="notif-empty">?쒖떆???뚮┝???놁뒿?덈떎.</li>';
        return;
    }
    items.slice(0, 30).forEach(n => {
        const li = document.createElement('li');
        li.className = `notif-item ${n.sev}${n.read ? ' read' : ''}`;
        const icon = n.sev === 'high' ? '!' : n.sev === 'medium' ? '?? : '??;
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
 * 紐⑤떖 / ?좎뒪??/ ?좏떥
 * ============================================================ */
function openEventDetail(ev) {
    const modal = $('detail-modal');
    $('modal-sev').textContent = ev.sev === 'high' ? '?믪쓬 ?꾪삊' : ev.sev === 'medium' ? '以묎컙 寃쎄퀬' : '?뺣낫';
    $('modal-sev').className = `sev-badge ${ev.sev === 'high' ? 'crit' : ev.sev}`;
    $('modal-title').textContent = ev.title;
    $('modal-body').innerHTML = `
        <div class="modal-grid">
            <div>
                <h5 class="mini-head">?대깽???뺣낫</h5>
                <div class="kv"><span>?쒓컖</span><span class="mono">${esc(ev.date)} ${esc(ev.time)}</span></div>
                <div class="kv"><span>?붿쭊</span><span>${esc(ev.source.toUpperCase())}</span></div>
                <div class="kv"><span>?ш컖??/span><span>${ev.sev}</span></div>
                <div class="kv"><span>?몄뒪??/span><span>${esc(ev.host)}</span></div>
                <div class="kv"><span>?ъ슜??/span><span>${esc(ev.username || '??)}</span></div>
            </div>
            <div>
                <h5 class="mini-head">?먮낯 硫붿떆吏</h5>
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
    const icons = { success: '??, error: '??, warn: '!', info: '?? };
    t.innerHTML = `<div class="toast-ic">${icons[type] || '??}</div><div>${esc(msg)}</div>`;
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
 * 遺?? * ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
    if (authToken && currentUsername) enterApp();
    else switchAuthMode('login');
    [$('auth-username'), $('auth-password')].forEach(el => {
        el && el.addEventListener('keydown', e => { if (e.key === 'Enter') submitAuth(); });
    });
});
