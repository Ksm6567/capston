const API_URL = window.location.origin;
const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/logs`;

let ws;
let authMode = 'login';
let authToken = localStorage.getItem('siemSessionToken') || '';
let currentUsername = localStorage.getItem('siemUsername') || '';
let currentUserIsAdmin = localStorage.getItem('siemIsAdmin') === 'true';
let logViewerUsername = localStorage.getItem('siemLogViewerUsername') || currentUsername;
let isWazuhRunning = false;
let isYaraRunning = false;
let responseDashboardActive = false;
let testAlertPresets = [];
let incidentRefreshTimer = null;
let incidentPollingHandle = null;
let lastDecisionFeedback = null;
let logClearModeArmed = false;
const selectedYaraPaths = new Set();
const loadedDirectoryChildren = new Set();

const authShell = document.getElementById('auth-shell');
const appShell = document.getElementById('app-shell');
const authFeedback = document.getElementById('auth-feedback');
const authUsernameInput = document.getElementById('auth-username');
const authPasswordInput = document.getElementById('auth-password');
const authSubmitButton = document.getElementById('auth-submit');
const loginTab = document.getElementById('tab-login');
const registerTab = document.getElementById('tab-register');
const userChip = document.getElementById('user-chip');
const topbarSectionLabel = document.getElementById('topbar-section-label');
const topbarTitle = document.getElementById('topbar-title');
const wazuhLogs = document.getElementById('wazuh-logs');
const yaraLogs = document.getElementById('yara-logs');
const responseSummary = document.getElementById('response-summary');
const responseIncidents = document.getElementById('response-incidents');
const wsStatus = document.getElementById('ws-status');
const responseDashboard = document.getElementById('response-dashboard');
const responsePanelLabel = document.getElementById('response-panel-label');
const responsePanelTitle = document.getElementById('response-panel-title');
const responsePanelCopy = document.getElementById('response-panel-copy');
const monitorConsoleGrid = document.getElementById('monitor-console-grid');
const yaraModal = document.getElementById('yara-modal');
const testAlertModal = document.getElementById('test-alert-modal');
const testAlertPresetSelect = document.getElementById('test-alert-preset-select');
const testAlertPresetDescription = document.getElementById('test-alert-preset-description');
const runTestAlertButton = document.getElementById('btn-run-test-alert');
const yaraDirectoryStatus = document.getElementById('yara-directory-status');
const yaraSelectedSummary = document.getElementById('yara-selected-summary');
const yaraDirectoryList = document.getElementById('yara-directory-list');
const startSelectedYaraButton = document.getElementById('btn-start-yara-selected');
const logClearToggleButton = document.getElementById('btn-log-clear-toggle');
const clearMyLogsButton = document.getElementById('btn-clear-my-logs');
const adminLogUserPicker = document.getElementById('admin-log-user-picker');
const logUserSelect = document.getElementById('log-user-select');

function setAuthFeedback(message, type = 'info') {
    authFeedback.textContent = message;
    authFeedback.className = 'auth-feedback';
    if (type !== 'info') {
        authFeedback.classList.add(type);
    }
}

function buildLogQueryString() {
    const params = new URLSearchParams();
    if (currentUserIsAdmin && logViewerUsername && logViewerUsername !== currentUsername) {
        params.set('username', logViewerUsername);
    }
    const query = params.toString();
    return query ? `?${query}` : '';
}

function isViewingOwnLogs() {
    return !currentUserIsAdmin || !logViewerUsername || logViewerUsername === currentUsername;
}

function syncAdminLogFilterVisibility() {
    adminLogUserPicker.classList.toggle('history-user-filter-hidden', !currentUserIsAdmin);
}

function setResponseDashboardActive(active) {
    responseDashboardActive = active;
    const responseButton = document.getElementById('btn-response');
    responseButton.classList.toggle('active-response', active);
    responseDashboard.classList.toggle('response-focus', active);
    monitorConsoleGrid.classList.toggle('console-grid-hidden', active);

    if (active) {
        topbarSectionLabel.textContent = 'Response';
        topbarTitle.textContent = 'Incident Dashboard';
        responsePanelLabel.textContent = 'Response Workflow';
        responsePanelTitle.textContent = 'Malware containment and response actions';
        responsePanelCopy.textContent = 'Review detections, remove malicious files, open suspicious folders, and keep or stop response actions from one focused dashboard.';
        responseDashboard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        return;
    }

    topbarSectionLabel.textContent = 'Overview';
    topbarTitle.textContent = 'Logs';
    responsePanelLabel.textContent = 'Selected Panel';
    responsePanelTitle.textContent = 'Real-time incident board';
    responsePanelCopy.textContent = 'Open incidents, current response recommendations, and monitoring health appear here first.';
}

function toggleResponseDashboard() {
    setResponseDashboardActive(!responseDashboardActive);
}

function switchAuthMode(mode) {
    authMode = mode;
    loginTab.classList.toggle('active', mode === 'login');
    registerTab.classList.toggle('active', mode === 'register');
    authSubmitButton.textContent = mode === 'login' ? 'Sign In' : 'Create Account';
    authPasswordInput.autocomplete = mode === 'login' ? 'current-password' : 'new-password';
    setAuthFeedback(
        mode === 'login'
            ? 'Default admin account: admin / admin1234'
            : 'New user accounts are stored in the central server database.'
    );
}

function authHeaders(includeJson = false) {
    const headers = {};
    if (authToken) {
        headers['X-Session-Token'] = authToken;
    }
    if (includeJson) {
        headers['Content-Type'] = 'application/json';
    }
    return headers;
}

async function fetchAuthed(path, options = {}) {
    const headers = {
        ...authHeaders(options.body !== undefined),
        ...(options.headers || {}),
    };
    const response = await fetch(`${API_URL}${path}`, { ...options, headers });
    if (response.status === 401) {
        forceLogout('Your session expired. Please sign in again.');
        throw new Error('Unauthorized');
    }
    return response;
}

async function submitAuth() {
    const username = authUsernameInput.value.trim();
    const password = authPasswordInput.value;

    if (!username || !password) {
        setAuthFeedback('Enter both a username and password.', 'error');
        return;
    }

    if (authMode === 'register') {
        try {
            const response = await fetch(`${API_URL}/api/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });
            const data = await response.json();
            if (data.status !== 'created') {
                setAuthFeedback(data.message || 'Failed to create the account.', 'error');
                return;
            }
            setAuthFeedback('Account created. Sign in with the new user now.', 'success');
            switchAuthMode('login');
            authPasswordInput.value = '';
        } catch (error) {
            setAuthFeedback('Registration request failed.', 'error');
        }
        return;
    }

    try {
        const response = await fetch(`${API_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        if (!response.ok) {
            const payload = await response.json().catch(() => ({}));
            setAuthFeedback(payload.detail || 'Sign in failed.', 'error');
            return;
        }

        const data = await response.json();
        authToken = data.token;
        currentUsername = data.user.username;
        currentUserIsAdmin = Boolean(data.user.is_admin);
        logViewerUsername = currentUsername;
        localStorage.setItem('siemSessionToken', authToken);
        localStorage.setItem('siemUsername', currentUsername);
        localStorage.setItem('siemIsAdmin', String(currentUserIsAdmin));
        localStorage.setItem('siemLogViewerUsername', logViewerUsername);
        authPasswordInput.value = '';
        applyAuthenticatedState();
    } catch (error) {
        setAuthFeedback('Sign in request failed.', 'error');
    }
}

function applyAuthenticatedState() {
    authShell.classList.add('app-hidden');
    appShell.classList.remove('app-hidden');
    userChip.textContent = currentUsername;
    syncAdminLogFilterVisibility();
    setResponseDashboardActive(false);
    wazuhLogs.innerHTML = "<div style='color: #8b949e'>Waiting for events... Press F1 to start Wazuh monitoring.</div>";
    yaraLogs.innerHTML = "<div style='color: #8b949e'>Waiting for events... Wazuh alerts with file paths will trigger Yara verification, or press F2 to start a manual scan.</div>";
    connectWS();
    fetchStatus();

    if (incidentPollingHandle) {
        clearInterval(incidentPollingHandle);
    }
    incidentPollingHandle = window.setInterval(fetchIncidents, 5000);
}

function forceLogout(message) {
    authToken = '';
    currentUsername = '';
    currentUserIsAdmin = false;
    logViewerUsername = '';
    localStorage.removeItem('siemSessionToken');
    localStorage.removeItem('siemUsername');
    localStorage.removeItem('siemIsAdmin');
    localStorage.removeItem('siemLogViewerUsername');
    authShell.classList.remove('app-hidden');
    appShell.classList.add('app-hidden');
    wsStatus.textContent = 'Disconnected';
    wsStatus.className = 'offline';
    if (ws) {
        ws.close();
        ws = null;
    }
    if (incidentPollingHandle) {
        clearInterval(incidentPollingHandle);
        incidentPollingHandle = null;
    }
    setResponseDashboardActive(false);
    syncAdminLogFilterVisibility();
    setAuthFeedback(message || 'Sign in to open the dashboard.');
}

async function restoreSession() {
    if (!authToken) {
        return;
    }

    try {
        const response = await fetchAuthed('/api/auth/me');
        const data = await response.json();
        currentUsername = data.user.username;
        currentUserIsAdmin = Boolean(data.user.is_admin);
        logViewerUsername = currentUsername;
        localStorage.setItem('siemUsername', currentUsername);
        localStorage.setItem('siemIsAdmin', String(currentUserIsAdmin));
        localStorage.setItem('siemLogViewerUsername', logViewerUsername);
        applyAuthenticatedState();
    } catch (error) {
        forceLogout('Please sign in again.');
    }
}

async function logout() {
    try {
        await fetchAuthed('/api/auth/logout', { method: 'POST' });
    } catch (error) {
        // local cleanup continues below
    }
    forceLogout('Signed out.');
}

function connectWS() {
    if (!authToken) {
        return;
    }

    if (ws) {
        ws.close();
    }

    ws = new WebSocket(`${WS_URL}?token=${encodeURIComponent(authToken)}`);

    ws.onopen = () => {
        wsStatus.textContent = 'Live Connected';
        wsStatus.className = 'online';
        fetchStatus();
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        const owner = data.username ? ` [${data.username}]` : '';
        const msg = `[${data.timestamp}]${owner} ${data.message}`;
        const entry = document.createElement('div');
        entry.textContent = msg;
        entry.style.marginBottom = '5px';

        if (data.source === 'wazuh') {
            wazuhLogs.appendChild(entry);
            wazuhLogs.scrollTop = wazuhLogs.scrollHeight;
        } else if (data.source === 'yara') {
            yaraLogs.appendChild(entry);
            yaraLogs.scrollTop = yaraLogs.scrollHeight;
        } else if (data.source === 'response') {
            scheduleIncidentRefresh();
        }
    };

    ws.onclose = () => {
        wsStatus.textContent = authToken ? 'Disconnected - Retrying...' : 'Disconnected';
        wsStatus.className = 'offline';
        if (authToken) {
            setTimeout(connectWS, 3000);
        }
    };

    ws.onerror = (err) => {
        console.error('WebSocket Error:', err);
        ws.close();
    };
}

async function fetchStatus() {
    try {
        const res = await fetchAuthed('/api/status');
        const data = await res.json();
        updateWazuhUI(data.wazuh_running);
        updateYaraUI(data.yara_running);
        fetchIncidents();
    } catch (e) {
        console.error('API Offline', e);
    }
}

async function toggleWazuh() {
    const endpoint = isWazuhRunning ? '/api/wazuh/stop' : '/api/wazuh/start';
    try {
        await fetchAuthed(endpoint, { method: 'POST' });
        updateWazuhUI(!isWazuhRunning);
    } catch (e) {
        alert('Backend server is not responding. Check whether the Python server is running.');
    }
}

async function toggleYara() {
    if (isYaraRunning) {
        try {
            await fetchAuthed('/api/yara/stop', { method: 'POST' });
            updateYaraUI(false);
        } catch (e) {
            alert('Backend server is not responding. Check whether the Python server is running.');
        }
        return;
    }

    openYaraDirectoryModal();
}

function updateTestAlertPresetDetails() {
    const preset = testAlertPresets.find((item) => item.id === testAlertPresetSelect.value);
    if (!preset) {
        testAlertPresetDescription.textContent = 'Select a safe test scenario.';
        runTestAlertButton.disabled = true;
        return;
    }

    testAlertPresetDescription.textContent = `${preset.description} ${preset.execute_runtime_test ? 'This preset also runs a safe local marker script inside the test folder.' : 'This preset only creates a harmless file artifact.'}`;
    runTestAlertButton.disabled = false;
}

async function openTestAlertModal() {
    testAlertModal.style.display = 'block';
    testAlertPresetSelect.innerHTML = '<option value="">Loading...</option>';
    testAlertPresetDescription.textContent = 'Loading preset details...';
    runTestAlertButton.disabled = true;

    try {
        const res = await fetchAuthed('/api/wazuh/test-alert-presets');
        const data = await res.json();
        testAlertPresets = Array.isArray(data.presets) ? data.presets : [];
        testAlertPresetSelect.innerHTML = '';

        testAlertPresets.forEach((preset) => {
            const option = document.createElement('option');
            option.value = preset.id;
            option.textContent = preset.label;
            testAlertPresetSelect.appendChild(option);
        });

        if (testAlertPresets.length) {
            testAlertPresetSelect.value = testAlertPresets[0].id;
        } else {
            testAlertPresetSelect.innerHTML = '<option value="">No presets available</option>';
        }
        updateTestAlertPresetDetails();
    } catch (error) {
        testAlertPresetSelect.innerHTML = '<option value="">Failed to load presets</option>';
        testAlertPresetDescription.textContent = 'Failed to load safe test presets from the backend.';
    }
}

function closeTestAlertModal() {
    testAlertModal.style.display = 'none';
}

async function runSelectedTestAlert() {
    const presetId = testAlertPresetSelect.value;
    if (!presetId) {
        return;
    }

    try {
        runTestAlertButton.disabled = true;
        const res = await fetchAuthed('/api/wazuh/test-alert', {
            method: 'POST',
            body: JSON.stringify({ preset_id: presetId }),
        });
        const data = await res.json();
        lastDecisionFeedback = {
            message: `${data.preset_label || 'Test alert'} queued. ${data.runtime_test?.message || ''}`.trim(),
            type: data.runtime_test?.status === 'error' ? 'error' : 'info',
        };
        closeTestAlertModal();
        renderIncidentSummary([]);
        scheduleIncidentRefresh();
    } catch (e) {
        lastDecisionFeedback = {
            message: 'Failed to run the Wazuh runtime test.',
            type: 'error',
        };
        renderIncidentSummary([]);
    } finally {
        runTestAlertButton.disabled = false;
    }
}

function updateWazuhUI(isRunning) {
    isWazuhRunning = isRunning;
    const btn = document.getElementById('btn-wazuh');
    btn.classList.toggle('active-wazuh', isRunning);
    btn.querySelector('.nav-btn-title').textContent = 'Wazuh';
    btn.querySelector('.nav-btn-copy').textContent = isRunning
        ? 'Monitoring active. Press F1 to stop the stream.'
        : 'Live event stream and detection feed. Press F1 to start.';
}

function updateYaraUI(isRunning) {
    isYaraRunning = isRunning;
    const btn = document.getElementById('btn-yara');
    btn.classList.toggle('active-yara', isRunning);
    btn.querySelector('.nav-btn-title').textContent = 'YARA';
    btn.querySelector('.nav-btn-copy').textContent = isRunning
        ? 'Scan monitoring active. Press F2 to stop YARA.'
        : 'Rule scan results and folder targets. Press F2 to start.';
}

function scheduleIncidentRefresh() {
    if (incidentRefreshTimer) {
        window.clearTimeout(incidentRefreshTimer);
    }

    incidentRefreshTimer = window.setTimeout(() => {
        fetchIncidents();
    }, 200);
}

async function openYaraDirectoryModal() {
    yaraModal.style.display = 'block';
    yaraDirectoryStatus.textContent = 'Loading drives...';
    yaraDirectoryList.innerHTML = '';
    loadedDirectoryChildren.clear();
    startSelectedYaraButton.disabled = selectedYaraPaths.size === 0;
    updateYaraSelectionState();

    try {
        const res = await fetchAuthed('/api/yara/directories');
        const data = await res.json();
        renderDirectoryRoots(data.directories || []);
    } catch (e) {
        yaraDirectoryStatus.textContent = 'Failed to load drives from the backend.';
        startSelectedYaraButton.disabled = true;
    }
}

function closeYaraDirectoryModal() {
    yaraModal.style.display = 'none';
}

function renderDirectoryRoots(directories) {
    yaraDirectoryList.innerHTML = '';

    if (!directories.length) {
        yaraDirectoryStatus.textContent = 'No selectable drives were found.';
        startSelectedYaraButton.disabled = true;
        return;
    }

    yaraDirectoryStatus.textContent = 'Expand only the folders you need. This keeps the directory loader fast.';

    directories.forEach((directory) => {
        yaraDirectoryList.appendChild(createDirectoryNode(directory));
    });
}

function createDirectoryNode(directory) {
    const wrapper = document.createElement('div');
    wrapper.className = 'directory-tree-node';
    wrapper.dataset.path = directory.path;

    const row = document.createElement('div');
    row.className = 'directory-option';
    if (directory.depth === 0) {
        row.classList.add('directory-option-drive');
    }
    row.style.paddingLeft = `${16 + directory.depth * 18}px`;

    const expandButton = document.createElement('button');
    expandButton.type = 'button';
    expandButton.className = 'tree-toggle';
    expandButton.textContent = directory.depth === 0 ? '+' : '>';
    expandButton.addEventListener('click', () => toggleDirectoryNode(wrapper, directory, expandButton));

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = directory.path;
    checkbox.checked = selectedYaraPaths.has(directory.path);
    checkbox.addEventListener('change', () => {
        if (checkbox.checked) {
            selectedYaraPaths.add(directory.path);
        } else {
            selectedYaraPaths.delete(directory.path);
        }
        updateYaraSelectionState();
    });

    const info = document.createElement('div');
    info.className = 'directory-meta';

    const title = document.createElement('strong');
    title.textContent = directory.label;

    const path = document.createElement('span');
    path.textContent = directory.path;

    info.appendChild(title);
    info.appendChild(path);
    row.appendChild(expandButton);
    row.appendChild(checkbox);
    row.appendChild(info);
    wrapper.appendChild(row);

    const childrenContainer = document.createElement('div');
    childrenContainer.className = 'directory-children';
    wrapper.appendChild(childrenContainer);

    return wrapper;
}

async function toggleDirectoryNode(wrapper, directory, expandButton) {
    const childrenContainer = wrapper.querySelector('.directory-children');
    const isOpen = wrapper.classList.contains('expanded');

    if (isOpen) {
        wrapper.classList.remove('expanded');
        expandButton.textContent = directory.depth === 0 ? '+' : '>';
        return;
    }

    wrapper.classList.add('expanded');
    expandButton.textContent = '-';

    if (loadedDirectoryChildren.has(directory.path)) {
        return;
    }

    childrenContainer.innerHTML = '<div class="directory-loading">Loading subfolders...</div>';
    try {
        const url = new URL(`${API_URL}/api/yara/directories/children`);
        url.searchParams.set('path', directory.path);
        const res = await fetch(url, { headers: authHeaders() });
        if (res.status === 401) {
            forceLogout('Your session expired. Please sign in again.');
            return;
        }
        const data = await res.json();
        const children = data.directories || [];
        loadedDirectoryChildren.add(directory.path);

        childrenContainer.innerHTML = '';
        if (!children.length) {
            childrenContainer.innerHTML = '<div class="directory-loading">No subfolders</div>';
            return;
        }

        children.forEach((child) => {
            childrenContainer.appendChild(createDirectoryNode(child));
        });
    } catch (e) {
        childrenContainer.innerHTML = '<div class="directory-loading">Failed to load subfolders</div>';
    }
}

function updateYaraSelectionState() {
    const selected = Array.from(selectedYaraPaths);
    startSelectedYaraButton.disabled = selected.length === 0;

    if (selected.length === 0) {
        yaraDirectoryStatus.textContent = 'Expand a drive and select at least one folder to start a scan.';
        yaraSelectedSummary.textContent = 'No folders selected.';
        return;
    }

    yaraDirectoryStatus.textContent = 'Initial scan and later change monitoring will run only on the selected folders.';
    yaraSelectedSummary.textContent = `${selected.length} selected: ${selected.slice(0, 3).join(', ')}${selected.length > 3 ? ' ...' : ''}`;
}

async function startSelectedYaraScan() {
    const targetPaths = Array.from(selectedYaraPaths);
    if (!targetPaths.length) {
        updateYaraSelectionState();
        return;
    }

    startSelectedYaraButton.disabled = true;

    try {
        await fetchAuthed('/api/yara/start', {
            method: 'POST',
            body: JSON.stringify({ target_paths: targetPaths }),
        });
        updateYaraUI(true);
        closeYaraDirectoryModal();
    } catch (e) {
        yaraDirectoryStatus.textContent = 'Failed to start the selected Yara scan.';
    } finally {
        startSelectedYaraButton.disabled = false;
    }
}

function buildRiskLabel(incident) {
    return `${incident.risk_label.toUpperCase()} ${incident.risk_score}`;
}

function renderIncidentSummary(incidents) {
    const activeIncidents = incidents.filter((incident) => incident.status === 'pending');
    responseSummary.className = 'response-summary';

    if (lastDecisionFeedback) {
        responseSummary.textContent = lastDecisionFeedback.message;
        responseSummary.classList.add(`response-summary-${lastDecisionFeedback.type}`);
        return;
    }

    if (!activeIncidents.length) {
        responseSummary.textContent = 'No incidents yet. Start Wazuh monitoring and wait for an alert with a file path.';
        return;
    }

    const pending = activeIncidents.length;
    const critical = activeIncidents.filter((incident) => incident.risk_label === 'critical').length;
    const high = activeIncidents.filter((incident) => incident.risk_label === 'high').length;
    responseSummary.textContent = `Open incidents ${pending} | Critical ${critical} | High ${high}`;
}

function renderIncidents(incidents) {
    const activeIncidents = incidents.filter((incident) => incident.status === 'pending');
    responseIncidents.innerHTML = '';
    renderIncidentSummary(incidents);

    if (!activeIncidents.length) {
        const empty = document.createElement('div');
        empty.className = 'incident-empty';
        empty.textContent = 'No response decisions are waiting right now.';
        responseIncidents.appendChild(empty);
        return;
    }

    activeIncidents.forEach((incident) => {
        const card = document.createElement('article');
        card.className = `incident-card risk-${incident.risk_label}`;

        const header = document.createElement('div');
        header.className = 'incident-header';

        const title = document.createElement('strong');
        title.textContent = buildRiskLabel(incident);

        const status = document.createElement('span');
        status.className = `incident-status status-${incident.status}`;
        status.textContent = incident.status.toUpperCase();

        header.appendChild(title);
        header.appendChild(status);

        const meta = document.createElement('div');
        meta.className = 'incident-meta';
        meta.textContent = `${incident.created_at} | Wazuh level ${incident.wazuh_level} | Yara ${incident.yara_status}`;

        const message = document.createElement('div');
        message.className = 'incident-message';
        message.textContent = incident.wazuh_message;

        const file = document.createElement('div');
        file.className = 'incident-path';
        file.textContent = incident.file_path || 'No file path captured from this event.';

        const fileState = document.createElement('div');
        fileState.className = `incident-file-state ${incident.file_exists ? 'file-present' : 'file-missing'}`;
        fileState.textContent = incident.file_exists
            ? 'Delete target is available.'
            : 'Delete target does not exist on disk.';

        const yara = document.createElement('div');
        yara.className = 'incident-yara';
        yara.textContent = incident.yara_matches.length
            ? `Yara matches: ${incident.yara_matches.join(', ')}`
            : `Yara result: ${incident.yara_status}`;

        const suggestion = document.createElement('div');
        suggestion.className = 'incident-suggestion';
        suggestion.textContent = `Suggested decision: ${incident.suggested_decision.toUpperCase()}`;

        const note = document.createElement('div');
        note.className = 'incident-note';
        note.textContent = incident.decision_note;

        const actions = document.createElement('div');
        actions.className = 'incident-actions';

        const openFolderButton = document.createElement('button');
        openFolderButton.type = 'button';
        openFolderButton.className = 'btn ghost';
        openFolderButton.textContent = 'Open Folder';
        openFolderButton.disabled = !incident.file_exists;
        openFolderButton.addEventListener('click', () => openIncidentFolder(incident.id));

        const deleteButton = document.createElement('button');
        deleteButton.type = 'button';
        deleteButton.className = 'btn danger';
        deleteButton.textContent = 'Delete';
        deleteButton.disabled = !incident.file_exists;
        deleteButton.addEventListener('click', () => submitIncidentDecision(incident.id, 'delete'));

        const keepButton = document.createElement('button');
        keepButton.type = 'button';
        keepButton.className = 'btn ghost';
        keepButton.textContent = 'Keep';
        keepButton.addEventListener('click', () => submitIncidentDecision(incident.id, 'keep'));

        actions.appendChild(openFolderButton);
        actions.appendChild(deleteButton);
        actions.appendChild(keepButton);

        card.appendChild(header);
        card.appendChild(meta);
        card.appendChild(message);
        card.appendChild(file);
        card.appendChild(fileState);
        card.appendChild(yara);
        card.appendChild(suggestion);
        card.appendChild(note);
        card.appendChild(actions);
        responseIncidents.appendChild(card);
    });
}

async function fetchIncidents() {
    try {
        const res = await fetchAuthed('/api/incidents');
        const data = await res.json();
        renderIncidents(data.incidents || []);
    } catch (e) {
        responseSummary.textContent = 'Failed to load incidents from the backend.';
    }
}

async function submitIncidentDecision(incidentId, action) {
    try {
        const res = await fetchAuthed(`/api/incidents/${incidentId}/decision`, {
            method: 'POST',
            body: JSON.stringify({ action }),
        });
        const data = await res.json();
        lastDecisionFeedback = {
            message: data.result_message || 'The incident decision was processed.',
            type: data.result_type || (data.status === 'error' ? 'error' : 'info'),
        };
        fetchIncidents();
    } catch (e) {
        lastDecisionFeedback = {
            message: 'Failed to submit the response decision.',
            type: 'error',
        };
        renderIncidentSummary([]);
    }
}

async function openIncidentFolder(incidentId) {
    try {
        const res = await fetchAuthed(`/api/incidents/${incidentId}/open-folder`, {
            method: 'POST',
        });
        const data = await res.json();
        if (data.status !== 'opened') {
            alert('Failed to open the folder for this incident.');
        }
    } catch (e) {
        alert('Failed to open the folder for this incident.');
    }
}

const modal = document.getElementById('log-modal');
const logViewers = {
    wazuh: {
        select: document.getElementById('wazuh-log-date-select'),
        deleteButton: document.getElementById('btn-clear-wazuh-log-date'),
        output: document.getElementById('wazuh-history-logs'),
        emptyMessage: 'No saved Wazuh detections yet.',
    },
    yara: {
        select: document.getElementById('yara-log-date-select'),
        deleteButton: document.getElementById('btn-clear-yara-log-date'),
        output: document.getElementById('yara-history-logs'),
        emptyMessage: 'No saved Yara detections yet.',
    },
    response: {
        select: document.getElementById('response-log-date-select'),
        deleteButton: document.getElementById('btn-clear-response-log-date'),
        output: document.getElementById('response-history-logs'),
        emptyMessage: 'No saved response actions yet.',
    },
};

async function loadAdminLogUsers() {
    if (!currentUserIsAdmin) {
        return;
    }

    logUserSelect.innerHTML = '<option value="">Loading...</option>';
    try {
        const res = await fetchAuthed('/api/users');
        const data = await res.json();
        const users = Array.isArray(data.users) ? data.users : [];
        logUserSelect.innerHTML = '';

        users.forEach((username) => {
            const option = document.createElement('option');
            option.value = username;
            option.textContent = username === currentUsername ? `${username} (Me)` : username;
            logUserSelect.appendChild(option);
        });

        if (!users.includes(logViewerUsername)) {
            logViewerUsername = currentUsername;
        }
        logUserSelect.value = logViewerUsername || currentUsername;
        localStorage.setItem('siemLogViewerUsername', logViewerUsername || currentUsername);
        setLogClearMode(logClearModeArmed);
    } catch (error) {
        logUserSelect.innerHTML = '<option value="">Failed to load users</option>';
    }
}

async function changeLogViewerUser() {
    if (!currentUserIsAdmin) {
        return;
    }

    logViewerUsername = logUserSelect.value || currentUsername;
    localStorage.setItem('siemLogViewerUsername', logViewerUsername);
    setLogClearMode(logClearModeArmed);
    try {
        await refreshLogViewerData({
            wazuh: '',
            yara: '',
            response: '',
        });
    } catch (error) {
        Object.values(logViewers).forEach((viewer) => {
            viewer.output.textContent = 'Failed to load the selected user logs.';
        });
    }
}

function formatDateLabel(dateString) {
    const weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const date = new Date(`${dateString}T00:00:00`);
    if (Number.isNaN(date.getTime())) {
        return dateString;
    }

    return `${dateString} (${weekdays[date.getDay()]})`;
}

function renderHistoricalLog(viewer, content, source) {
    viewer.output.innerHTML = '';

    if (!content || content === 'Log file not found.') {
        viewer.output.textContent = viewer.emptyMessage;
        return;
    }

    const lines = content
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);

    if (!lines.length) {
        viewer.output.textContent = viewer.emptyMessage;
        return;
    }

    const list = document.createElement('div');
    list.className = `history-list ${source}`;

    lines.forEach((line) => {
        const card = document.createElement('article');
        card.className = 'history-entry';

        const timeMatch = line.match(/^\[(.*?)\]\s*(.*)$/);
        const time = document.createElement('div');
        time.className = 'history-entry-time';
        time.textContent = timeMatch ? timeMatch[1] : '--:--:--';

        const message = document.createElement('div');
        message.className = 'history-entry-message';
        message.textContent = timeMatch ? timeMatch[2] : line;

        card.appendChild(time);
        card.appendChild(message);
        list.appendChild(card);
    });

    viewer.output.appendChild(list);
}

function updateLogDeleteButton(source) {
    const viewer = logViewers[source];
    viewer.deleteButton.disabled = !logClearModeArmed || !viewer.select.value || !isViewingOwnLogs();
}

function renderLogOptions(source, dates, preferredDate = '') {
    const viewer = logViewers[source];
    viewer.select.innerHTML = '';

    if (!dates.length) {
        viewer.select.innerHTML = '<option value="">No logs</option>';
        viewer.output.textContent = viewer.emptyMessage;
        updateLogDeleteButton(source);
        return;
    }

    dates.forEach((date) => {
        const opt = document.createElement('option');
        opt.value = date;
        opt.textContent = formatDateLabel(date);
        viewer.select.appendChild(opt);
    });

    const nextDate = preferredDate && dates.includes(preferredDate) ? preferredDate : dates[0];
    viewer.select.value = nextDate;
    updateLogDeleteButton(source);
}

function getSelectedLogDates() {
    return Object.fromEntries(
        Object.entries(logViewers).map(([source, viewer]) => [source, viewer.select.value || ''])
    );
}

async function refreshLogViewerData(preferredDates = getSelectedLogDates()) {
    const res = await fetchAuthed(`/api/logs${buildLogQueryString()}`);
    const data = await res.json();
    const logsBySource = data.logs || {};

    Object.keys(logViewers).forEach((source) => {
        renderLogOptions(source, logsBySource[source] || [], preferredDates[source] || '');
    });

    await Promise.all(Object.keys(logViewers).map((source) => fetchLogContent(source)));
}

async function openLogViewer() {
    modal.style.display = 'block';
    syncAdminLogFilterVisibility();
    Object.values(logViewers).forEach((viewer) => {
        viewer.select.innerHTML = '<option value="">Loading...</option>';
        viewer.output.textContent = '';
    });

    try {
        if (currentUserIsAdmin) {
            await loadAdminLogUsers();
        }
        await refreshLogViewerData({
            wazuh: '',
            yara: '',
            response: '',
        });
    } catch (e) {
        Object.values(logViewers).forEach((viewer) => {
            viewer.select.innerHTML = '<option value="">Server unavailable</option>';
            viewer.output.textContent = 'The backend server did not respond.';
            viewer.deleteButton.disabled = true;
        });
    }
}

async function fetchLogContent(source) {
    const viewer = logViewers[source];
    const date = viewer.select.value;
    updateLogDeleteButton(source);
    if (!date) {
        viewer.output.textContent = viewer.emptyMessage;
        return;
    }

    try {
        const res = await fetchAuthed(`/api/logs/${source}/${date}${buildLogQueryString()}`);
        const data = await res.json();
        renderHistoricalLog(viewer, data.content, source);
    } catch (e) {
        viewer.output.textContent = 'Failed to load the selected log.';
    }
}

function closeLogViewer() {
    modal.style.display = 'none';
    setLogClearMode(false);
}

function setLogClearMode(armed) {
    logClearModeArmed = armed;
    logClearToggleButton.textContent = armed ? 'Clear Mode On' : 'Clear Mode Off';
    logClearToggleButton.classList.toggle('toggle-armed', armed);
    clearMyLogsButton.disabled = !armed || !isViewingOwnLogs();
    Object.keys(logViewers).forEach((source) => updateLogDeleteButton(source));
}

function toggleLogClearMode() {
    setLogClearMode(!logClearModeArmed);
}

async function clearMyLogs() {
    if (!logClearModeArmed) {
        return;
    }

    try {
        const res = await fetchAuthed('/api/logs/clear', { method: 'POST' });
        const data = await res.json();
        lastDecisionFeedback = {
            message: `Cleared your saved logs. DB rows: ${data.deleted_db_rows || 0}, files: ${data.deleted_files || 0}.`,
            type: 'success',
        };
        await refreshLogViewerData({
            wazuh: '',
            yara: '',
            response: '',
        });
        wazuhLogs.innerHTML = '';
        yaraLogs.innerHTML = '';
        responseIncidents.innerHTML = '';
        renderIncidentSummary([]);
        setLogClearMode(false);
    } catch (e) {
        lastDecisionFeedback = {
            message: 'Failed to clear your saved logs.',
            type: 'error',
        };
        renderIncidentSummary([]);
    }
}

async function clearSelectedLogDate(source) {
    if (!logClearModeArmed) {
        return;
    }

    const viewer = logViewers[source];
    const date = viewer.select.value;
    if (!date) {
        return;
    }

    try {
        const res = await fetchAuthed(`/api/logs/${source}/${date}/clear`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || 'Failed to clear the selected day.');
        }

        lastDecisionFeedback = {
            message: `Deleted ${source.toUpperCase()} logs for ${formatDateLabel(date)}. DB rows: ${data.deleted_db_rows || 0}, files: ${data.deleted_files || 0}.`,
            type: 'success',
        };
        const preferredDates = getSelectedLogDates();
        preferredDates[source] = '';
        await refreshLogViewerData(preferredDates);
    } catch (e) {
        lastDecisionFeedback = {
            message: 'Failed to clear the selected log date.',
            type: 'error',
        };
    }

    renderIncidentSummary([]);
}

window.onclick = function(event) {
    if (event.target === modal) {
        closeLogViewer();
    }
    if (event.target === yaraModal) {
        closeYaraDirectoryModal();
    }
    if (event.target === testAlertModal) {
        closeTestAlertModal();
    }
};

document.addEventListener('keydown', (e) => {
    if (document.activeElement === authUsernameInput || document.activeElement === authPasswordInput) {
        if (e.key === 'Enter') {
            submitAuth();
        }
        return;
    }

    if (!authToken) {
        return;
    }

    if (e.key === 'F1') {
        e.preventDefault();
        toggleWazuh();
    }
    if (e.key === 'F2') {
        e.preventDefault();
        toggleYara();
    }
    if (e.key === 'F3') {
        e.preventDefault();
        openLogViewer();
    }
});

switchAuthMode('login');
setLogClearMode(false);
restoreSession();
