const API_URL = window.location.origin;
const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/logs`;

let ws;
let isWazuhRunning = false;
let isYaraRunning = false;
let incidentRefreshTimer = null;
let lastDecisionFeedback = null;
const selectedYaraPaths = new Set();
const loadedDirectoryChildren = new Set();

const wazuhLogs = document.getElementById('wazuh-logs');
const yaraLogs = document.getElementById('yara-logs');
const responseSummary = document.getElementById('response-summary');
const responseIncidents = document.getElementById('response-incidents');
const wsStatus = document.getElementById('ws-status');
const yaraModal = document.getElementById('yara-modal');
const yaraDirectoryStatus = document.getElementById('yara-directory-status');
const yaraSelectedSummary = document.getElementById('yara-selected-summary');
const yaraDirectoryList = document.getElementById('yara-directory-list');
const startSelectedYaraButton = document.getElementById('btn-start-yara-selected');

function connectWS() {
    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        wsStatus.textContent = 'Live Connected';
        wsStatus.className = 'online';
        fetchStatus();
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        const msg = `[${data.timestamp}] ${data.message}`;
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
        wsStatus.textContent = 'Disconnected - Retrying...';
        wsStatus.className = 'offline';
        setTimeout(connectWS, 3000);
    };

    ws.onerror = (err) => {
        console.error('WebSocket Error:', err);
        ws.close();
    };
}

async function fetchStatus() {
    try {
        const res = await fetch(`${API_URL}/api/status`);
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
        await fetch(`${API_URL}${endpoint}`, { method: 'POST' });
        updateWazuhUI(!isWazuhRunning);
    } catch (e) {
        alert('Backend server is not responding. Check whether the Python server is running.');
    }
}

async function toggleYara() {
    if (isYaraRunning) {
        try {
            await fetch(`${API_URL}/api/yara/stop`, { method: 'POST' });
            updateYaraUI(false);
        } catch (e) {
            alert('Backend server is not responding. Check whether the Python server is running.');
        }
        return;
    }

    openYaraDirectoryModal();
}

async function injectTestAlert() {
    try {
        const res = await fetch(`${API_URL}/api/wazuh/test-alert`, { method: 'POST' });
        const data = await res.json();
        lastDecisionFeedback = {
            message: data.runtime_test?.status === 'executed'
                ? `Test Wazuh run completed and alert queued: ${data.alert?.syscheck?.path || ''}`.trim()
                : data.runtime_test?.message || 'Test Wazuh alert queued.',
            type: data.runtime_test?.status === 'error' ? 'error' : 'info',
        };
        renderIncidentSummary([]);
        scheduleIncidentRefresh();
    } catch (e) {
        lastDecisionFeedback = {
            message: 'Failed to run the Wazuh runtime test.',
            type: 'error',
        };
        renderIncidentSummary([]);
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
        const res = await fetch(`${API_URL}/api/yara/directories`);
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
        const res = await fetch(url);
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
        await fetch(`${API_URL}/api/yara/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
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
        const res = await fetch(`${API_URL}/api/incidents`);
        const data = await res.json();
        renderIncidents(data.incidents || []);
    } catch (e) {
        responseSummary.textContent = 'Failed to load incidents from the backend.';
    }
}

async function submitIncidentDecision(incidentId, action) {
    try {
        const res = await fetch(`${API_URL}/api/incidents/${incidentId}/decision`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
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
        const res = await fetch(`${API_URL}/api/incidents/${incidentId}/open-folder`, {
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
        output: document.getElementById('wazuh-history-logs'),
        emptyMessage: 'No saved Wazuh detections yet.',
    },
    yara: {
        select: document.getElementById('yara-log-date-select'),
        output: document.getElementById('yara-history-logs'),
        emptyMessage: 'No saved Yara detections yet.',
    },
    response: {
        select: document.getElementById('response-log-date-select'),
        output: document.getElementById('response-history-logs'),
        emptyMessage: 'No saved response actions yet.',
    },
};

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

function renderLogOptions(source, dates) {
    const viewer = logViewers[source];
    viewer.select.innerHTML = '';

    if (!dates.length) {
        viewer.select.innerHTML = '<option value="">No logs</option>';
        viewer.output.textContent = viewer.emptyMessage;
        return;
    }

    dates.forEach((date) => {
        const opt = document.createElement('option');
        opt.value = date;
        opt.textContent = formatDateLabel(date);
        viewer.select.appendChild(opt);
    });
}

async function openLogViewer() {
    modal.style.display = 'block';
    Object.values(logViewers).forEach((viewer) => {
        viewer.select.innerHTML = '<option value="">Loading...</option>';
        viewer.output.textContent = '';
    });

    try {
        const res = await fetch(`${API_URL}/api/logs`);
        const data = await res.json();
        const logsBySource = data.logs || {};

        renderLogOptions('wazuh', logsBySource.wazuh || []);
        renderLogOptions('yara', logsBySource.yara || []);
        renderLogOptions('response', logsBySource.response || []);

        fetchLogContent('wazuh');
        fetchLogContent('yara');
        fetchLogContent('response');
    } catch (e) {
        Object.values(logViewers).forEach((viewer) => {
            viewer.select.innerHTML = '<option value="">Server unavailable</option>';
            viewer.output.textContent = 'The backend server did not respond.';
        });
    }
}

async function fetchLogContent(source) {
    const viewer = logViewers[source];
    const date = viewer.select.value;
    if (!date) {
        return;
    }

    try {
        const res = await fetch(`${API_URL}/api/logs/${source}/${date}`);
        const data = await res.json();
        renderHistoricalLog(viewer, data.content, source);
    } catch (e) {
        viewer.output.textContent = 'Failed to load the selected log.';
    }
}

function closeLogViewer() {
    modal.style.display = 'none';
}

window.onclick = function(event) {
    if (event.target === modal) {
        closeLogViewer();
    }
    if (event.target === yaraModal) {
        closeYaraDirectoryModal();
    }
};

document.addEventListener('keydown', (e) => {
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

wazuhLogs.innerHTML = "<div style='color: #8b949e'>Waiting for events... Press F1 to start Wazuh monitoring.</div>";
yaraLogs.innerHTML = "<div style='color: #8b949e'>Waiting for events... Wazuh alerts with file paths will trigger Yara verification, or press F2 to start a manual scan.</div>";
fetchIncidents();
window.setInterval(fetchIncidents, 5000);
connectWS();
