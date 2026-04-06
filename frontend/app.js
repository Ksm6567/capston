const API_URL = "http://127.0.0.1:8000";
const WS_URL = "ws://127.0.0.1:8000/ws/logs";

let ws;
let isSuricataRunning = false;
let isYaraRunning = false;
const selectedYaraPaths = new Set();
const loadedDirectoryChildren = new Set();

const suriLogs = document.getElementById('suricata-logs');
const yaraLogs = document.getElementById('yara-logs');
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

        if (data.source === 'suricata') {
            suriLogs.appendChild(entry);
            suriLogs.scrollTop = suriLogs.scrollHeight;
        } else if (data.source === 'yara') {
            yaraLogs.appendChild(entry);
            yaraLogs.scrollTop = yaraLogs.scrollHeight;
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
        updateSuricataUI(data.suricata_running);
        updateYaraUI(data.yara_running);
    } catch (e) {
        console.error('API Offline', e);
    }
}

async function toggleSuricata() {
    const endpoint = isSuricataRunning ? '/api/suricata/stop' : '/api/suricata/start';
    try {
        await fetch(`${API_URL}${endpoint}`, { method: 'POST' });
        updateSuricataUI(!isSuricataRunning);
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

function updateSuricataUI(isRunning) {
    isSuricataRunning = isRunning;
    const btn = document.getElementById('btn-suricata');
    btn.textContent = isRunning ? 'Stop Suricata (F1)' : 'Start Suricata (F1)';
    btn.classList.toggle('active-suri', isRunning);
}

function updateYaraUI(isRunning) {
    isYaraRunning = isRunning;
    const btn = document.getElementById('btn-yara');
    btn.textContent = isRunning ? 'Stop Yara (F2)' : 'Start Yara (F2)';
    btn.classList.toggle('active-yara', isRunning);
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

const modal = document.getElementById('log-modal');
const select = document.getElementById('log-date-select');
const historyLogs = document.getElementById('historical-logs');

async function openLogViewer() {
    modal.style.display = 'block';
    select.innerHTML = '<option>Loading...</option>';
    historyLogs.textContent = '';

    try {
        const res = await fetch(`${API_URL}/api/logs`);
        const data = await res.json();

        if (data.logs.length === 0) {
            select.innerHTML = '<option>No logs</option>';
            historyLogs.textContent = 'No historical detections have been stored yet.';
            return;
        }

        select.innerHTML = '';
        data.logs.forEach((date) => {
            const opt = document.createElement('option');
            opt.value = date;
            opt.textContent = date;
            select.appendChild(opt);
        });

        fetchLogContent();
    } catch (e) {
        select.innerHTML = '<option>Server unavailable</option>';
        historyLogs.textContent = 'The backend server did not respond.';
    }
}

async function fetchLogContent() {
    const date = select.value;
    if (!date || date === 'No logs' || date === 'Server unavailable') {
        return;
    }

    try {
        const res = await fetch(`${API_URL}/api/logs/${date}`);
        const data = await res.json();
        historyLogs.textContent = data.content;
    } catch (e) {
        historyLogs.textContent = 'Failed to load the selected log.';
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
        toggleSuricata();
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

suriLogs.innerHTML = "<div style='color: #8b949e'>Waiting for events... Press F1 to start Suricata.</div>";
yaraLogs.innerHTML = "<div style='color: #8b949e'>Waiting for events... Press F2 to choose folders and start Yara.</div>";
connectWS();
