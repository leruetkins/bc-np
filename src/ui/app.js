let currentConfig = null;
let editingIndex = -1;

async function apiCall(url, method = 'GET', body = null) {
    const creds = localStorage.getItem('credentials') || '';
    const headers = { 'Authorization': 'Basic ' + creds };
    if (body) headers['Content-Type'] = 'application/json';

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const resp = await fetch(url, opts);
    if (resp.status === 401) {
        localStorage.removeItem('credentials');
        window.location.href = '/ui/login.html';
        return null;
    }
    return resp.json();
}

async function loadStatus() {
    const data = await apiCall('/api/status');
    if (!data) return;

    document.getElementById('status-cards').innerHTML = `
        <div class="card">
            <h3>${data.node.name}</h3>
            <p>${data.node.place}</p>
            <p>${data.node.description}</p>
        </div>
        <div class="card">
            <h3>Version</h3>
            <p>${data.version}</p>
        </div>
        <div class="card">
            <h3>Active Endpoints</h3>
            <p>${data.endpoints.filter(e => e.enabled).length}</p>
        </div>
    `;
}

async function loadEndpoints() {
    const data = await apiCall('/api/status');
    if (!data) return;

    currentConfig = { node: data.node, endpoints: data.endpoints };

    document.getElementById('endpoints-list').innerHTML = data.endpoints.map((ep, i) => `
        <div class="endpoint-card ${ep.enabled ? 'enabled' : 'disabled'}">
            <div class="ep-header">
                <h3>${ep.name}</h3>
                <span class="status-badge ${ep.enabled ? 'active' : 'inactive'}">${ep.enabled ? 'Active' : 'Inactive'}</span>
            </div>
            <p class="path">${ep.path}</p>
            <div class="ep-stats">
                <div class="stat"><span class="label">Files:</span> ${ep.fileCount} / ${ep.count}</div>
                <div class="stat"><span class="label">Space:</span> ${ep.freeSpaceGb} / ${ep.wholeSpaceGb} GB</div>
            </div>
            <p class="filter">Filter: ${ep.filter.join(', ') || 'none'}</p>
            <div class="actions">
                <button class="btn btn-sm ${ep.enabled ? 'btn-warning' : 'btn-success'}" onclick="toggleEndpoint(${i})">${ep.enabled ? 'Disable' : 'Enable'}</button>
                <button class="btn btn-sm btn-outline" onclick="editEndpoint(${i})">Edit</button>
                <button class="btn btn-sm btn-outline btn-danger" onclick="deleteEndpoint(${i})">Delete</button>
            </div>
        </div>
    `).join('');
}

function refreshEndpoints() {
    loadEndpoints();
}

async function loadSettings() {
    const data = await apiCall('/api/status');
    if (!data) return;

    const cfg = await apiCall('/config');
    if (!cfg) return;

    document.getElementById('node-name').value = cfg.node.name;
    document.getElementById('node-place').value = cfg.node.place;
    document.getElementById('node-desc').value = cfg.node.description;
    document.getElementById('settings-period').value = cfg.settings[0].period;
    document.getElementById('settings-port').value = cfg.settings[0].port;
}

function showSection(name) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById(name + '-section').classList.add('active');

    if (name === 'dashboard') loadStatus();
    if (name === 'endpoints') loadEndpoints();
    if (name === 'settings') loadSettings();
}

function showAddEndpointForm() {
    editingIndex = -1;
    document.getElementById('modal-title').textContent = 'Add Endpoint';
    document.getElementById('endpoint-form').reset();
    document.getElementById('modal').style.display = 'block';
}

function editEndpoint(index) {
    editingIndex = index;
    const ep = currentConfig.endpoints[index];
    document.getElementById('modal-title').textContent = 'Edit Endpoint';
    document.getElementById('ep-name').value = ep.name;
    document.getElementById('ep-path').value = ep.path;
    document.getElementById('ep-count').value = ep.count;
    document.getElementById('ep-filter').value = ep.filter.join(', ');
    document.getElementById('ep-enabled').checked = ep.enabled;
    document.getElementById('modal').style.display = 'block';
}

function closeModal() {
    document.getElementById('modal').style.display = 'none';
}

async function toggleEndpoint(index) {
    const ep = currentConfig.endpoints[index];
    ep.enabled = !ep.enabled;
    await apiCall('/api/config', 'POST', { endpoints: currentConfig.endpoints });
    loadEndpoints();
}

async function deleteEndpoint(index) {
    if (!confirm('Delete this endpoint?')) return;
    currentConfig.endpoints.splice(index, 1);
    await apiCall('/api/config', 'POST', { endpoints: currentConfig.endpoints });
    loadEndpoints();
}

document.getElementById('endpoint-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const endpoint = {
        name: document.getElementById('ep-name').value,
        path: document.getElementById('ep-path').value,
        count: parseInt(document.getElementById('ep-count').value),
        filter: document.getElementById('ep-filter').value.split(',').map(s => s.trim()).filter(s => s),
        enabled: document.getElementById('ep-enabled').checked
    };

    if (editingIndex >= 0) {
        currentConfig.endpoints[editingIndex] = endpoint;
    } else {
        currentConfig.endpoints.push(endpoint);
    }

    await apiCall('/api/config', 'POST', { endpoints: currentConfig.endpoints });
    closeModal();
    loadEndpoints();
});

document.getElementById('settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await apiCall('/api/config', 'POST', {
        node: {
            name: document.getElementById('node-name').value,
            place: document.getElementById('node-place').value,
            description: document.getElementById('node-desc').value
        }
    });
    alert('Settings saved!');
});

document.getElementById('password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const cfg = await apiCall('/config');
    if (!cfg) return;
    cfg.settings[0].login = document.getElementById('new-login').value;
    cfg.settings[0].password = document.getElementById('new-password').value;
    await apiCall('/api/config', 'POST', { settings: cfg.settings });
    if (confirm('Credentials updated! Re-login required. Logout now?')) {
        logout();
    }
});

function logout() {
    localStorage.removeItem('credentials');
    window.location.href = '/ui/login.html';
}

if (!localStorage.getItem('credentials')) {
    window.location.href = '/ui/login.html';
} else {
    showSection('dashboard');
}