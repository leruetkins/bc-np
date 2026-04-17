let currentConfig = null;
let editingGroupIndex = -1;
let editingEndpointIndex = -1;

async function apiCall(url, method = 'GET', body = null) {
    const creds = localStorage.getItem('credentials') || '';
    const headers = { 
        'Authorization': 'Basic ' + creds,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache'
    };
    if (body) headers['Content-Type'] = 'application/json';

    const cacheBuster = url.includes('?') ? '&' : '?';
    const fullUrl = url + cacheBuster + '_=' + Date.now();

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const resp = await fetch(fullUrl, opts);
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

    let totalEnabled = 0;
    let totalEndpoints = 0;
    data.groups.forEach(g => {
        g.endpoints.forEach(ep => {
            totalEndpoints++;
            if (ep.enabled) totalEnabled++;
        });
    });

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
            <h3>Groups</h3>
            <p>${data.groups.length}</p>
        </div>
        <div class="card">
            <h3>Active Endpoints</h3>
            <p>${totalEnabled} / ${totalEndpoints}</p>
        </div>
    `;
}

async function loadEndpoints() {
    const data = await apiCall('/api/status');
    if (!data) return;

    currentConfig = { node: data.node, groups: data.groups };

    document.getElementById('endpoints-list').innerHTML = data.groups.map((group, gi) => `
        <div class="group-card" ondragover="allowDrop(event)" ondrop="dropToGroup(event, ${gi})">
            <div class="group-header">
                <h3 onclick="toggleGroup(${gi})" style="cursor: pointer;">${group.name} <span class="badge">${group.endpoints.length}</span> <span class="collapse-icon">▼</span></h3>
                <div class="group-actions">
                    <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); editGroup(${gi})">Rename</button>
                    <button class="btn btn-sm btn-success" onclick="event.stopPropagation(); showAddEndpointForm(${gi})">+ Endpoint</button>
                    <button class="btn btn-sm btn-outline btn-danger" onclick="event.stopPropagation(); deleteGroup(${gi})">Delete</button>
                </div>
            </div>
            <div class="endpoints-in-group" ondragover="allowDrop(event); event.stopPropagation();" ondrop="dropToGroup(event, ${gi})">
                ${group.endpoints.length === 0 ? '<p class="empty">No endpoints (drag here)</p>' : group.endpoints.map((ep, ei) => `
                    <div class="endpoint-card ${ep.enabled ? 'enabled' : 'disabled'}" draggable="true" ondragstart="dragEndpoint(event, ${gi}, ${ei})">
                        <div class="ep-header">
                            <h4>${ep.name}</h4>
                            <span class="status-badge ${ep.enabled ? 'active' : 'inactive'}">${ep.enabled ? 'Active' : 'Inactive'}</span>
                        </div>
                        <p class="path">${ep.path}</p>
                        <div class="ep-stats">
                            <div class="stat"><span class="label">Files:</span> ${ep.fileCount} / ${ep.count}</div>
                            <div class="stat"><span class="label">Period:</span> ${ep.period || 15}s</div>
                            <div class="stat"><span class="label">Space:</span> ${ep.freeSpaceGb} / ${ep.wholeSpaceGb} GB</div>
                        </div>
                        <p class="filter">Filter: ${ep.filter.join(', ') || 'none'}</p>
                        <div class="actions">
                            <button class="btn btn-sm ${ep.enabled ? 'btn-warning' : 'btn-success'}" onclick="toggleEndpoint(${gi}, ${ei})">${ep.enabled ? 'Disable' : 'Enable'}</button>
                            <button class="btn btn-sm btn-outline" onclick="editEndpoint(${gi}, ${ei})">Edit</button>
                            <button class="btn btn-sm btn-outline" onclick="moveToGroup(${gi}, ${ei})">Move</button>
                            <button class="btn btn-sm btn-outline btn-danger" onclick="deleteEndpoint(${gi}, ${ei})">Delete</button>
                        </div>
                    </div>
                `).join('')}
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

function showAddEndpointForm(groupIndex = 0) {
    editingGroupIndex = groupIndex;
    editingEndpointIndex = -1;
    document.getElementById('modal-title').textContent = 'Add Endpoint';
    document.getElementById('endpoint-form').reset();
    document.getElementById('modal').style.display = 'block';
}

function editEndpoint(gi, ei) {
    editingGroupIndex = gi;
    editingEndpointIndex = ei;
    const ep = currentConfig.groups[gi].endpoints[ei];
    document.getElementById('modal-title').textContent = 'Edit Endpoint';
    document.getElementById('ep-name').value = ep.name;
    document.getElementById('ep-path').value = ep.path;
    document.getElementById('ep-count').value = ep.count;
    document.getElementById('ep-period').value = ep.period || 15;
    document.getElementById('ep-filter').value = ep.filter.join(', ');
    document.getElementById('ep-enabled').checked = ep.enabled;
    document.getElementById('modal').style.display = 'block';
}

function toggleGroup(gi) {
    const cards = document.querySelectorAll('.group-card');
    cards[gi].classList.toggle('collapsed');
}

function editGroup(gi) {
    const newName = prompt('Enter new group name:', currentConfig.groups[gi].name);
    if (!newName) return;
    currentConfig.groups[gi].name = newName;
    apiCall('/api/config', 'POST', { groups: currentConfig.groups });
    loadEndpoints();
}

function deleteGroup(gi) {
    if (!confirm('Delete this group and all its endpoints?')) return;
    currentConfig.groups.splice(gi, 1);
    apiCall('/api/config', 'POST', { groups: currentConfig.groups });
    loadEndpoints();
}

async function addGroup() {
    const name = prompt('Enter new group name:');
    if (!name) return;
    currentConfig.groups.push({ name: name, endpoints: [] });
    await apiCall('/api/config', 'POST', { groups: currentConfig.groups });
    loadEndpoints();
}

function closeModal() {
    document.getElementById('modal').style.display = 'none';
}

async function toggleEndpoint(gi, ei) {
    const ep = currentConfig.groups[gi].endpoints[ei];
    ep.enabled = !ep.enabled;
    await apiCall('/api/config', 'POST', { groups: currentConfig.groups });
    loadEndpoints();
}

async function deleteEndpoint(gi, ei) {
    if (!confirm('Delete this endpoint?')) return;
    currentConfig.groups[gi].endpoints.splice(ei, 1);
    await apiCall('/api/config', 'POST', { groups: currentConfig.groups });
    loadEndpoints();
}

let draggedFromGroup = -1;
let draggedFromEndpoint = -1;

function dragEndpoint(event, gi, ei) {
    draggedFromGroup = gi;
    draggedFromEndpoint = ei;
    event.dataTransfer.setData('text/plain', JSON.stringify({gi, ei}));
    event.target.style.opacity = '0.5';
}

function allowDrop(event) {
    event.preventDefault();
}

async function dropToGroup(event, targetGi) {
    event.preventDefault();
    if (draggedFromGroup < 0 || draggedFromEndpoint < 0) return;
    if (draggedFromGroup === targetGi) {
        loadEndpoints();
        return;
    }
    
    const endpoint = currentConfig.groups[draggedFromGroup].endpoints[draggedFromEndpoint];
    currentConfig.groups[draggedFromGroup].endpoints.splice(draggedFromEndpoint, 1);
    currentConfig.groups[targetGi].endpoints.push(endpoint);
    
    await apiCall('/api/config', 'POST', { groups: currentConfig.groups });
    loadEndpoints();
    
    draggedFromGroup = -1;
    draggedFromEndpoint = -1;
}

async function moveToGroup(gi, ei) {
    const groups = currentConfig.groups.map((g, i) => `${i}: ${g.name}`).join('\n');
    const targetGi = prompt(`Enter group number to move to:\n${groups}`);
    if (targetGi === null) return;
    
    const targetIndex = parseInt(targetGi);
    if (isNaN(targetIndex) || targetIndex < 0 || targetIndex >= currentConfig.groups.length) {
        alert('Invalid group number');
        return;
    }
    if (targetIndex === gi) {
        alert('Already in this group');
        return;
    }
    
    const endpoint = currentConfig.groups[gi].endpoints[ei];
    currentConfig.groups[gi].endpoints.splice(ei, 1);
    currentConfig.groups[targetIndex].endpoints.push(endpoint);
    
    await apiCall('/api/config', 'POST', { groups: currentConfig.groups });
    loadEndpoints();
}

document.getElementById('endpoint-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const endpoint = {
        name: document.getElementById('ep-name').value,
        path: document.getElementById('ep-path').value,
        count: parseInt(document.getElementById('ep-count').value),
        period: parseInt(document.getElementById('ep-period').value) || 15,
        filter: document.getElementById('ep-filter').value.split(',').map(s => s.trim()).filter(s => s),
        enabled: document.getElementById('ep-enabled').checked
    };

    if (editingGroupIndex >= 0) {
        if (editingEndpointIndex >= 0) {
            currentConfig.groups[editingGroupIndex].endpoints[editingEndpointIndex] = endpoint;
        } else {
            currentConfig.groups[editingGroupIndex].endpoints.push(endpoint);
        }
    }

    await apiCall('/api/config', 'POST', { groups: currentConfig.groups });
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
    const path = window.location.pathname;
    if (path.includes('/endpoints')) {
        showSection('endpoints');
    } else if (path.includes('/settings')) {
        showSection('settings');
    } else {
        showSection('dashboard');
    }
}