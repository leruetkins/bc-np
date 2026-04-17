<template>
  <div v-if="!isAuthenticated">
    <div class="login-container">
      <h1>bc-np</h1>
      <form @submit.prevent="handleLogin">
        <div class="form-group">
          <label>Login</label>
          <input v-model="loginForm.login" type="text" placeholder="Login" required>
        </div>
        <div class="form-group">
          <label>Password</label>
          <input v-model="loginForm.password" type="password" placeholder="Password" required>
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
        <p v-if="loginError" class="error">{{ loginError }}</p>
      </form>
    </div>
  </div>

  <div v-else>
    <nav class="navbar">
      <div class="nav-brand">bc-np</div>
      <div class="nav-links">
        <a href="#" @click.prevent="currentSection = 'dashboard'">Dashboard</a>
        <a href="#" @click.prevent="currentSection = 'endpoints'">Endpoints</a>
        <a href="#" @click.prevent="currentSection = 'settings'">Settings</a>
        <a href="#" @click.prevent="logout">Logout</a>
      </div>
    </nav>

    <div class="container">
      <div v-if="currentSection === 'dashboard'" id="dashboard-section">
        <h2>Dashboard</h2>
        <div class="cards">
          <div class="card">
            <h3>{{ status.node?.name }}</h3>
            <p>{{ status.node?.place }}</p>
            <p>{{ status.node?.description }}</p>
          </div>
          <div class="card">
            <h3>Version</h3>
            <p>{{ status.version }}</p>
          </div>
          <div class="card">
            <h3>Groups</h3>
            <p>{{ status.groups?.length || 0 }}</p>
          </div>
          <div class="card">
            <h3>Active Endpoints</h3>
            <p>{{ activeCount }} / {{ totalCount }}</p>
          </div>
        </div>
      </div>

      <div v-if="currentSection === 'endpoints'" id="endpoints-section">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
          <h2>Endpoints</h2>
          <button class="btn btn-success" @click="addGroup">+ New Group</button>
        </div>
        <div class="endpoints-grid">
          <div
            v-for="(group, gi) in config.groups"
            :key="gi"
            class="group-card"
            :class="{ collapsed: group.collapsed }"
            @dragover.prevent="handleDragOver($event, gi)"
            @drop="handleDrop($event, gi)"
          >
            <div class="group-header" @click="toggleGroup(gi)">
              <h3>
                {{ group.name }}
                <span class="badge">{{ group.endpoints.length }}</span>
                <span class="collapse-icon">▼</span>
              </h3>
              <div class="group-actions">
                <button class="btn btn-sm btn-outline" @click.stop="editGroup(gi)">Rename</button>
                <button class="btn btn-sm btn-success" @click.stop="showAddEndpointForm(gi)">+ Endpoint</button>
                <button class="btn btn-sm btn-outline btn-danger" @click.stop="deleteGroup(gi)">Delete</button>
              </div>
            </div>
            <div
              class="endpoints-in-group"
              :class="{ 'drag-over': dragOverIndex === gi }"
              @dragover.prevent="handleDragOver($event, gi)"
              @drop="handleDrop($event, gi)"
            >
              <div v-if="group.endpoints.length === 0" class="empty">No endpoints (drag here)</div>
              <div
                v-for="(ep, ei) in group.endpoints"
                :key="ei"
                class="endpoint-card"
                :class="{ enabled: ep.enabled, disabled: !ep.enabled }"
                draggable="true"
                @dragstart="dragEndpoint($event, gi, ei)"
              >
                <div class="ep-header">
                  <h4>{{ ep.name }}</h4>
                  <span class="status-badge" :class="ep.enabled ? 'active' : 'inactive'">
                    {{ ep.enabled ? 'Active' : 'Inactive' }}
                  </span>
                </div>
                <p class="path">{{ ep.path }}</p>
                <div class="ep-stats">
                  <span><span class="label">Files:</span> {{ ep.fileCount || 0 }} / {{ ep.count }}</span>
                  <span><span class="label">Period:</span> {{ ep.period || 15 }}s</span>
                  <span><span class="label">Space:</span> {{ ep.freeSpaceGb || 0 }} / {{ ep.wholeSpaceGb || 0 }} GB</span>
                </div>
                <p class="filter">Filter: {{ ep.filter?.join(', ') || 'none' }}</p>
                <div class="actions">
                  <button class="btn btn-sm" :class="ep.enabled ? 'btn-warning' : 'btn-success'" @click="toggleEndpoint(gi, ei)">
                    {{ ep.enabled ? 'Disable' : 'Enable' }}
                  </button>
                  <button class="btn btn-sm btn-outline" @click="editEndpointForm(gi, ei)">Edit</button>
                  <button class="btn btn-sm btn-outline" @click="moveToGroup(gi, ei)">Move</button>
                  <button class="btn btn-sm btn-outline btn-danger" @click="deleteEndpoint(gi, ei)">Delete</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-if="currentSection === 'settings'" id="settings-section">
        <h2>Settings</h2>
        <div class="card" style="max-width: 500px;">
          <form @submit.prevent="saveSettings">
            <div class="form-group">
              <label>Node Name</label>
              <input v-model="settingsForm.name" type="text">
            </div>
            <div class="form-group">
              <label>Place</label>
              <input v-model="settingsForm.place" type="text">
            </div>
            <div class="form-group">
              <label>Description</label>
              <input v-model="settingsForm.description" type="text">
            </div>
            <button type="submit" class="btn btn-primary">Save</button>
          </form>
        </div>

        <h3 style="margin-top: 2rem;">Change Password</h3>
        <div class="card" style="max-width: 500px;">
          <form @submit.prevent="changePassword">
            <div class="form-group">
              <label>New Login</label>
              <input v-model="passwordForm.login" type="text">
            </div>
            <div class="form-group">
              <label>New Password</label>
              <input v-model="passwordForm.password" type="password">
            </div>
            <button type="submit" class="btn btn-primary">Update</button>
          </form>
        </div>
      </div>
    </div>

    <div class="modal" :class="{ show: showModal }">
      <div class="modal-content">
        <button class="close" @click="closeModal">&times;</button>
        <h3>{{ modalTitle }}</h3>
        <form @submit.prevent="saveEndpoint">
          <div class="form-group">
            <label>Name</label>
            <input v-model="endpointForm.name" required>
          </div>
          <div class="form-group">
            <label>Path</label>
            <input v-model="endpointForm.path" required>
          </div>
          <div class="form-group">
            <label>Count</label>
            <input v-model.number="endpointForm.count" type="number" required>
          </div>
          <div class="form-group">
            <label>Period (seconds)</label>
            <input v-model.number="endpointForm.period" type="number">
          </div>
          <div class="form-group">
            <label>Filter (comma separated)</label>
            <input v-model="endpointForm.filter" placeholder="*.zip, backup_*.*">
          </div>
          <div class="checkbox-group">
            <input v-model="endpointForm.enabled" type="checkbox" id="enabled">
            <label for="enabled">Enabled</label>
          </div>
          <button type="submit" class="btn btn-primary" style="margin-top: 1rem;">Save</button>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'

const isAuthenticated = ref(false)
const currentSection = ref('dashboard')
const status = ref({})
const config = ref({ groups: [] })
const showModal = ref(false)
const modalTitle = ref('')
const loginError = ref('')

const loginForm = reactive({ login: '', password: '' })
const settingsForm = reactive({ name: '', place: '', description: '' })
const passwordForm = reactive({ login: '', password: '' })
const endpointForm = reactive({
  name: '', path: '', count: 10, period: 15, filter: '', enabled: true
})

const editingGroupIndex = ref(-1)
const editingEndpointIndex = ref(-1)
const dragOverIndex = ref(-1)
let draggedFromGroup = -1
let draggedFromEndpoint = -1

const activeCount = computed(() => {
  let count = 0
  config.value.groups?.forEach(g => {
    g.endpoints?.forEach(ep => {
      if (ep.enabled) count++
    })
  })
  return count
})

const totalCount = computed(() => {
  let count = 0
  config.value.groups?.forEach(g => {
    count += g.endpoints?.length || 0
  })
  return count
})

async function apiCall(url, method = 'GET', body = null) {
  const creds = localStorage.getItem('credentials') || ''
  const headers = {
    'Authorization': 'Basic ' + creds,
    'Content-Type': 'application/json'
  }
  const opts = { method, headers }
  if (body) opts.body = JSON.stringify(body)

  const resp = await fetch(url + (url.includes('?') ? '&' : '?') + '_=' + Date.now(), opts)
  if (resp.status === 401) {
    logout()
    return null
  }
  return resp.json()
}

function handleLogin() {
  const creds = btoa(loginForm.login + ':' + loginForm.password)
  localStorage.setItem('credentials', creds)
  isAuthenticated.value = true
  loadStatus()
  loadConfig()
}

function logout() {
  localStorage.removeItem('credentials')
  isAuthenticated.value = false
  currentSection.value = 'dashboard'
}

async function loadStatus() {
  const data = await apiCall('/api/status')
  if (data) status.value = data
}

async function loadConfig() {
  const data = await apiCall('/config')
  if (data) {
    config.value = data
    if (data.node) {
      settingsForm.name = data.node.name || ''
      settingsForm.place = data.node.place || ''
      settingsForm.description = data.node.description || ''
    }
  }
}

function toggleGroup(gi) {
  config.value.groups[gi].collapsed = !config.value.groups[gi].collapsed
}

function addGroup() {
  const name = prompt('Enter new group name:')
  if (!name) return
  config.value.groups.push({ name, endpoints: [], collapsed: false })
  saveConfig()
}

function editGroup(gi) {
  const newName = prompt('Enter new group name:', config.value.groups[gi].name)
  if (!newName) return
  config.value.groups[gi].name = newName
  saveConfig()
}

function deleteGroup(gi) {
  if (!confirm('Delete this group and all its endpoints?')) return
  config.value.groups.splice(gi, 1)
  saveConfig()
}

function showAddEndpointForm(gi) {
  editingGroupIndex.value = gi
  editingEndpointIndex.value = -1
  modalTitle.value = 'Add Endpoint'
  Object.assign(endpointForm, { name: '', path: '', count: 10, period: 15, filter: '', enabled: true })
  showModal.value = true
}

function editEndpointForm(gi, ei) {
  editingGroupIndex.value = gi
  editingEndpointIndex.value = ei
  const ep = config.value.groups[gi].endpoints[ei]
  modalTitle.value = 'Edit Endpoint'
  Object.assign(endpointForm, {
    name: ep.name,
    path: ep.path,
    count: ep.count,
    period: ep.period || 15,
    filter: ep.filter?.join(', ') || '',
    enabled: ep.enabled
  })
  showModal.value = true
}

function closeModal() {
  showModal.value = false
}

function saveEndpoint() {
  const endpoint = {
    name: endpointForm.name,
    path: endpointForm.path,
    count: endpointForm.count,
    period: endpointForm.period,
    filter: endpointForm.filter.split(',').map(s => s.trim()).filter(s => s),
    enabled: endpointForm.enabled
  }

  if (editingEndpointIndex.value >= 0) {
    config.value.groups[editingGroupIndex.value].endpoints[editingEndpointIndex.value] = endpoint
  } else {
    config.value.groups[editingGroupIndex.value].endpoints.push(endpoint)
  }

  closeModal()
  saveConfig()
}

async function toggleEndpoint(gi, ei) {
  const ep = config.value.groups[gi].endpoints[ei]
  ep.enabled = !ep.enabled
  await saveConfig()
}

async function deleteEndpoint(gi, ei) {
  if (!confirm('Delete this endpoint?')) return
  config.value.groups[gi].endpoints.splice(ei, 1)
  await saveConfig()
}

function dragEndpoint(event, gi, ei) {
  draggedFromGroup = gi
  draggedFromEndpoint = ei
  event.dataTransfer.setData('text/plain', JSON.stringify({ gi, ei }))
  event.target.style.opacity = '0.5'
}

function handleDragOver(event, gi) {
  dragOverIndex.value = gi
}

function handleDrop(event, targetGi) {
  event.preventDefault()
  dragOverIndex.value = -1

  if (draggedFromGroup < 0 || draggedFromEndpoint < 0) return
  if (draggedFromGroup === targetGi) {
    loadConfig()
    return
  }

  const endpoint = config.value.groups[draggedFromGroup].endpoints[draggedFromEndpoint]
  config.value.groups[draggedFromGroup].endpoints.splice(draggedFromEndpoint, 1)
  config.value.groups[targetGi].endpoints.push(endpoint)

  draggedFromGroup = -1
  draggedFromEndpoint = -1
  saveConfig()
}

async function moveToGroup(gi, ei) {
  const groups = config.value.groups.map((g, i) => `${i}: ${g.name}`).join('\n')
  const targetGi = prompt(`Enter group number to move to:\n${groups}`)
  if (targetGi === null) return

  const targetIndex = parseInt(targetGi)
  if (isNaN(targetIndex) || targetIndex < 0 || targetIndex >= config.value.groups.length) {
    alert('Invalid group number')
    return
  }
  if (targetIndex === gi) {
    alert('Already in this group')
    return
  }

  const endpoint = config.value.groups[gi].endpoints[ei]
  config.value.groups[gi].endpoints.splice(ei, 1)
  config.value.groups[targetIndex].endpoints.push(endpoint)
  await saveConfig()
}

async function saveSettings() {
  await apiCall('/api/config', 'POST', {
    node: {
      name: settingsForm.name,
      place: settingsForm.place,
      description: settingsForm.description
    }
  })
  alert('Settings saved!')
}

async function changePassword() {
  const cfg = await apiCall('/config')
  if (!cfg) return
  cfg.settings[0].login = passwordForm.login
  cfg.settings[0].password = passwordForm.password
  await apiCall('/api/config', 'POST', { settings: cfg.settings })
  if (confirm('Credentials updated! Re-login required. Logout now?')) {
    logout()
  }
}

async function saveConfig() {
  await apiCall('/api/config', 'POST', { groups: config.value.groups })
}

onMounted(() => {
  if (localStorage.getItem('credentials')) {
    isAuthenticated.value = true
    loadStatus()
    loadConfig()
  }
})
</script>