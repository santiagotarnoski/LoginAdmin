const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? 'http://localhost:3000'
  : 'https://loginadmin-ge3g.onrender.com'; // ← Cambia esta URL
const $ = (sel) => document.querySelector(sel);

const tabLogin = $('#tab-login');
const tabRegister = $('#tab-register');
const loginForm = $('#login-form');
const registerForm = $('#register-form');
const loginMsg = $('#login-msg');
const regMsg = $('#reg-msg');
const dashboard = $('#dashboard');
const authForms = $('#auth-forms');
const authContainer = $('#auth-container');
const usernameSpan = $('#username-span');
const roleSpan = $('#role-span');
const btnProfile = $('#btn-profile');
const btnLogout = $('#btn-logout');
const profilePre = $('#profile-json');

// Admin elements
const adminSection = $('#admin-section');
const tabRbac = $('#tab-rbac');
const tabAudit = $('#tab-audit');
const tabPasswordReset = $('#tab-password-reset');
const rbacPanel = $('#rbac-panel');
const auditPanel = $('#audit-panel');
const passwordResetPanel = $('#password-reset-panel');

// Dashboard elements
const tabOverview = $('#tab-overview');
const tabProfile = $('#tab-profile');
const tabSessions = $('#tab-sessions');
const tabNotifications = $('#tab-notifications');
const overviewPanel = $('#overview-panel');
const profilePanel = $('#profile-panel');
const sessionsPanel = $('#sessions-panel');
const notificationsPanel = $('#notifications-panel');

function setActiveTab(tab) {
  if (tab === 'login') {
    tabLogin.classList.add('active');
    tabRegister.classList.remove('active');
    loginForm.classList.add('visible');
    registerForm.classList.remove('visible');
  } else {
    tabRegister.classList.add('active');
    tabLogin.classList.remove('active');
    registerForm.classList.add('visible');
    loginForm.classList.remove('visible');
  }
}

tabLogin.addEventListener('click', () => setActiveTab('login'));
tabRegister.addEventListener('click', () => setActiveTab('register'));

function saveToken(token, username, role){
  localStorage.setItem('auth_token', token);
  localStorage.setItem('auth_username', username);
  localStorage.setItem('auth_role', role || '');
}

function getToken(){
  return localStorage.getItem('auth_token');
}

function getUsername(){
  return localStorage.getItem('auth_username');
}
function getRole(){
  return localStorage.getItem('auth_role');
}

function clearSession(){
  localStorage.removeItem('auth_token');
  localStorage.removeItem('auth_username');
  localStorage.removeItem('auth_role');
}

function showDashboard(){
  usernameSpan.textContent = getUsername() || '';
  roleSpan.textContent = getRole() || '';
  authForms.classList.add('hidden');
  if (authContainer) authContainer.classList.add('hidden');
  dashboard.classList.remove('hidden');
  
  // Cargar datos del dashboard
  loadDashboardData();
  
  // Mostrar secciÃ³n de admin si el usuario tiene permiso de administraciÃ³n
  checkAdminAccess();
}

function showAuth(){
  dashboard.classList.add('hidden');
  authForms.classList.remove('hidden');
  if (authContainer) authContainer.classList.remove('hidden');
}

async function api(path, opts={}){
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...(opts.headers||{}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(API_URL + path, { ...opts, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error||'Error'), { status: res.status, data });
  return data;
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginMsg.textContent = 'Ingresando...';
  const username = $('#login-username').value.trim();
  const password = $('#login-password').value;
  try {
    const data = await api('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    saveToken(data.token, data.username, data.role);
    loginMsg.textContent = '';
    showDashboard();
  } catch (err) {
    loginMsg.textContent = err.data?.error || 'Credenciales invÃ¡lidas';
  }
});

registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  regMsg.textContent = 'Creando cuenta...';
  const username = $('#reg-username').value.trim();
  const password = $('#reg-password').value;
  const role = $('#reg-role').value;
  try {
    await api('/api/register', { method: 'POST', body: JSON.stringify({ username, password, role }) });
    regMsg.textContent = 'Cuenta creada. Ahora inicia sesiÃ³n.';
    setActiveTab('login');
  } catch (err) {
    regMsg.textContent = err.data?.error || 'Error al registrar';
  }
});

btnProfile.addEventListener('click', async () => {
  profilePre.textContent = 'Cargando...';
  try {
    const data = await api('/api/profile');
    profilePre.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    profilePre.textContent = err.data?.error || 'Error al cargar perfil';
  }
});

btnLogout.addEventListener('click', () => {
  clearSession();
  showAuth();
});

// Probar autorizaciones
document.querySelectorAll('[data-action]').forEach(btn => {
  btn.addEventListener('click', async () => {
    const action = btn.getAttribute('data-action');
    const msg = $('#auth-msg');
    msg.textContent = 'Verificando...';
    try {
      const data = await api('/api/authorize', { method: 'POST', body: JSON.stringify({ action }) });
      msg.textContent = data.allowed ? `Permitido para ${data.role}: ${action}` : `Denegado para ${data.role}: ${action}`;
    } catch (e) {
      msg.textContent = e.data?.error || 'Error al autorizar';
    }
  });
});

// Admin functions
async function checkAdminAccess() {
  try {
    const data = await api('/api/authorize', { method: 'POST', body: JSON.stringify({ action: 'administracion' }) });
    if (data.allowed) {
      adminSection.classList.remove('hidden');
      loadAdminData();
    } else {
      adminSection.classList.add('hidden');
    }
  } catch (e) {
    adminSection.classList.add('hidden');
  }
}

function setActiveAdminTab(tab) {
  // Remove active class from all tabs
  document.querySelectorAll('.admin-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.admin-panel').forEach(p => p.classList.add('hidden'));
  
  // Add active class to selected tab and show corresponding panel
  if (tab === 'rbac') {
    tabRbac.classList.add('active');
    rbacPanel.classList.remove('hidden');
  } else if (tab === 'audit') {
    tabAudit.classList.add('active');
    auditPanel.classList.remove('hidden');
    loadAuditLogs();
  } else if (tab === 'password-reset') {
    tabPasswordReset.classList.add('active');
    passwordResetPanel.classList.remove('hidden');
  }
}

async function loadAdminData() {
  await loadRoles();
  await loadPermissions();
}

async function loadRoles() {
  try {
    const data = await api('/api/rbac/roles');
    const rolesList = $('#roles-list');
    rolesList.innerHTML = '';
    
    data.roles.forEach(role => {
      const div = document.createElement('div');
      div.className = 'role-item';
      div.innerHTML = `
        <span>${role.name}</span>
        <button onclick="deleteRole('${role.name}')" class="secondary" style="padding:4px 8px;font-size:12px">Eliminar</button>
      `;
      rolesList.appendChild(div);
    });
    
    // Update role select
    const roleSelect = $('#assign-role');
    roleSelect.innerHTML = '<option value="">Seleccionar rol</option>';
    data.roles.forEach(role => {
      const option = document.createElement('option');
      option.value = role.name;
      option.textContent = role.name;
      roleSelect.appendChild(option);
    });
  } catch (e) {
    console.error('Error loading roles:', e);
  }
}

async function loadPermissions() {
  try {
    const data = await api('/api/rbac/permissions');
    const permissionsList = $('#permissions-list');
    permissionsList.innerHTML = '';
    
    data.permissions.forEach(permission => {
      const div = document.createElement('div');
      div.className = 'permission-item';
      div.innerHTML = `
        <span>${permission.name}</span>
        <button onclick="deletePermission('${permission.name}')" class="secondary" style="padding:4px 8px;font-size:12px">Eliminar</button>
      `;
      permissionsList.appendChild(div);
    });
    
    // Update permission select
    const permissionSelect = $('#assign-permission');
    permissionSelect.innerHTML = '<option value="">Seleccionar permiso</option>';
    data.permissions.forEach(permission => {
      const option = document.createElement('option');
      option.value = permission.name;
      option.textContent = permission.name;
      permissionSelect.appendChild(option);
    });
  } catch (e) {
    console.error('Error loading permissions:', e);
  }
}

async function loadAuditLogs() {
  try {
    const data = await api('/api/audit');
    const auditList = $('#audit-list');
    auditList.innerHTML = '';
    
    data.items.forEach(item => {
      const div = document.createElement('div');
      div.className = 'audit-item';
      div.innerHTML = `
        <div><span class="action">${item.action}</span> - <span class="user">${item.username || 'Sistema'}</span></div>
        <div class="time">${new Date(item.created_at).toLocaleString()}</div>
        ${item.resource ? `<div>Recurso: ${item.resource}</div>` : ''}
      `;
      auditList.appendChild(div);
    });
  } catch (e) {
    console.error('Error loading audit logs:', e);
  }
}

// Event listeners for admin functions
tabRbac.addEventListener('click', () => setActiveAdminTab('rbac'));
tabAudit.addEventListener('click', () => setActiveAdminTab('audit'));
tabPasswordReset.addEventListener('click', () => setActiveAdminTab('password-reset'));

$('#btn-create-role').addEventListener('click', async () => {
  const name = $('#new-role').value.trim();
  if (!name) return;
  
  try {
    await api('/api/rbac/roles', { method: 'POST', body: JSON.stringify({ name }) });
    $('#new-role').value = '';
    await loadRoles();
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
});

$('#btn-create-permission').addEventListener('click', async () => {
  const name = $('#new-permission').value.trim();
  if (!name) return;
  
  try {
    await api('/api/rbac/permissions', { method: 'POST', body: JSON.stringify({ name }) });
    $('#new-permission').value = '';
    await loadPermissions();
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
});

$('#btn-assign-permission').addEventListener('click', async () => {
  const role = $('#assign-role').value;
  const permission = $('#assign-permission').value;
  if (!role || !permission) return;
  
  try {
    await api('/api/rbac/roles/assign-permission', { 
      method: 'POST', 
      body: JSON.stringify({ role, permission }) 
    });
    alert('Permiso asignado correctamente');
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
});

$('#btn-refresh-audit').addEventListener('click', loadAuditLogs);

$('#btn-request-reset').addEventListener('click', async () => {
  const username = $('#reset-username').value.trim();
  if (!username) return;
  
  try {
    const data = await api('/api/password-reset/request', { 
      method: 'POST', 
      body: JSON.stringify({ username }) 
    });
    $('#reset-token').textContent = data.token;
    $('#reset-expires').textContent = new Date(data.expiresAt).toLocaleString();
    $('#reset-token-display').classList.remove('hidden');
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
});

$('#btn-confirm-reset').addEventListener('click', async () => {
  const token = $('#reset-token-input').value.trim();
  const newPassword = $('#new-password').value;
  if (!token || !newPassword) return;
  
  try {
    await api('/api/password-reset/confirm', { 
      method: 'POST', 
      body: JSON.stringify({ token, newPassword }) 
    });
    alert('ContraseÃ±a actualizada correctamente');
    $('#reset-token-input').value = '';
    $('#new-password').value = '';
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
});

// Dashboard functions
async function loadDashboardData() {
  await loadUserStats();
  await loadUserProfile();
}

async function loadUserStats() {
  try {
    const data = await api('/api/user/stats');
    const stats = data.stats;
    
    $('#last-login').textContent = stats.last_login ? 
      new Date(stats.last_login).toLocaleString() : 'Nunca';
    $('#active-sessions').textContent = stats.active_sessions || 0;
    $('#unread-notifications').textContent = stats.unread_notifications || 0;
    $('#total-sessions').textContent = stats.total_sessions || 0;
  } catch (e) {
    console.error('Error loading user stats:', e);
  }
}

async function loadUserProfile() {
  try {
    const data = await api('/api/user/profile');
    const profile = data.profile;
    
    $('#profile-fullname').value = profile.full_name || '';
    $('#profile-email').value = profile.email || '';
    $('#profile-phone').value = profile.phone || '';
    $('#profile-department').value = profile.department || '';
  } catch (e) {
    console.error('Error loading user profile:', e);
  }
}

async function loadUserSessions() {
  try {
    const data = await api('/api/user/sessions');
    const sessionsList = $('#sessions-list');
    sessionsList.innerHTML = '';
    
    data.sessions.forEach(session => {
      const div = document.createElement('div');
      div.className = 'session-item';
      div.innerHTML = `
        <div>
          <span class="ip">IP: ${session.ip_address}</span>
          ${session.is_active ? '<span class="active">ACTIVA</span>' : ''}
        </div>
        <div class="time">
          Login: ${new Date(session.login_at).toLocaleString()}
          ${session.logout_at ? `<br>Logout: ${new Date(session.logout_at).toLocaleString()}` : ''}
        </div>
      `;
      sessionsList.appendChild(div);
    });
  } catch (e) {
    console.error('Error loading sessions:', e);
  }
}

async function loadUserNotifications() {
  try {
    const data = await api('/api/user/notifications');
    const notificationsList = $('#notifications-list');
    notificationsList.innerHTML = '';
    
    data.notifications.forEach(notification => {
      const div = document.createElement('div');
      div.className = `notification-item ${notification.is_read ? '' : 'unread'}`;
      div.innerHTML = `
        <div class="title">${notification.title}</div>
        <div class="message">${notification.message}</div>
        <div class="time">${new Date(notification.created_at).toLocaleString()}</div>
        ${!notification.is_read ? `<button onclick="markNotificationRead(${notification.id})" style="margin-top:4px;padding:2px 6px;font-size:10px">Marcar leÃ­da</button>` : ''}
      `;
      notificationsList.appendChild(div);
    });
  } catch (e) {
    console.error('Error loading notifications:', e);
  }
}

function setActiveDashboardTab(tab) {
  // Remove active class from all tabs
  document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.dashboard-panel').forEach(p => p.classList.add('hidden'));
  
  // Add active class to selected tab and show corresponding panel
  if (tab === 'overview') {
    tabOverview.classList.add('active');
    overviewPanel.classList.remove('hidden');
    loadUserStats();
  } else if (tab === 'profile') {
    tabProfile.classList.add('active');
    profilePanel.classList.remove('hidden');
    loadUserProfile();
  } else if (tab === 'sessions') {
    tabSessions.classList.add('active');
    sessionsPanel.classList.remove('hidden');
    loadUserSessions();
  } else if (tab === 'notifications') {
    tabNotifications.classList.add('active');
    notificationsPanel.classList.remove('hidden');
    loadUserNotifications();
  }
}

// Event listeners for dashboard
tabOverview.addEventListener('click', () => setActiveDashboardTab('overview'));
tabProfile.addEventListener('click', () => setActiveDashboardTab('profile'));
tabSessions.addEventListener('click', () => setActiveDashboardTab('sessions'));
tabNotifications.addEventListener('click', () => setActiveDashboardTab('notifications'));

$('#profile-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const profileData = {
      full_name: $('#profile-fullname').value,
      email: $('#profile-email').value,
      phone: $('#profile-phone').value,
      department: $('#profile-department').value
    };
    
    await api('/api/user/profile', { 
      method: 'PUT', 
      body: JSON.stringify(profileData) 
    });
    alert('Perfil actualizado correctamente');
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
});

$('#password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const currentPassword = $('#current-password').value;
    const newPassword = $('#new-password-profile').value;
    
    await api('/api/user/change-password', { 
      method: 'POST', 
      body: JSON.stringify({ currentPassword, newPassword }) 
    });
    alert('ContraseÃ±a actualizada correctamente');
    $('#current-password').value = '';
    $('#new-password-profile').value = '';
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
});

$('#btn-refresh-sessions').addEventListener('click', loadUserSessions);
$('#btn-refresh-notifications').addEventListener('click', loadUserNotifications);

// Global functions for inline event handlers
window.deleteRole = async (roleName) => {
  if (!confirm(`Â¿Eliminar rol "${roleName}"?`)) return;
  try {
    await api('/api/rbac/roles', { method: 'DELETE', body: JSON.stringify({ name: roleName }) });
    await loadRoles();
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
};

window.deletePermission = async (permissionName) => {
  if (!confirm(`Â¿Eliminar permiso "${permissionName}"?`)) return;
  try {
    await api('/api/rbac/permissions', { method: 'DELETE', body: JSON.stringify({ name: permissionName }) });
    await loadPermissions();
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
};

window.markNotificationRead = async (notificationId) => {
  try {
    await api(`/api/user/notifications/${notificationId}/read`, { method: 'POST' });
    loadUserNotifications(); // Refresh the list
  } catch (e) {
    alert('Error: ' + (e.data?.error || e.message));
  }
};

// Init
if (getToken()) {
  showDashboard();
} else {
  showAuth();
}




