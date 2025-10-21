import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import { Role, AllowedRoles } from './domain/Role.js';
import { LoginSystem } from './domain/LoginSystem.js';
import { RBACService } from './domain/RBACService.js';
import { AuditService } from './domain/AuditService.js';
import { PasswordResetService } from './domain/PasswordResetService.js';
import { UserService } from './domain/UserService.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// DB setup
sqlite3.verbose();
const db = new sqlite3.Database(path.join(__dirname, 'data.db'));

db.serialize(() => {
  // Garantizar llaves foráneas activas
  db.run('PRAGMA foreign_keys = ON');

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT,
    full_name TEXT,
    phone TEXT,
    department TEXT,
    last_login TEXT,
    created_at TEXT NOT NULL
  )`);
  // Intento de migración: agregar columnas si no existen (no falla si ya existen)
  db.run(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT '${Role.Roles.PERSONAL}'`, (err) => {});
  db.run(`ALTER TABLE users ADD COLUMN email TEXT`, (err) => {});
  db.run(`ALTER TABLE users ADD COLUMN full_name TEXT`, (err) => {});
  db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, (err) => {});
  db.run(`ALTER TABLE users ADD COLUMN department TEXT`, (err) => {});
  db.run(`ALTER TABLE users ADD COLUMN last_login TEXT`, (err) => {});

  // RBAC: roles
  db.run(`CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
  )`);

  // RBAC: permisos
  db.run(`CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
  )`);

  // RBAC: relación rol-permiso (muchos a muchos)
  db.run(`CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
  )`);

  // RBAC: relación usuario-rol (muchos a muchos)
  db.run(`CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
  )`);

  // Auditoría: registro de acciones
  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  )`);

  // Recuperación de contraseña: tokens temporales
  db.run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Historial de sesiones
  db.run(`CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    login_at TEXT NOT NULL,
    logout_at TEXT,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Notificaciones
  db.run(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT DEFAULT 'info',
    is_read INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Seed inicial de roles predefinidos (idempotente)
  const predefinedRoles = [
    Role.Roles.PERSONAL,
    Role.Roles.JEFE_AREA,
    Role.Roles.SUPERVISOR,
    Role.Roles.GERENTE,
    Role.Roles.DIRECTOR,
    Role.Roles.ADMIN
  ];
  const insertRoleStmt = db.prepare('INSERT OR IGNORE INTO roles (name) VALUES (?)');
  predefinedRoles.forEach((r) => insertRoleStmt.run([r]));
  insertRoleStmt.finalize();

  // Seed inicial de permisos básicos (idempotente)
  const predefinedPermissions = ['lectura', 'edicion', 'aprobacion', 'administracion'];
  const insertPermStmt = db.prepare('INSERT OR IGNORE INTO permissions (name) VALUES (?)');
  predefinedPermissions.forEach((p) => insertPermStmt.run([p]));
  insertPermStmt.finalize();

  // Mapear permisos por rol preexistentes del sistema actual
  // Nota: usamos subconsultas para obtener ids y poblar role_permissions
  function linkRolePerm(roleName, permName) {
    db.run(
      `INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
       VALUES ((SELECT id FROM roles WHERE name = ?), (SELECT id FROM permissions WHERE name = ?))`,
      [roleName, permName]
    );
  }

  // Personal
  linkRolePerm(Role.Roles.PERSONAL, 'lectura');
  // Jefe de Área / Supervisor
  ['Jefe de Área', 'Supervisor'].forEach((r) => {
    linkRolePerm(r, 'lectura');
    linkRolePerm(r, 'edicion');
  });
  // Gerente / Director
  ['Gerente', 'Director'].forEach((r) => {
    linkRolePerm(r, 'lectura');
    linkRolePerm(r, 'edicion');
    linkRolePerm(r, 'aprobacion');
  });
  // Administrador del Sistema
  [Role.Roles.ADMIN].forEach((r) => {
    linkRolePerm(r, 'lectura');
    linkRolePerm(r, 'edicion');
    linkRolePerm(r, 'aprobacion');
    linkRolePerm(r, 'administracion');
  });
});

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Helpers
const loginSystem = new LoginSystem(db, JWT_SECRET);
const rbac = new RBACService(db);
const audit = new AuditService(db);
const passwordReset = new PasswordResetService(db, JWT_SECRET);
const userService = new UserService(db);

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    const decoded = loginSystem.verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function requirePermission(permission) {
  return async (req, res, next) => {
    try {
      const ok = await rbac.userHasPermission(req.user.userId, permission);
      if (!ok) return res.status(403).json({ error: `Permiso requerido: ${permission}` });
      next();
    } catch (e) {
      return res.status(500).json({ error: 'Error de autorización' });
    }
  };
}

// Routes
app.post('/api/register', (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
  }
  if (String(username).length < 3 || String(password).length < 6) {
    return res.status(400).json({ error: 'Usuario >= 3 y contraseña >= 6 caracteres' });
  }
  const roleName = AllowedRoles.includes(role) ? role : Role.Roles.PERSONAL;

  const passwordHash = bcrypt.hashSync(String(password), 10);
  const createdAt = new Date().toISOString();

  const stmt = db.prepare('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)');
  stmt.run([String(username).toLowerCase(), passwordHash, roleName, createdAt], function(err) {
    if (err) {
      if (String(err.message).includes('UNIQUE')) {
        return res.status(409).json({ error: 'Usuario ya existe' });
      }
      return res.status(500).json({ error: 'Error al registrar' });
    }
    // Asignar rol inicial también a la tabla user_roles (RBAC)
    rbac.assignRoleToUser(this.lastID, roleName).catch(() => {});
    audit.log({ userId: this.lastID, action: 'user.register', resource: 'users', metadata: { username, role: roleName } }).catch(() => {});
    return res.json({ success: true, id: this.lastID, username, role: roleName });
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [String(username).toLowerCase()], (err, row) => {
    if (err) return res.status(500).json({ error: 'Error en la base de datos' });
    if (!row) return res.status(401).json({ error: 'Credenciales inválidas' });

    const isValid = bcrypt.compareSync(String(password), row.password_hash);
    if (!isValid) return res.status(401).json({ error: 'Credenciales inválidas' });

    const token = loginSystem.generateToken({ userId: row.id, username: row.username, role: row.role });
    
    // Registrar sesión
    const ipAddress = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.get('User-Agent') || 'unknown';
    userService.logUserSession(row.id, token, ipAddress, userAgent).catch(() => {});
    
    audit.log({ userId: row.id, action: 'user.login', resource: 'auth' }).catch(() => {});
    return res.json({ token, username: row.username, role: row.role });
  });
});

app.get('/api/profile', authMiddleware, (req, res) => {
  return res.json({ user: req.user });
});

// Autorización basada en rol/acción
app.post('/api/authorize', authMiddleware, async (req, res) => {
  const { action } = req.body;
  if (!action) return res.status(400).json({ error: 'Acción requerida' });
  try {
    const allowed = await rbac.userHasPermission(req.user.userId, action);
    audit.log({ userId: req.user.userId, action: 'auth.authorize', resource: action, metadata: { allowed } }).catch(() => {});
    return res.json({ allowed, action });
  } catch (e) {
    console.error('Authorize error:', e);
    return res.status(500).json({ error: 'Error al autorizar' });
  }
});

// Admin RBAC: gestión de roles y permisos (protegidos por permiso "administracion")
app.get('/api/rbac/roles', authMiddleware, requirePermission('administracion'), async (req, res) => {
  try {
    const roles = await rbac.listRoles();
    res.json({ roles });
  } catch (e) {
    res.status(500).json({ error: 'Error al listar roles' });
  }
});

app.post('/api/rbac/roles', authMiddleware, requirePermission('administracion'), async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Nombre de rol requerido' });
  try {
    await rbac.createRole(name);
    audit.log({ userId: req.user.userId, action: 'rbac.role.create', resource: name }).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al crear rol' });
  }
});

app.delete('/api/rbac/roles', authMiddleware, requirePermission('administracion'), async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Nombre de rol requerido' });
  try {
    await rbac.deleteRole(name);
    audit.log({ userId: req.user.userId, action: 'rbac.role.delete', resource: name }).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al eliminar rol' });
  }
});

app.get('/api/rbac/permissions', authMiddleware, requirePermission('administracion'), async (req, res) => {
  try {
    const permissions = await rbac.listPermissions();
    res.json({ permissions });
  } catch (e) {
    res.status(500).json({ error: 'Error al listar permisos' });
  }
});

app.post('/api/rbac/permissions', authMiddleware, requirePermission('administracion'), async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Nombre de permiso requerido' });
  try {
    await rbac.createPermission(name);
    audit.log({ userId: req.user.userId, action: 'rbac.permission.create', resource: name }).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al crear permiso' });
  }
});

app.delete('/api/rbac/permissions', authMiddleware, requirePermission('administracion'), async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Nombre de permiso requerido' });
  try {
    await rbac.deletePermission(name);
    audit.log({ userId: req.user.userId, action: 'rbac.permission.delete', resource: name }).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al eliminar permiso' });
  }
});

app.post('/api/rbac/roles/assign-permission', authMiddleware, requirePermission('administracion'), async (req, res) => {
  const { role, permission } = req.body;
  if (!role || !permission) return res.status(400).json({ error: 'Rol y permiso requeridos' });
  try {
    await rbac.assignPermissionToRole(role, permission);
    audit.log({ userId: req.user.userId, action: 'rbac.role.assignPermission', resource: role, metadata: { permission } }).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al asignar permiso' });
  }
});

app.post('/api/rbac/users/assign-role', authMiddleware, requirePermission('administracion'), async (req, res) => {
  const { userId, role } = req.body;
  if (!userId || !role) return res.status(400).json({ error: 'userId y rol requeridos' });
  try {
    await rbac.assignRoleToUser(userId, role);
    audit.log({ userId: req.user.userId, action: 'rbac.user.assignRole', resource: String(userId), metadata: { role } }).catch(() => {});
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al asignar rol al usuario' });
  }
});

app.get('/api/audit', authMiddleware, requirePermission('administracion'), async (req, res) => {
  try {
    const items = await audit.list({ limit: 100, offset: 0 });
    res.json({ items });
  } catch (e) {
    res.status(500).json({ error: 'Error al listar auditoría' });
  }
});

// Recuperación de contraseña
app.post('/api/password-reset/request', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Usuario requerido' });
  }

  try {
    const { token, expiresAt } = await passwordReset.generateResetToken(username);
    // En producción, aquí enviarías el token por email
    // Por ahora lo devolvemos en la respuesta para testing
    audit.log({ 
      userId: null, 
      action: 'password.reset.request', 
      resource: username,
      metadata: { token: token.substring(0, 8) + '...' }
    }).catch(() => {});
    
    res.json({ 
      success: true, 
      message: 'Token generado (en producción se enviaría por email)',
      token, // Solo para testing - remover en producción
      expiresAt 
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/password-reset/confirm', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token y nueva contraseña requeridos' });
  }

  try {
    await passwordReset.resetPassword(token, newPassword);
    audit.log({ 
      userId: null, 
      action: 'password.reset.confirm', 
      resource: 'password',
      metadata: { token: token.substring(0, 8) + '...' }
    }).catch(() => {});
    
    res.json({ success: true, message: 'Contraseña actualizada correctamente' });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Limpiar tokens expirados (endpoint de mantenimiento)
app.post('/api/password-reset/cleanup', authMiddleware, requirePermission('administracion'), async (req, res) => {
  try {
    await passwordReset.cleanupExpiredTokens();
    res.json({ success: true, message: 'Tokens expirados eliminados' });
  } catch (e) {
    res.status(500).json({ error: 'Error al limpiar tokens' });
  }
});

// Endpoints de usuario (disponibles para todos los roles)
app.get('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const profile = await userService.getUserProfile(req.user.userId);
    if (!profile) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ profile });
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener perfil' });
  }
});

app.put('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const { email, full_name, phone, department } = req.body;
    await userService.updateUserProfile(req.user.userId, { email, full_name, phone, department });
    audit.log({ userId: req.user.userId, action: 'user.profile.update', resource: 'profile' }).catch(() => {});
    res.json({ success: true, message: 'Perfil actualizado correctamente' });
  } catch (e) {
    res.status(500).json({ error: 'Error al actualizar perfil' });
  }
});

app.post('/api/user/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Contraseña actual y nueva contraseña requeridas' });
    }
    
    await userService.changePassword(req.user.userId, currentPassword, newPassword);
    audit.log({ userId: req.user.userId, action: 'user.password.change', resource: 'password' }).catch(() => {});
    res.json({ success: true, message: 'Contraseña actualizada correctamente' });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/api/user/sessions', authMiddleware, async (req, res) => {
  try {
    const sessions = await userService.getUserSessions(req.user.userId, 20);
    res.json({ sessions });
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener sesiones' });
  }
});

app.post('/api/user/logout', authMiddleware, async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (token) {
      await userService.logoutUserSession(token);
    }
    audit.log({ userId: req.user.userId, action: 'user.logout', resource: 'auth' }).catch(() => {});
    res.json({ success: true, message: 'Sesión cerrada correctamente' });
  } catch (e) {
    res.status(500).json({ error: 'Error al cerrar sesión' });
  }
});

app.get('/api/user/notifications', authMiddleware, async (req, res) => {
  try {
    const notifications = await userService.getUserNotifications(req.user.userId, 20);
    res.json({ notifications });
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener notificaciones' });
  }
});

app.post('/api/user/notifications/:id/read', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await userService.markNotificationAsRead(id, req.user.userId);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al marcar notificación' });
  }
});

app.get('/api/user/stats', authMiddleware, async (req, res) => {
  try {
    const stats = await userService.getUserStats(req.user.userId);
    res.json({ stats });
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener estadísticas' });
  }
});

// Endpoints de administración de usuarios (solo admin)
app.get('/api/admin/users', authMiddleware, requirePermission('administracion'), async (req, res) => {
  try {
    const users = await userService.listAllUsers(50);
    res.json({ users });
  } catch (e) {
    res.status(500).json({ error: 'Error al listar usuarios' });
  }
});

app.get('/api/admin/sessions', authMiddleware, requirePermission('administracion'), async (req, res) => {
  try {
    const sessions = await userService.getAllSessions(100);
    res.json({ sessions });
  } catch (e) {
    res.status(500).json({ error: 'Error al obtener sesiones' });
  }
});

app.post('/api/admin/notify', authMiddleware, requirePermission('administracion'), async (req, res) => {
  try {
    const { userId, title, message, type = 'info' } = req.body;
    if (!userId || !title || !message) {
      return res.status(400).json({ error: 'userId, title y message requeridos' });
    }
    
    await userService.createNotification(userId, title, message, type);
    audit.log({ userId: req.user.userId, action: 'admin.notify', resource: String(userId), metadata: { title } }).catch(() => {});
    res.json({ success: true, message: 'Notificación enviada' });
  } catch (e) {
    res.status(500).json({ error: 'Error al enviar notificación' });
  }
});

// Fallback to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});


