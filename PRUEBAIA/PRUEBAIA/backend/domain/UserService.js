import bcrypt from 'bcryptjs';

export class UserService {
  constructor(db) {
    this.db = db;
  }

  // Obtener perfil completo del usuario
  async getUserProfile(userId) {
    return await this._get(
      `SELECT id, username, email, full_name, phone, department, role, last_login, created_at
       FROM users WHERE id = ?`,
      [Number(userId)]
    );
  }

  // Actualizar perfil del usuario
  async updateUserProfile(userId, profileData) {
    const { email, full_name, phone, department } = profileData;
    
    await this._run(
      `UPDATE users 
       SET email = ?, full_name = ?, phone = ?, department = ?
       WHERE id = ?`,
      [email, full_name, phone, department, Number(userId)]
    );
  }

  // Cambiar contraseña
  async changePassword(userId, currentPassword, newPassword) {
    // Verificar contraseña actual
    const user = await this._get('SELECT password_hash FROM users WHERE id = ?', [Number(userId)]);
    if (!user) throw new Error('Usuario no encontrado');

    const isValid = bcrypt.compareSync(currentPassword, user.password_hash);
    if (!isValid) throw new Error('Contraseña actual incorrecta');

    if (String(newPassword).length < 6) {
      throw new Error('La nueva contraseña debe tener al menos 6 caracteres');
    }

    // Actualizar contraseña
    const passwordHash = bcrypt.hashSync(String(newPassword), 10);
    await this._run(
      'UPDATE users SET password_hash = ? WHERE id = ?',
      [passwordHash, Number(userId)]
    );
  }

  // Registrar sesión de login
  async logUserSession(userId, sessionToken, ipAddress, userAgent) {
    const loginAt = new Date().toISOString();
    
    await this._run(
      `INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, login_at)
       VALUES (?, ?, ?, ?, ?)`,
      [Number(userId), sessionToken, ipAddress, userAgent, loginAt]
    );

    // Actualizar last_login del usuario
    await this._run(
      'UPDATE users SET last_login = ? WHERE id = ?',
      [loginAt, Number(userId)]
    );
  }

  // Cerrar sesión
  async logoutUserSession(sessionToken) {
    const logoutAt = new Date().toISOString();
    await this._run(
      'UPDATE user_sessions SET logout_at = ?, is_active = 0 WHERE session_token = ?',
      [logoutAt, sessionToken]
    );
  }

  // Obtener historial de sesiones del usuario
  async getUserSessions(userId, limit = 20) {
    return await this._all(
      `SELECT id, ip_address, user_agent, login_at, logout_at, is_active
       FROM user_sessions 
       WHERE user_id = ?
       ORDER BY login_at DESC
       LIMIT ?`,
      [Number(userId), Number(limit)]
    );
  }

  // Obtener todas las sesiones (solo admin)
  async getAllSessions(limit = 100) {
    return await this._all(
      `SELECT s.id, s.ip_address, s.user_agent, s.login_at, s.logout_at, s.is_active, u.username
       FROM user_sessions s
       JOIN users u ON u.id = s.user_id
       ORDER BY s.login_at DESC
       LIMIT ?`,
      [Number(limit)]
    );
  }

  // Crear notificación
  async createNotification(userId, title, message, type = 'info') {
    const createdAt = new Date().toISOString();
    await this._run(
      `INSERT INTO notifications (user_id, title, message, type, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [Number(userId), title, message, type, createdAt]
    );
  }

  // Obtener notificaciones del usuario
  async getUserNotifications(userId, limit = 20) {
    return await this._all(
      `SELECT id, title, message, type, is_read, created_at
       FROM notifications 
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT ?`,
      [Number(userId), Number(limit)]
    );
  }

  // Marcar notificación como leída
  async markNotificationAsRead(notificationId, userId) {
    await this._run(
      'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
      [Number(notificationId), Number(userId)]
    );
  }

  // Obtener estadísticas del usuario (para dashboard)
  async getUserStats(userId) {
    const stats = await this._get(
      `SELECT 
        (SELECT COUNT(*) FROM user_sessions WHERE user_id = ?) as total_sessions,
        (SELECT COUNT(*) FROM user_sessions WHERE user_id = ? AND is_active = 1) as active_sessions,
        (SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0) as unread_notifications,
        (SELECT last_login FROM users WHERE id = ?) as last_login`,
      [userId, userId, userId, userId]
    );
    return stats;
  }

  // Listar todos los usuarios (solo admin)
  async listAllUsers(limit = 50) {
    return await this._all(
      `SELECT id, username, email, full_name, phone, department, role, last_login, created_at
       FROM users 
       ORDER BY created_at DESC
       LIMIT ?`,
      [Number(limit)]
    );
  }

  // Helpers
  _run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) return reject(err);
        resolve(this);
      });
    });
  }

  _get(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      });
    });
  }

  _all(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      });
    });
  }
}


