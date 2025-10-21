import crypto from 'crypto';
import bcrypt from 'bcryptjs';

export class PasswordResetService {
  constructor(db, jwtSecret) {
    this.db = db;
    this.jwtSecret = jwtSecret;
  }

  // Generar token de recuperación
  async generateResetToken(username) {
    const user = await this._getUserByUsername(username);
    if (!user) {
      throw new Error('Usuario no encontrado');
    }

    // Generar token único
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutos
    const createdAt = new Date().toISOString();

    // Guardar token en BD
    await this._run(
      `INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at) 
       VALUES (?, ?, ?, ?)`,
      [user.id, token, expiresAt, createdAt]
    );

    return { token, expiresAt };
  }

  // Validar token y resetear contraseña
  async resetPassword(token, newPassword) {
    if (!token || !newPassword) {
      throw new Error('Token y nueva contraseña requeridos');
    }

    if (String(newPassword).length < 6) {
      throw new Error('La contraseña debe tener al menos 6 caracteres');
    }

    // Buscar token válido
    const tokenData = await this._getValidToken(token);
    if (!tokenData) {
      throw new Error('Token inválido o expirado');
    }

    // Verificar que no esté usado
    if (tokenData.used_at) {
      throw new Error('Token ya utilizado');
    }

    // Hash de la nueva contraseña
    const passwordHash = bcrypt.hashSync(String(newPassword), 10);

    // Actualizar contraseña del usuario
    await this._run(
      'UPDATE users SET password_hash = ? WHERE id = ?',
      [passwordHash, tokenData.user_id]
    );

    // Marcar token como usado
    await this._run(
      'UPDATE password_reset_tokens SET used_at = ? WHERE token = ?',
      [new Date().toISOString(), token]
    );

    return { success: true };
  }

  // Limpiar tokens expirados
  async cleanupExpiredTokens() {
    await this._run(
      'DELETE FROM password_reset_tokens WHERE expires_at < ?',
      [new Date().toISOString()]
    );
  }

  // Helpers
  async _getUserByUsername(username) {
    return await this._get(
      'SELECT id, username FROM users WHERE username = ?',
      [String(username).toLowerCase()]
    );
  }

  async _getValidToken(token) {
    return await this._get(
      `SELECT user_id, token, expires_at, used_at 
       FROM password_reset_tokens 
       WHERE token = ? AND expires_at > ?`,
      [token, new Date().toISOString()]
    );
  }

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
}


