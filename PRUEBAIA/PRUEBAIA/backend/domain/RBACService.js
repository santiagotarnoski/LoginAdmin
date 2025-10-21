export class RBACService {
  constructor(db) {
    this.db = db;
  }

  // Roles
  async listRoles() {
    return await this._all('SELECT id, name FROM roles ORDER BY name');
  }

  async createRole(name) {
    await this._run('INSERT INTO roles (name) VALUES (?)', [String(name)]);
  }

  async deleteRole(name) {
    await this._run('DELETE FROM roles WHERE name = ?', [String(name)]);
  }

  // Permisos
  async listPermissions() {
    return await this._all('SELECT id, name FROM permissions ORDER BY name');
  }

  async createPermission(name) {
    await this._run('INSERT INTO permissions (name) VALUES (?)', [String(name)]);
  }

  async deletePermission(name) {
    await this._run('DELETE FROM permissions WHERE name = ?', [String(name)]);
  }

  // Asignaciones rol-permiso
  async assignPermissionToRole(roleName, permissionName) {
    await this._run(
      `INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
       VALUES ((SELECT id FROM roles WHERE name = ?), (SELECT id FROM permissions WHERE name = ?))`,
      [String(roleName), String(permissionName)]
    );
  }

  async revokePermissionFromRole(roleName, permissionName) {
    await this._run(
      `DELETE FROM role_permissions
       WHERE role_id = (SELECT id FROM roles WHERE name = ?)
       AND permission_id = (SELECT id FROM permissions WHERE name = ?)` ,
      [String(roleName), String(permissionName)]
    );
  }

  // Asignaciones usuario-rol
  async assignRoleToUser(userId, roleName) {
    await this._run(
      `INSERT OR IGNORE INTO user_roles (user_id, role_id)
       VALUES (?, (SELECT id FROM roles WHERE name = ?))`,
      [Number(userId), String(roleName)]
    );
  }

  async revokeRoleFromUser(userId, roleName) {
    await this._run(
      `DELETE FROM user_roles
       WHERE user_id = ? AND role_id = (SELECT id FROM roles WHERE name = ?)` ,
      [Number(userId), String(roleName)]
    );
  }

  async listUserRoles(userId) {
    return await this._all(
      `SELECT r.name AS role
       FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id
       WHERE ur.user_id = ?
       ORDER BY r.name`,
      [Number(userId)]
    );
  }

  async listRolePermissions(roleName) {
    return await this._all(
      `SELECT p.name AS permission
       FROM role_permissions rp
       JOIN roles r ON r.id = rp.role_id
       JOIN permissions p ON p.id = rp.permission_id
       WHERE r.name = ?
       ORDER BY p.name`,
      [String(roleName)]
    );
  }

  async userHasPermission(userId, permissionName) {
    const row = await this._get(
      `SELECT 1 AS ok
       FROM user_roles ur
       JOIN role_permissions rp ON rp.role_id = ur.role_id
       JOIN permissions p ON p.id = rp.permission_id
       WHERE ur.user_id = ? AND p.name = ?
       LIMIT 1`,
      [Number(userId), String(permissionName)]
    );
    return Boolean(row && row.ok);
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






