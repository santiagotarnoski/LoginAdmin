export class AuditService {
  constructor(db) {
    this.db = db;
  }

  async log({ userId = null, action, resource = null, metadata = null }) {
    const createdAt = new Date().toISOString();
    const metaStr = metadata ? JSON.stringify(metadata) : null;
    await this._run(
      `INSERT INTO audit_logs (user_id, action, resource, metadata, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, String(action), resource, metaStr, createdAt]
    );
  }

  async list({ limit = 100, offset = 0 } = {}) {
    return await this._all(
      `SELECT al.id, al.user_id, al.action, al.resource, al.metadata, al.created_at, u.username
       FROM audit_logs al
       LEFT JOIN users u ON u.id = al.user_id
       ORDER BY al.id DESC
       LIMIT ? OFFSET ?`,
      [Number(limit), Number(offset)]
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

  _all(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      });
    });
  }
}






