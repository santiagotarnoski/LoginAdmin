import jwt from 'jsonwebtoken';
import { Role, AllowedActions } from './Role.js';
import { User } from './User.js';

export class LoginSystem {
  constructor(db, jwtSecret) {
    this.db = db;
    this.jwtSecret = jwtSecret;
  }

  findUserByUsername(username) {
    return new Promise((resolve, reject) => {
      this.db.get('SELECT * FROM users WHERE username = ?', [String(username).toLowerCase()], (err, row) => {
        if (err) return reject(err);
        if (!row) return resolve(null);
        resolve(new User(row.username, row.password_hash, row.role));
      });
    });
  }

  register({ username, password, role }) {
    return new Promise((resolve, reject) => {
      const createdAt = new Date().toISOString();
      const stmt = this.db.prepare('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)');
      stmt.run([String(username).toLowerCase(), password, role, createdAt], function(err){
        if (err) return reject(err);
        resolve({ id: this.lastID, username, role });
      });
    });
  }

  generateToken(payload) {
    return jwt.sign(payload, this.jwtSecret, { expiresIn: '2h' });
  }

  verifyToken(token) {
    return jwt.verify(token, this.jwtSecret);
  }

  authorize(user, action) {
    if (!AllowedActions.includes(action)) return false;
    return user.getRol().can(action);
  }
}


