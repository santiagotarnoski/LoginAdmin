import bcrypt from 'bcryptjs';
import { Role } from './Role.js';

export class User {
  #username;
  #passwordHash;
  #role;

  constructor(username, passwordHash, roleName) {
    this.#username = username;
    this.#passwordHash = passwordHash;
    this.#role = new Role(roleName);
  }

  getUsername() { return this.#username; }
  getRol() { return this.#role; }

  validarClave(plainPassword) {
    return bcrypt.compareSync(String(plainPassword), this.#passwordHash);
  }

  toSafeJSON() {
    return { username: this.#username, role: this.#role.name };
  }
}


