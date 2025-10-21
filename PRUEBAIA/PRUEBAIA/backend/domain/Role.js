export class Role {
  static Roles = {
    PERSONAL: 'Personal',
    JEFE_AREA: 'Jefe de Área',
    GERENTE: 'Gerente',
    DIRECTOR: 'Director',
    SUPERVISOR: 'Supervisor',
    ADMIN: 'Administrador del Sistema'
  };

  static PermissionsByRole = {
    [Role.Roles.PERSONAL]: new Set(['lectura']),
    [Role.Roles.JEFE_AREA]: new Set(['lectura', 'edicion']),
    [Role.Roles.SUPERVISOR]: new Set(['lectura', 'edicion']),
    [Role.Roles.GERENTE]: new Set(['lectura', 'edicion', 'aprobacion']),
    [Role.Roles.DIRECTOR]: new Set(['lectura', 'edicion', 'aprobacion']),
    [Role.Roles.ADMIN]: new Set(['lectura', 'edicion', 'aprobacion', 'administracion'])
  };

  constructor(name) {
    this.name = name;
    this.permissions = Role.PermissionsByRole[name] || new Set();
  }

  can(action) {
    return this.permissions.has(action);
  }
}

export const AllowedRoles = Object.values(Role.Roles);
export const AllowedActions = ['lectura', 'edicion', 'aprobacion', 'administracion'];


