'use strict';
class RBAC {
  constructor(config = {}) {
    this.roles = new Map();
    for (const [role, def] of Object.entries(config)) this.roles.set(role, { permissions: new Set(def.permissions || []), inherits: def.inherits || [] });
  }

  addRole(name, perms = [], inherits = []) { this.roles.set(name, { permissions: new Set(perms), inherits }); }

  can(userRoles, perm) {
    const roles = Array.isArray(userRoles) ? userRoles : [userRoles];
    return roles.some(r => this._has(r, perm, new Set()));
  }

  hasAnyRole(userRoles, required) {
    const r = Array.isArray(userRoles) ? userRoles : [userRoles];
    const req = Array.isArray(required) ? required : [required];
    return req.some(x => r.includes(x));
  }

  getPermissions(roleName) { const all = new Set(); this._collect(roleName, all, new Set()); return [...all]; }

  _has(name, perm, visited) {
    if (visited.has(name)) return false; visited.add(name);
    const r = this.roles.get(name); if (!r) return false;
    if (r.permissions.has(perm) || r.permissions.has('*')) return true;
    return r.inherits.some(p => this._has(p, perm, visited));
  }

  _collect(name, all, visited) {
    if (visited.has(name)) return; visited.add(name);
    const r = this.roles.get(name); if (!r) return;
    for (const p of r.permissions) all.add(p);
    for (const parent of r.inherits) this._collect(parent, all, visited);
  }
}
module.exports = { RBAC };
