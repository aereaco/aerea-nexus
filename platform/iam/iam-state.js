/**
 * Aerea-Nexus IAM Workbench State & Actions Module
 * Loaded declaratively via `data-signal-src="/_pages/apps/iam/iam-state.js"`.
 * Mutates the live ZCZS reactive `scope` proxy directly (zero copy).
 */
export default function createIamState(s) {
  const ALL_CAPS = [
    'db.read',
    'db.write',
    'db.admin',
    'blob.read',
    'blob.write',
    'cell.spawn',
    'cell.manage',
    'runtime.install',
    'secrets.read',
    'metrics.read',
  ];

  const SYSTEM_ROLES = [
    {
      name: 'OWNER',
      desc: 'Full database, storage, cell, and IAM administration',
      caps: [...ALL_CAPS],
    },
    {
      name: 'EDITOR',
      desc: 'Read/write data, S3 blobs, and spawn Wasm cells',
      caps: ['db.read', 'db.write', 'blob.read', 'blob.write', 'cell.spawn', 'metrics.read'],
    },
    {
      name: 'VIEWER',
      desc: 'Read-only access to permitted tables and S3 blobs',
      caps: ['db.read', 'blob.read'],
    },
  ];

  const notify = (title, msg, type = 'info') => {
    const g = window.UX?.signals || {};
    if (typeof g.notify === 'function') g.notify(title, msg, type);
  };

  const safeProfileId = (username) =>
    'iam_profile:u_' + String(username || '').replace(/[^a-zA-Z0-9_]/g, '_');

  const getGroups = () => {
    const list = s.groupsLive && Array.isArray(s.groupsLive.data) ? s.groupsLive.data : [];
    return [...list].sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
  };

  const getCustomRoles = () => {
    const list = s.rolesLive && Array.isArray(s.rolesLive.data) ? s.rolesLive.data : [];
    return [...list].sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
  };

  const getPolicies = () => {
    const list = s.policiesLive && Array.isArray(s.policiesLive.data) ? s.policiesLive.data : [];
    return [...list].sort((a, b) => String(a.table || '').localeCompare(String(b.table || '')));
  };

  const getProfile = (username) => {
    const list = s.profilesLive && Array.isArray(s.profilesLive.data) ? s.profilesLive.data : [];
    const targetId = safeProfileId(username);
    return (
      list.find((p) => p.id === targetId || p.username === username) || {
        username,
        display_name: username,
        email: '',
        title: '',
        department: '',
        status: 'active',
        avatar_path: '',
        custom_roles: [],
      }
    );
  };

  const getUserGroups = (username) =>
    getGroups().filter((g) => Array.isArray(g.members) && g.members.includes(username));

  const getRoleCaps = (roleName) => {
    const sys = SYSTEM_ROLES.find((r) => r.name === roleName);
    if (sys) return sys.caps;
    const custom = getCustomRoles().find((r) => r.name === roleName);
    return custom && Array.isArray(custom.caps) ? custom.caps : [];
  };

  const getEffectiveCaps = (userObj) => {
    if (!userObj) return [];
    const set = new Set();
    const baseRoles = Array.isArray(userObj.roles) ? userObj.roles : [];
    for (const r of baseRoles) {
      for (const c of getRoleCaps(r)) set.add(c);
    }
    const prof = getProfile(userObj.name);
    for (const cr of Array.isArray(prof.custom_roles) ? prof.custom_roles : []) {
      for (const c of getRoleCaps(cr)) set.add(c);
    }
    for (const grp of getUserGroups(userObj.name)) {
      if (grp.role) {
        for (const c of getRoleCaps(grp.role)) set.add(c);
      }
      for (const gc of Array.isArray(grp.caps) ? grp.caps : []) set.add(gc);
      for (const gcr of Array.isArray(grp.custom_roles) ? grp.custom_roles : []) {
        for (const c of getRoleCaps(gcr)) set.add(c);
      }
    }
    return [...set].sort();
  };

  return {
    iamReady: true,
    iamTab: 'users',
    iamSyncedActor: null,
    iamSyncing: false,
    users: [],
    groupsLive: null,
    rolesLive: null,
    policiesLive: null,
    profilesLive: null,
    allCaps: ALL_CAPS,
    systemRoles: SYSTEM_ROLES,

    // Add User form
    uName: '',
    uPass: '',
    uRole: 'VIEWER',

    // Account Profile Modal state
    userModalOpen: false,
    userModalTab: 'profile',
    activeUserName: null,
    profDisplayName: '',
    profEmail: '',
    profTitle: '',
    profDepartment: '',
    profStatus: 'active',
    profAvatarPath: '',
    profBaseRole: 'VIEWER',
    profCustomRoles: [],
    profNewPass: '',

    // Group Management Modal state
    groupModalOpen: false,
    editingGroupId: null,
    gName: '',
    gDesc: '',
    gRole: 'VIEWER',
    gMembers: [],
    gCustomRoles: [],
    gCaps: [],

    // Role & Permissions Modal state
    roleModalOpen: false,
    editingRoleId: null,
    rName: '',
    rDesc: '',
    rBase: 'VIEWER',
    rCaps: ['db.read', 'blob.read'],

    // Record & Field Policy form state
    editingPolicyId: null,
    pTable: 'erp_po',
    pScope: 'table',
    pField: '',
    pMode: 'where',
    pOps: 'select, create, update, delete',
    pExpr: 'owner == $auth',

    getGroups,
    getCustomRoles,
    getPolicies,
    getProfile,
    getUserGroups,
    getRoleCaps,
    getEffectiveCaps,

    getActiveUserObj: () => (s.users || []).find((u) => u.name === s.activeUserName) || null,

    refreshUsers: async () => {
      try {
        const res = await window.fetch('/_nexus/iam/users', { credentials: 'same-origin' });
        if (res.ok) {
          const data = await res.json();
          s.users = Array.isArray(data.users) ? data.users : [];
        }
      } catch (_) {}
    },

    disconnectIam: async () => {
      const handles = [s.groupsLive, s.rolesLive, s.policiesLive, s.profilesLive].filter(Boolean);
      s.groupsLive = null;
      s.rolesLive = null;
      s.policiesLive = null;
      s.profilesLive = null;
      s.users = [];
      s.iamSyncedActor = null;
      for (const h of handles) {
        try {
          if (typeof h.unsubscribe === 'function') await h.unsubscribe();
        } catch (_) {}
      }
    },

    connectIam: async (sqlFn, actor) => {
      if (!sqlFn || !actor || s.iamSyncing || s.iamSyncedActor === actor) return;
      s.iamSyncing = true;
      try {
        await s.disconnectIam();
        await s.refreshUsers();
        s.groupsLive = await sqlFn('LIVE SELECT * FROM iam_group');
        s.rolesLive = await sqlFn('LIVE SELECT * FROM iam_role');
        s.policiesLive = await sqlFn('LIVE SELECT * FROM iam_policy');
        s.profilesLive = await sqlFn('LIVE SELECT * FROM iam_profile');
        s.iamSyncedActor = actor;
      } catch (_) {
        s.iamSyncedActor = null;
      } finally {
        s.iamSyncing = false;
      }
    },

    // ==================== USERS & ACCOUNT PROFILE MODAL ====================
    addUser: async () => {
      const name = (s.uName || '').trim();
      const pass = s.uPass || '';
      if (!name || pass.length < 4) {
        notify('Validation', 'Username and password (min 4 chars) required', 'warning');
        return;
      }
      const res = await window.fetch('/_nexus/iam/users', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: name, pass, roles: [s.uRole || 'VIEWER'] }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        notify('Create User Failed', data.details || `HTTP ${res.status}`, 'error');
        return;
      }
      s.uName = '';
      s.uPass = '';
      s.uRole = 'VIEWER';
      await s.refreshUsers();
      notify('User Created', `${name} added to Nexus-IO IAM`, 'success');
    },

    openUserModal: (u, tab = 'profile') => {
      if (!u) return;
      const prof = getProfile(u.name);
      s.activeUserName = u.name;
      s.userModalTab = tab;
      s.profDisplayName = prof.display_name || u.name;
      s.profEmail = prof.email || '';
      s.profTitle = prof.title || '';
      s.profDepartment = prof.department || '';
      s.profStatus = prof.status || 'active';
      s.profAvatarPath = prof.avatar_path || '';
      s.profBaseRole = Array.isArray(u.roles) && u.roles[0] ? u.roles[0] : 'VIEWER';
      s.profCustomRoles = Array.isArray(prof.custom_roles) ? [...prof.custom_roles] : [];
      s.profNewPass = '';
      s.userModalOpen = true;
    },

    closeUserModal: () => {
      s.userModalOpen = false;
      s.activeUserName = null;
      s.profNewPass = '';
    },

    toggleUserCustomRole: (roleName) => {
      const cur = Array.isArray(s.profCustomRoles) ? s.profCustomRoles : [];
      s.profCustomRoles = cur.includes(roleName)
        ? cur.filter((r) => r !== roleName)
        : [...cur, roleName];
    },

    saveUserProfile: async (sqlFn) => {
      if (!s.activeUserName || !sqlFn) return;
      const pid = safeProfileId(s.activeUserName);
      const exists = (s.profilesLive?.data || []).some((p) => p.id === pid);
      const q = exists
        ? `UPDATE ${pid} SET username = $u, display_name = $dn, email = $em, title = $ti, department = $dept, status = $st, avatar_path = $av, custom_roles = $cr;`
        : `CREATE ${pid} SET username = $u, display_name = $dn, email = $em, title = $ti, department = $dept, status = $st, avatar_path = $av, custom_roles = $cr;`;
      const r = await sqlFn(q, {
        u: s.activeUserName,
        dn: (s.profDisplayName || '').trim() || s.activeUserName,
        em: (s.profEmail || '').trim(),
        ti: (s.profTitle || '').trim(),
        dept: (s.profDepartment || '').trim(),
        st: s.profStatus || 'active',
        av: s.profAvatarPath || '',
        cr: [...(s.profCustomRoles || [])],
      });
      if (r && r.status === 'error') {
        notify('Profile Save Error', r.error, 'error');
        return;
      }
      notify('Profile Saved', `${s.activeUserName} profile persisted in Nexus-DB`, 'success');
    },

    saveUserRolesAndSecurity: async (sqlFn) => {
      if (!s.activeUserName) return;
      const body = { roles: [s.profBaseRole || 'VIEWER'] };
      if (s.profNewPass && s.profNewPass.length > 0) body.pass = s.profNewPass;
      const res = await window.fetch('/_nexus/iam/users/' + encodeURIComponent(s.activeUserName), {
        method: 'PUT',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        notify('Update Rejected', data.details || `HTTP ${res.status}`, 'error');
        return;
      }
      s.profNewPass = '';
      if (sqlFn) await s.saveUserProfile(sqlFn);
      await s.refreshUsers();
      notify('Account Updated', `${s.activeUserName} roles & security updated`, 'success');
    },

    uploadUserAvatar: async (fileInput, sqlFn) => {
      const file = fileInput?.files?.[0];
      if (!file || !s.activeUserName) return;
      const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
      const path = `/s3/iam-avatars/${encodeURIComponent(s.activeUserName)}-${Date.now()}-${safeName}`;
      try {
        const res = await window.fetch(path, {
          method: 'PUT',
          credentials: 'same-origin',
          headers: { 'Content-Type': file.type || 'application/octet-stream' },
          body: file,
        });
        if (!res.ok) {
          notify('Avatar Upload Failed', `HTTP ${res.status}`, 'error');
          return;
        }
        s.profAvatarPath = path;
        if (sqlFn) await s.saveUserProfile(sqlFn);
      } finally {
        if (fileInput) fileInput.value = '';
      }
    },

    toggleUserInGroup: async (username, grp, sqlFn) => {
      if (!username || !grp || !grp.id || !sqlFn) return;
      const cur = Array.isArray(grp.members) ? grp.members : [];
      const next = cur.includes(username) ? cur.filter((m) => m !== username) : [...cur, username];
      const r = await sqlFn(`UPDATE ${grp.id} SET members = $members;`, { members: next });
      if (r && r.status === 'error') {
        notify('Membership Error', r.error, 'error');
        return;
      }
      notify(
        'Group Membership Updated',
        `${username} ${next.includes(username) ? 'added to' : 'removed from'} ${grp.name}`,
        'success'
      );
    },

    deleteUser: async (name) => {
      const res = await window.fetch('/_nexus/iam/users/' + encodeURIComponent(name), {
        method: 'DELETE',
        credentials: 'same-origin',
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        notify('Delete Blocked', data.details || `HTTP ${res.status}`, 'error');
        return;
      }
      if (s.activeUserName === name) s.closeUserModal();
      await s.refreshUsers();
      notify('User Deleted', `${name} removed from IAM`, 'info');
    },

    // ==================== GROUP MANAGEMENT MODAL ====================
    openGroupModal: (grp = null) => {
      if (grp) {
        s.editingGroupId = grp.id;
        s.gName = grp.name || '';
        s.gDesc = grp.description || '';
        s.gRole = grp.role || 'VIEWER';
        s.gMembers = Array.isArray(grp.members) ? [...grp.members] : [];
        s.gCustomRoles = Array.isArray(grp.custom_roles) ? [...grp.custom_roles] : [];
        s.gCaps = Array.isArray(grp.caps) ? [...grp.caps] : [];
      } else {
        s.editingGroupId = null;
        s.gName = '';
        s.gDesc = '';
        s.gRole = 'VIEWER';
        s.gMembers = [];
        s.gCustomRoles = [];
        s.gCaps = [];
      }
      s.groupModalOpen = true;
    },

    closeGroupModal: () => {
      s.groupModalOpen = false;
      s.editingGroupId = null;
    },

    toggleGroupMember: (username) => {
      const cur = Array.isArray(s.gMembers) ? s.gMembers : [];
      s.gMembers = cur.includes(username) ? cur.filter((m) => m !== username) : [...cur, username];
    },

    toggleGroupCustomRole: (roleName) => {
      const cur = Array.isArray(s.gCustomRoles) ? s.gCustomRoles : [];
      s.gCustomRoles = cur.includes(roleName)
        ? cur.filter((r) => r !== roleName)
        : [...cur, roleName];
    },

    toggleGroupCap: (cap) => {
      const cur = Array.isArray(s.gCaps) ? s.gCaps : [];
      s.gCaps = cur.includes(cap) ? cur.filter((c) => c !== cap) : [...cur, cap];
    },

    saveGroup: async (sqlFn) => {
      const name = (s.gName || '').trim();
      if (!name || !sqlFn) {
        notify('Validation', 'Group name is required', 'warning');
        return;
      }
      const ts = Date.now();
      const targetId = s.editingGroupId || `iam_group:grp_${ts}`;
      const q = s.editingGroupId
        ? `UPDATE ${targetId} SET name = $name, description = $desc, role = $role, members = $members, custom_roles = $croles, caps = $caps;`
        : `CREATE ${targetId} SET name = $name, description = $desc, role = $role, members = $members, custom_roles = $croles, caps = $caps, ts = $ts;`;
      const r = await sqlFn(q, {
        name,
        desc: (s.gDesc || '').trim(),
        role: s.gRole || 'VIEWER',
        members: [...(s.gMembers || [])],
        croles: [...(s.gCustomRoles || [])],
        caps: [...(s.gCaps || [])],
        ts,
      });
      if (r && r.status === 'error') {
        notify('Group Error', r.error, 'error');
        return;
      }
      const wasEdit = Boolean(s.editingGroupId);
      s.closeGroupModal();
      notify(wasEdit ? 'Group Updated' : 'Group Created', `${name} saved in Nexus-DB`, 'success');
    },

    deleteGroup: async (grp, sqlFn) => {
      if (!grp || !grp.id || !sqlFn) return;
      const r = await sqlFn(`DELETE ${grp.id};`);
      if (r && r.status === 'error') {
        notify('Delete Error', r.error, 'error');
        return;
      }
      if (s.editingGroupId === grp.id) s.closeGroupModal();
      notify('Group Deleted', `${grp.name} removed`, 'info');
    },

    // ==================== ROLE & PERMISSION MANAGEMENT MODAL ====================
    openRoleModal: (role = null) => {
      if (role) {
        s.editingRoleId = role.id;
        s.rName = role.name || '';
        s.rDesc = role.description || '';
        s.rBase = role.base_role || 'VIEWER';
        s.rCaps = Array.isArray(role.caps) ? [...role.caps] : ['db.read'];
      } else {
        s.editingRoleId = null;
        s.rName = '';
        s.rDesc = '';
        s.rBase = 'VIEWER';
        s.rCaps = ['db.read', 'blob.read'];
      }
      s.roleModalOpen = true;
    },

    closeRoleModal: () => {
      s.roleModalOpen = false;
      s.editingRoleId = null;
    },

    toggleRoleCap: (cap) => {
      const cur = Array.isArray(s.rCaps) ? s.rCaps : [];
      s.rCaps = cur.includes(cap) ? cur.filter((c) => c !== cap) : [...cur, cap];
    },

    saveRole: async (sqlFn) => {
      const name = (s.rName || '').trim();
      if (!name || !sqlFn) {
        notify('Validation', 'Role name is required', 'warning');
        return;
      }
      const ts = Date.now();
      const targetId = s.editingRoleId || `iam_role:role_${ts}`;
      const q = s.editingRoleId
        ? `UPDATE ${targetId} SET name = $name, description = $desc, base_role = $base, caps = $caps;`
        : `CREATE ${targetId} SET name = $name, description = $desc, base_role = $base, caps = $caps, ts = $ts;`;
      const r = await sqlFn(q, {
        name,
        desc: (s.rDesc || '').trim(),
        base: s.rBase || 'VIEWER',
        caps: [...(s.rCaps || [])],
        ts,
      });
      if (r && r.status === 'error') {
        notify('Role Error', r.error, 'error');
        return;
      }
      const wasEdit = Boolean(s.editingRoleId);
      s.closeRoleModal();
      notify(wasEdit ? 'Role Updated' : 'Role Created', `${name} saved`, 'success');
    },

    deleteRole: async (role, sqlFn) => {
      if (!role || !role.id || !sqlFn) return;
      const r = await sqlFn(`DELETE ${role.id};`);
      if (r && r.status === 'error') {
        notify('Delete Error', r.error, 'error');
        return;
      }
      if (s.editingRoleId === role.id) s.closeRoleModal();
      notify('Role Deleted', `${role.name} removed`, 'info');
    },

    // ==================== RECORD & FIELD POLICIES ====================
    startEditPolicy: (pol) => {
      s.editingPolicyId = pol.id;
      s.pTable = pol.table || 'erp_po';
      s.pScope = pol.scope || 'table';
      s.pField = pol.field || '';
      s.pMode = pol.mode || 'where';
      s.pOps = pol.ops || 'select, create, update, delete';
      s.pExpr = pol.where_expr || 'owner == $auth';
    },

    cancelEditPolicy: () => {
      s.editingPolicyId = null;
      s.pTable = 'erp_po';
      s.pScope = 'table';
      s.pField = '';
      s.pMode = 'where';
      s.pOps = 'select, create, update, delete';
      s.pExpr = 'owner == $auth';
    },

    savePolicy: async (sqlFn, actor) => {
      const table = (s.pTable || '').trim();
      if (!table || !sqlFn) {
        notify('Validation', 'Table name is required', 'warning');
        return;
      }
      const applyRes = await window.fetch('/_nexus/iam/policies/apply', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          table,
          scope: s.pScope || 'table',
          field: (s.pField || '').trim(),
          mode: s.pMode || 'where',
          ops: (s.pOps || 'select, create, update, delete').trim(),
          where_expr: (s.pExpr || '').trim(),
        }),
      });
      const applyData = await applyRes.json().catch(() => ({}));
      if (!applyRes.ok) {
        notify('Policy Rejected', applyData.details || `HTTP ${applyRes.status}`, 'error');
        return;
      }
      const ts = Date.now();
      const targetId = s.editingPolicyId || `iam_policy:pol_${ts}`;
      const q = s.editingPolicyId
        ? `UPDATE ${targetId} SET table = $table, scope = $scope, field = $field, mode = $mode, ops = $ops, where_expr = $expr, surql = $surql, updated_by = $actor;`
        : `CREATE ${targetId} SET table = $table, scope = $scope, field = $field, mode = $mode, ops = $ops, where_expr = $expr, surql = $surql, updated_by = $actor, ts = $ts;`;
      await sqlFn(q, {
        table,
        scope: s.pScope || 'table',
        field: (s.pField || '').trim(),
        mode: s.pMode || 'where',
        ops: (s.pOps || '').trim(),
        expr: (s.pExpr || '').trim(),
        surql: applyData.surql || '',
        actor: actor || 'unknown',
        ts,
      });
      const wasEdit = Boolean(s.editingPolicyId);
      s.cancelEditPolicy();
      notify(wasEdit ? 'Policy Updated' : 'Policy Applied Live', applyData.surql || table, 'success');
    },

    deletePolicy: async (pol, sqlFn) => {
      if (!pol || !pol.id || !sqlFn) return;
      await window.fetch('/_nexus/iam/policies/apply', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          table: pol.table,
          scope: pol.scope || 'table',
          field: pol.field || '',
          mode: 'remove',
        }),
      });
      await sqlFn(`DELETE ${pol.id};`);
      if (s.editingPolicyId === pol.id) s.cancelEditPolicy();
      notify('Policy Removed', `${pol.table || ''} reset to PERMISSIONS FULL`, 'info');
    },
  };
}
