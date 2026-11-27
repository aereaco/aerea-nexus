/**
 * Shared Nexus-IDP State & Actions Module for Multi-Page IAM App (`platform/iam/*.html`)
 * Loaded declaratively via `data-signal-src="/_pages/apps/iam/idp-state.js"`.
 * Pure ZCZS reactive proxy mutations; all authorization enforced server-side.
 */
export default function createIdpState(s) {
  const notify = (title, msg, type = 'info') => {
    const g = window.UX?.signals || {};
    if (typeof g.notify === 'function') g.notify(title, msg, type);
  };

  const api = async (url, opts = {}) => {
    const res = await window.fetch(url, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...(opts.headers || {}) },
      ...opts,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || data.details || `HTTP ${res.status}`);
    return data;
  };

  return {
    idpReady: true,
    idpLoaded: false,
    orgSearch: '',
    orgs: [],
    selectedOrgId: localStorage.getItem('nexus_selected_org') || 'default',
    orgDetail: null,
    composedPolicy: null,
    orgMembers: [],
    orgChildren: [],
    clients: [],
    lastClientSecret: null,
    fedProviders: [],
    flows: [],
    auditEvents: [],
    identities: [],

    // Create Org form
    newOrgSlug: '',
    newOrgName: '',
    newOrgParentId: '',
    newOrgDomain: '',
    newOrgMfa: false,

    // Grant Member form
    grantSubjectId: '',
    grantRole: 'ORG_ADMIN',
    grantScopeKind: 'self_only',

    // Create OIDC Client form
    newClientName: '',
    newClientType: 'confidential',
    newClientRedirect: 'https://app.example/callback',

    // Policy patch form
    polMfa: false,
    polMinPw: 12,
    polMaxTtl: 86400,
    polBranding: '',

    // New AuthFlow form
    newFlowId: '',
    newFlowName: '',

    provenanceBadge(prov) {
      switch (prov) {
        case 'inherited_enforced': return { text: 'Inherited & Enforced', cls: 'badge-warning' };
        case 'prohibited_by_parent': return { text: 'Prohibited by Parent', cls: 'badge-error' };
        case 'locally_overridden': return { text: 'Locally Overridden', cls: 'badge-info' };
        default: return { text: 'Inherited Default', cls: 'badge-ghost' };
      }
    },

    filteredOrgs() {
      const q = (s.orgSearch || '').trim().toLowerCase();
      const list = Array.isArray(s.orgs) ? s.orgs : [];
      if (!q) return list;
      return list.filter(
        (o) =>
          String(o.name || '').toLowerCase().includes(q) ||
          String(o.slug || '').toLowerCase().includes(q) ||
          String(o.org_id || '').toLowerCase().includes(q)
      );
    },

    async loadOrgs() {
      try {
        const data = await api('/_nexus/iam/orgs');
        s.orgs = Array.isArray(data.orgs) ? data.orgs : [];
        s.idpLoaded = true;
      } catch (e) {
        notify('Organizations', e.message, 'error');
      }
    },

    async createOrg() {
      if (!s.newOrgSlug.trim() || !s.newOrgName.trim()) {
        notify('Validation', 'Enter slug and organization name', 'warning');
        return;
      }
      try {
        const body = {
          slug: s.newOrgSlug.trim(),
          name: s.newOrgName.trim(),
          parent_org_id: s.newOrgParentId ? s.newOrgParentId.trim() : null,
          primary_domain: s.newOrgDomain ? s.newOrgDomain.trim() : null,
          local_policy: s.newOrgMfa ? { mfa_required: true } : {},
        };
        const created = await api('/_nexus/iam/orgs', { method: 'POST', body: JSON.stringify(body) });
        s.newOrgSlug = '';
        s.newOrgName = '';
        s.newOrgDomain = '';
        s.newOrgMfa = false;
        notify('Organization Created', `${created.name} (${created.org_id})`, 'success');
        await s.loadOrgs();
      } catch (e) {
        notify('Create Org Failed', e.message, 'error');
      }
    },

    selectOrg(orgId, router) {
      s.selectedOrgId = orgId;
      localStorage.setItem('nexus_selected_org', orgId);
      if (router && typeof router.go === 'function') {
        router.go('/iam/organization');
      }
    },

    async loadOrgDetail(orgId) {
      const target = orgId || s.selectedOrgId || 'default';
      s.selectedOrgId = target;
      localStorage.setItem('nexus_selected_org', target);
      try {
        await s.loadOrgs();
        const data = await api(`/_nexus/iam/orgs/${encodeURIComponent(target)}`);
        s.orgDetail = data.organization || null;
        s.composedPolicy = data.composed_policy || null;
        s.orgChildren = Array.isArray(data.children) ? data.children : [];
        s.orgMembers = Array.isArray(data.members) ? data.members : [];
        if (s.composedPolicy) {
          s.polMfa = !!s.composedPolicy.mfa_required?.value;
          s.polMinPw = Number(s.composedPolicy.min_password_length?.value || 12);
          s.polMaxTtl = Number(s.composedPolicy.max_session_ttl_secs?.value || 86400);
          s.polBranding = s.composedPolicy.branding_name?.value || '';
        }
      } catch (e) {
        notify('Organization Profile', e.message, 'error');
      }
    },

    async saveOrgPolicy() {
      try {
        const patch = {
          mfa_required: !!s.polMfa,
          min_password_length: Number(s.polMinPw) || 12,
          max_session_ttl_secs: Number(s.polMaxTtl) || 86400,
          branding_name: s.polBranding ? s.polBranding.trim() : null,
        };
        s.composedPolicy = await api(`/_nexus/iam/orgs/${encodeURIComponent(s.selectedOrgId)}/policy`, {
          method: 'PUT',
          body: JSON.stringify(patch),
        });
        notify('Policy Updated', 'Composed organization security policy saved', 'success');
      } catch (e) {
        notify('Policy Update Failed', e.message, 'error');
      }
    },

    async grantOrgMember() {
      if (!s.grantSubjectId.trim()) {
        notify('Validation', 'Enter identity ID or subject', 'warning');
        return;
      }
      try {
        const scope = s.grantScopeKind === 'descendants' ? { kind: 'descendants' } : { kind: 'self_only' };
        await api(`/_nexus/iam/orgs/${encodeURIComponent(s.selectedOrgId)}/members`, {
          method: 'POST',
          body: JSON.stringify({
            subject_id: s.grantSubjectId.trim(),
            role_assignments: [s.grantRole],
            scope,
          }),
        });
        s.grantSubjectId = '';
        notify('Membership Granted', 'Delegated organization membership saved', 'success');
        await s.loadOrgDetail(s.selectedOrgId);
      } catch (e) {
        notify('Grant Failed', e.message, 'error');
      }
    },

    async revokeOrgMember(subjectId) {
      try {
        await api(
          `/_nexus/iam/orgs/${encodeURIComponent(s.selectedOrgId)}/members?subject_id=${encodeURIComponent(subjectId)}`,
          { method: 'DELETE' }
        );
        notify('Membership Revoked', `Org access revoked for ${subjectId} (personal identity preserved)`, 'info');
        await s.loadOrgDetail(s.selectedOrgId);
      } catch (e) {
        notify('Revoke Failed', e.message, 'error');
      }
    },

    async loadApplications() {
      try {
        await s.loadOrgs();
        const [cData, fData] = await Promise.all([
          api(`/_nexus/iam/clients?org_id=${encodeURIComponent(s.selectedOrgId)}`),
          api(`/_nexus/iam/federation/providers?org_id=${encodeURIComponent(s.selectedOrgId)}`),
        ]);
        s.clients = Array.isArray(cData.clients) ? cData.clients : [];
        s.fedProviders = Array.isArray(fData.providers) ? fData.providers : [];
      } catch (e) {
        notify('Applications & SSO', e.message, 'error');
      }
    },

    async createOidcClient() {
      if (!s.newClientName.trim()) {
        notify('Validation', 'Enter application name', 'warning');
        return;
      }
      try {
        const data = await api('/_nexus/iam/clients', {
          method: 'POST',
          body: JSON.stringify({
            org_id: s.selectedOrgId,
            name: s.newClientName.trim(),
            client_type: s.newClientType,
            redirect_uris: s.newClientRedirect ? [s.newClientRedirect.trim()] : [],
            grant_types:
              s.newClientType === 'confidential'
                ? ['authorization_code', 'refresh_token', 'client_credentials']
                : ['authorization_code', 'refresh_token'],
            scopes: ['openid', 'profile', 'email'],
          }),
        });
        s.newClientName = '';
        s.lastClientSecret = data.client_secret || null;
        notify('OIDC Client Created', data.client?.client_id || 'Client registered', 'success');
        await s.loadApplications();
      } catch (e) {
        notify('Create Client Failed', e.message, 'error');
      }
    },

    async loadFlows() {
      try {
        const data = await api('/_nexus/iam/flows');
        s.flows = Array.isArray(data.flows) ? data.flows : [];
      } catch (e) {
        notify('Auth Flows', e.message, 'error');
      }
    },

    async createStandardFlow() {
      if (!s.newFlowId.trim() || !s.newFlowName.trim()) {
        notify('Validation', 'Enter flow ID and name', 'warning');
        return;
      }
      try {
        await api('/_nexus/iam/flows', {
          method: 'POST',
          body: JSON.stringify({
            flow_id: s.newFlowId.trim(),
            name: s.newFlowName.trim(),
            org_id: s.selectedOrgId,
            stages: [
              { stage_id: 'identify', kind: { type: 'identification' }, max_retries: 3 },
              { stage_id: 'password', kind: { type: 'password_verify' }, max_retries: 3 },
              {
                stage_id: 'mfa_branch',
                kind: {
                  type: 'conditional_branch',
                  condition: { kind: 'org_mfa_required' },
                  if_true_stage: 'totp',
                  if_false_stage: 'consent',
                },
                max_retries: 1,
              },
              { stage_id: 'totp', kind: { type: 'totp_verify', org_required: true }, max_retries: 3 },
              { stage_id: 'consent', kind: { type: 'consent', scopes: ['openid', 'profile'] }, max_retries: 1 },
            ],
          }),
        });
        s.newFlowId = '';
        s.newFlowName = '';
        notify('Auth Flow Created', 'Versioned authentication pipeline saved', 'success');
        await s.loadFlows();
      } catch (e) {
        notify('Create Flow Failed', e.message, 'error');
      }
    },

    async loadAudit() {
      try {
        const q = s.selectedOrgId && s.selectedOrgId !== 'all' ? `?org_id=${encodeURIComponent(s.selectedOrgId)}` : '';
        const data = await api(`/_nexus/iam/audit${q}`);
        s.auditEvents = Array.isArray(data.events) ? data.events : [];
      } catch (e) {
        notify('Audit Log', e.message, 'error');
      }
    },
  };
}
