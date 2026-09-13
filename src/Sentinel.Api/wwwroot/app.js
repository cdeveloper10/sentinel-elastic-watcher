/* ==========================================================================
   Sentinel console

   Vanilla, on purpose. This is an operations console for a platform that
   blocks network traffic; a build step and a dependency tree are two more
   things that can go wrong between an operator and a kill switch. Everything
   here runs from source in the browser.

   The API is the only source of truth. Nothing about actions, strategies or
   permissions is hard-coded — action forms are generated from the schema the
   backend publishes, so a new action provider needs no change to this file.
   ========================================================================== */

const state = {
  me: null,
  route: 'dashboard',
  data: {},
  drawer: null,
  busy: false,
  notice: null
};

// -- talking to the API -----------------------------------------------------

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  if (response.status === 401) {
    state.me = null;
    render();
    throw new Error('Not signed in.');
  }

  if (response.status === 204) return null;

  const text = await response.text();
  const payload = text ? safeParse(text) : null;

  if (!response.ok) {
    // ValidationProblemDetails nests the useful part; a bare message is easier to read than the envelope.
    const detail = payload?.errors
      ? Object.entries(payload.errors).map(([field, messages]) => `${field}: ${messages.join(' ')}`).join('\n')
      : payload?.error || payload?.title || `Request failed (${response.status}).`;

    throw new Error(detail);
  }

  return payload;
}

const safeParse = (text) => { try { return JSON.parse(text); } catch { return null; } };

// -- small helpers ----------------------------------------------------------

const el = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };

function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function when(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  const seconds = (Date.now() - date.getTime()) / 1000;

  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 86400 * 7) return `${Math.floor(seconds / 86400)}d ago`;

  return date.toLocaleString();
}

const exact = (iso) => iso ? new Date(iso).toLocaleString() : '—';
const pill = (kind, value) => `<span class="pill ${kind}-${esc(value)}">${esc(value)}</span>`;
const can = (permission) => state.me?.permissions?.includes(permission);

function notify(text, kind = 'ok') {
  state.notice = { text, kind };
  render();
  setTimeout(() => { if (state.notice?.text === text) { state.notice = null; render(); } }, 6000);
}

async function guard(work) {
  state.busy = true; render();
  try { await work(); }
  catch (error) { notify(error.message, 'err'); }
  finally { state.busy = false; render(); }
}

// -- routes -----------------------------------------------------------------

const ROUTES = [
  { id: 'dashboard',   label: 'Dashboard',  needs: 'rules.read' },
  { id: 'connections', label: 'Connections', needs: 'connections.read' },
  { id: 'rules',       label: 'Rules',       needs: 'rules.read' },
  { id: 'alerts',      label: 'Alerts',      needs: 'alerts.read' },
  { id: 'executions',  label: 'Actions',     needs: 'actions.read' },
  { id: 'audit',       label: 'Audit',       needs: 'audit.read' },
  { id: 'users',       label: 'Users',       needs: 'users.manage' }
];

async function go(route) {
  state.route = route;
  state.data = {};
  location.hash = route;
  await guard(() => load(route));
}

async function load(route) {
  const get = async (path, key) => { state.data[key] = await api(path); };

  if (route === 'dashboard') {
    await Promise.all([get('/api/summary', 'summary'), get('/api/rules', 'rules')]);
  } else if (route === 'connections') {
    // The action catalogue too: it is what tells this page which endpoints a service of a given type is
    // asked for, without the page knowing what any action is.
    await Promise.all([get('/api/connections', 'connections'), get('/api/action-types', 'actionTypes')]);
  } else if (route === 'rules') {
    await Promise.all([
      get('/api/rules', 'rules'),
      get('/api/connections', 'connections'),
      get('/api/action-types', 'actionTypes'),
      get('/api/detection-strategies', 'strategies'),
      get('/api/placeholders', 'placeholders'),
      get('/api/rule-templates', 'templates')
    ]);
  } else if (route === 'alerts') {
    await get('/api/alerts?take=100', 'alerts');
  } else if (route === 'executions') {
    await get('/api/action-executions?take=100', 'executions');
  } else if (route === 'audit') {
    await get('/api/audit?take=200', 'audit');
  } else if (route === 'users') {
    await Promise.all([get('/api/users', 'users'), get('/api/users/roles', 'roles')]);
  }
}

// ==========================================================================
// Rendering
// ==========================================================================

function render() {
  const root = document.getElementById('root');
  root.innerHTML = '';
  root.appendChild(state.me ? shell() : signIn());

  if (state.drawer) root.appendChild(state.drawer());
}

function signIn() {
  const view = el(`
    <div class="signin">
      <div class="card signin-card">
        <div class="brand">Sentinel</div>
        <div class="brand-sub">Detection &amp; response</div>
        <div id="signin-error"></div>
        <form id="signin-form">
          <div class="field">
            <label for="u">Username</label>
            <input id="u" name="username" autocomplete="username" autofocus required>
          </div>
          <div class="field">
            <label for="p">Password</label>
            <input id="p" name="password" type="password" autocomplete="current-password" required>
          </div>
          <button class="btn primary" style="width:100%;justify-content:center" type="submit">Sign in</button>
        </form>
      </div>
    </div>`);

  view.querySelector('#signin-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const box = view.querySelector('#signin-error');
    box.innerHTML = '';

    try {
      await api('/api/auth/sign-in', {
        method: 'POST',
        body: { username: form.get('username'), password: form.get('password') }
      });

      await start();
    } catch (error) {
      box.innerHTML = `<div class="notice err">${esc(error.message)}</div>`;
    }
  });

  return view;
}

function shell() {
  const visible = ROUTES.filter(r => can(r.needs));

  const view = el(`
    <div class="shell">
      <nav class="sidebar">
        <div class="brand">Sentinel</div>
        <div class="brand-sub">Detection &amp; response</div>
        ${visible.map(r => `
          <button class="nav-item ${state.route === r.id ? 'active' : ''}" data-route="${r.id}">
            <span>${r.label}</span>
          </button>`).join('')}
        <div class="sidebar-foot">
          <div class="who">
            <strong>${esc(state.me.displayName || state.me.username)}</strong>
            <span>${esc((state.me.roles || []).join(', ') || 'no roles')}</span>
          </div>
          <button class="btn small" id="sign-out" style="width:100%;justify-content:center">Sign out</button>
        </div>
      </nav>
      <main id="main"></main>
    </div>`);

  view.querySelectorAll('[data-route]').forEach(button =>
    button.addEventListener('click', () => go(button.dataset.route)));

  view.querySelector('#sign-out').addEventListener('click', async () => {
    await api('/api/auth/sign-out', { method: 'POST' });
    state.me = null;
    render();
  });

  const main = view.querySelector('#main');

  if (state.notice) main.appendChild(el(`<div class="notice ${state.notice.kind}">${esc(state.notice.text)}</div>`));
  if (state.busy) main.appendChild(el('<div class="notice info"><span class="spinner"></span> Working…</div>'));

  const page = ({
    dashboard: dashboardPage, connections: connectionsPage, rules: rulesPage,
    alerts: alertsPage, executions: executionsPage, audit: auditPage, users: usersPage
  })[state.route];

  if (page) main.appendChild(page());

  return view;
}

// -- dashboard --------------------------------------------------------------

function dashboardPage() {
  const s = state.data.summary;
  if (!s) return el('<div class="card"><div class="empty">Loading…</div></div>');

  const failing = (state.data.rules || []).filter(r => r.consecutiveFailures > 0);

  // Read from what the engines reported rather than from this host's settings. The API evaluates nothing,
  // so its own idea of the tick interval and the never-act list describes a process that is not doing the
  // work — and, worse, made a stopped engine look exactly like a healthy one.
  const nodes = s.engine.nodes || [];

  const view = el(`
    <div>
      <div class="page-head">
        <div>
          <h1>Dashboard</h1>
          <p>${nodes.length === 0
              ? 'No engine has reported.'
              : `${nodes.length} engine${nodes.length > 1 ? 's' : ''}: ${nodes.map(n =>
                  `<strong>${esc(n.nodeId)}</strong>${n.stale ? ' <span class="pill st-FAILED">silent</span>' : ''}`).join(', ')},
                 ticking every ${nodes[0].tickSeconds}s.`}</p>
        </div>
      </div>

      ${nodes.length === 0
        ? `<div class="notice err">No engine has ever reported to this database. Rules can be written and
             rehearsed, but nothing is being evaluated and no alert will be raised. Start
             <span class="mono">Sentinel.Engine</span> against this same database.</div>`
        : ''}

      ${nodes.length > 0 && !s.engine.reporting
        ? `<div class="notice err">Every engine has stopped reporting — the most recent was
             ${when(nodes.map(n => n.lastSeenAt).sort().reverse()[0])}. Nothing is being evaluated right
             now. This is what a crashed or unscheduled engine looks like; check its logs and its database
             connection.</div>`
        : ''}

      ${nodes.some(n => !n.enabled) ? '<div class="notice warn">An engine is paused. Its rules are not being evaluated.</div>' : ''}
      ${!s.safety.actionsEnabled && nodes.length > 0 ? '<div class="notice warn">Disruptive actions are switched off platform-wide. Rules still detect and alert.</div>' : ''}
      ${s.safety.nodesDisagree
        ? `<div class="notice warn">The engines are not configured alike — they disagree about the kill
             switch or the never-act list. Whichever one evaluates a rule decides what happens to it, so
             the platform's behaviour depends on which pod picks up the work.</div>`
        : ''}
      ${nodes.length > 0 && s.safety.neverBlock === 0 ? '<div class="notice warn">The never-block list is empty. Set <span class="mono">Safety:NeverBlockAddresses</span> to your own egress ranges before arming a blocking rule — a brute-force rule behind NAT identifies the address every employee shares.</div>' : ''}

      <div class="tiles">
        <div class="tile"><div class="n">${s.rules.enabled}<span class="muted" style="font-size:15px">/${s.rules.total}</span></div><div class="k">Rules armed</div></div>
        <div class="tile ${s.rules.failing ? 'warn' : ''}"><div class="n">${s.rules.failing}</div><div class="k">Rules failing</div></div>
        <div class="tile ${s.alerts.open ? 'warn' : 'ok'}"><div class="n">${s.alerts.open}</div><div class="k">Open alerts</div></div>
        <div class="tile"><div class="n">${s.alerts.lastDay}</div><div class="k">Alerts, 24h</div></div>
        <div class="tile ok"><div class="n">${s.actions.succeeded}</div><div class="k">Actions done, 24h</div></div>
        <div class="tile ${s.actions.failed ? 'warn' : ''}"><div class="n">${s.actions.failed}</div><div class="k">Actions failed, 24h</div></div>
        <div class="tile"><div class="n">${s.actions.skipped}</div><div class="k">Actions held back</div></div>
        <div class="tile"><div class="n">${s.connections}</div><div class="k">Connections</div></div>
      </div>

      ${failing.length ? `
        <div class="card" style="margin-top:14px">
          <h3>Rules that are not working</h3>
          <div class="scroller"><table>
            <thead><tr><th>Rule</th><th>Failures</th><th>Last error</th></tr></thead>
            <tbody>${failing.map(r => `
              <tr><td>${esc(r.name)}</td><td>${r.consecutiveFailures}</td>
              <td class="muted">${esc(r.lastError || '')}</td></tr>`).join('')}
            </tbody>
          </table></div>
        </div>` : ''}
    </div>`);

  return view;
}

// -- connections ------------------------------------------------------------

/// The endpoints a service answers on, shown beside its address so the full URL is readable without
/// opening the form — it is the thing most often got wrong and least often looked at.
function pathSummary(connection) {
  const paths = readPaths(connection.configurationJson);
  const entries = Object.entries(paths);

  if (entries.length === 0) return '';

  return `<div class="muted" style="font-size:12px">${
    entries.map(([action, path]) => `${esc(action)} → ${esc(path)}`).join('<br>')}</div>`;
}

function readPaths(configurationJson) {
  try {
    const parsed = JSON.parse(configurationJson || '{}');
    return parsed && typeof parsed.paths === 'object' && parsed.paths ? parsed.paths : {};
  } catch {
    return {};
  }
}

function readTls(configurationJson) {
  try {
    const parsed = JSON.parse(configurationJson || '{}');
    return parsed && typeof parsed.tls === 'object' && parsed.tls ? parsed.tls : {};
  } catch {
    return {};
  }
}

/// How a connection verifies, shown beside it — so "not verified" is something an operator reads rather
/// than something they have to infer from a setting they cannot see.
function tlsSummary(connection) {
  if (!/^https:/i.test(connection.endpoint || '')) return '';

  const tls = readTls(connection.configurationJson);

  if (tls.allowInvalidCertificates)
    return '<div class="pill st-FAILED" style="margin-top:4px">certificate not verified</div>';

  if (tls.fingerprint) return '<div class="muted" style="font-size:12px">certificate pinned</div>';
  if (tls.caCertificate) return '<div class="muted" style="font-size:12px">private CA</div>';

  return '';
}

function connectionsPage() {
  const rows = state.data.connections || [];

  // Split by what a connection is for, not merely by its type. Reading events and carrying out responses
  // are opposite directions of the same platform — one is where detection looks, the other is what it does
  // about what it finds, and only the second can block traffic or wake somebody at night. Listed together,
  // an SMS gateway read as just another index to search.
  const sources = rows.filter(c => c.type === 'elasticsearch');
  const services = rows.filter(c => c.type !== 'elasticsearch');

  const table = (list, empty) => `
    <div class="scroller"><table>
      <thead><tr><th>Name</th><th>Type</th><th>Endpoint</th><th>Auth</th><th>Verified</th><th></th></tr></thead>
      <tbody>
        ${list.length === 0 ? `<tr><td colspan="6" class="empty">${empty}</td></tr>` : ''}
        ${list.map(c => `
          <tr>
            <td><strong>${esc(c.name)}</strong>${c.enabled ? '' : ' <span class="pill off">disabled</span>'}
                <div class="muted" style="font-size:12.5px">${esc(c.description || '')}</div></td>
            <td class="nowrap">${esc(c.type)}</td>
            <td class="mono">${esc(c.endpoint)}${tlsSummary(c)}${pathSummary(c)}</td>
            <td class="nowrap">${esc(c.authenticationMode)}</td>
            <td class="nowrap">${c.lastProbedAt
                ? (c.lastProbeSucceeded
                    ? `<span class="pill on">ok</span> <span class="muted">${when(c.lastProbedAt)}</span>`
                    : `<span class="pill st-FAILED">failed</span> <span class="muted">${esc(c.lastProbeMessage || '')}</span>`)
                : '<span class="muted">never</span>'}</td>
            <td class="nowrap">
              <div class="row">
                ${c.type === 'elasticsearch' ? `<button class="btn small" data-probe="${c.id}">Test</button>` : ''}
                ${can('connections.manage') ? `<button class="btn small" data-edit="${c.id}">Edit</button>` : ''}
                ${can('connections.manage') ? `<button class="btn small danger" data-del="${c.id}">Delete</button>` : ''}
              </div>
            </td>
          </tr>`).join('')}
      </tbody>
    </table></div>`;

  const view = el(`
    <div>
      <div class="page-head">
        <div>
          <h1>Connections</h1>
          <p>Where events are read from and where responses are sent. A rule names a connection; it never
             holds an endpoint or a credential itself.</p>
        </div>
        ${can('connections.manage') ? '<button class="btn primary" id="add">New connection</button>' : ''}
      </div>

      <div class="card">
        <h3>Event sources</h3>
        <p class="muted" style="font-size:13px;margin:-4px 0 10px">
          What rules read from. A rule names one of these as its source.</p>
        ${table(sources, 'No event source yet. Add one pointing at your Elasticsearch to begin.')}
      </div>

      <div class="card">
        <h3>Response services</h3>
        <p class="muted" style="font-size:13px;margin:-4px 0 10px">
          Where an action sends what it has to send. The endpoint each action calls is set here, on the
          service — a rule only says which service to use.</p>
        ${table(services, 'No response service yet. Rules can still raise alerts; they just will not send anything.')}
      </div>
    </div>`);

  view.querySelector('#add')?.addEventListener('click', () => openConnection(null));

  view.querySelectorAll('[data-probe]').forEach(b => b.addEventListener('click', () => guard(async () => {
    const probe = await api(`/api/connections/${b.dataset.probe}/probe`, { method: 'POST' });
    notify(probe.reachable
      ? `Connected${probe.version ? ` — Elasticsearch ${probe.version}` : ''}${probe.clusterName ? `, cluster “${probe.clusterName}”` : ''}.`
      : probe.message, probe.reachable ? 'ok' : 'err');
    await load('connections');
  })));

  view.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () =>
    openConnection(rows.find(c => c.id === +b.dataset.edit))));

  view.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', () => {
    const target = rows.find(c => c.id === +b.dataset.del);
    if (!confirm(`Delete connection “${target.name}”?`)) return;

    guard(async () => {
      await api(`/api/connections/${target.id}`, { method: 'DELETE' });
      notify('Connection deleted.');
      await load('connections');
    });
  }));

  return view;
}

function openConnection(existing) {
  state.drawer = () => {
    const isNew = !existing;

    const view = el(`
      <div class="drawer-back">
        <div class="drawer">
          <div class="drawer-head">
            <div><h1>${isNew ? 'New connection' : `Edit ${esc(existing.name)}`}</h1>
              <p class="muted">Credentials are encrypted before they are stored and never returned.</p></div>
            <button class="btn" id="close">Close</button>
          </div>
          <div class="card">
            <form id="form">
              <div class="grid2">
                <div class="field"><label>Name</label>
                  <input name="name" value="${esc(existing?.name || '')}" ${isNew ? '' : ''} required>
                  <div class="hint">Lowercase, digits and hyphens. Rules refer to this.</div></div>
                <div class="field"><label>Display name</label>
                  <input name="displayName" value="${esc(existing?.displayName || '')}"></div>
              </div>

              <div class="grid2">
                <div class="field"><label>Type</label>
                  <select name="type">
                    ${['elasticsearch', 'security_api', 'sms'].map(t =>
                      `<option value="${t}" ${existing?.type === t ? 'selected' : ''}>${t}</option>`).join('')}
                  </select></div>
                <div class="field"><label>Timeout (seconds)</label>
                  <input name="timeoutSeconds" type="number" min="1" max="300" value="${existing?.timeoutSeconds || 30}"></div>
              </div>

              <div class="field"><label>Endpoint</label>
                <input name="endpoint" value="${esc(existing?.endpoint || '')}" placeholder="https://es.internal:9200" required>
                <div class="hint">Absolute http(s). Credentials belong below, never in the URL.</div></div>

              <div class="field"><label>Authentication</label>
                <select name="authenticationMode" id="auth">
                  ${['none', 'api_key', 'basic', 'bearer'].map(m =>
                    `<option value="${m}" ${existing?.authenticationMode === m ? 'selected' : ''}>${m}</option>`).join('')}
                </select></div>

              <fieldset id="secrets"><legend>Credentials</legend></fieldset>

              <fieldset id="paths"><legend>Endpoints</legend></fieldset>

              <fieldset id="tls"><legend>Certificate</legend>
                <p class="muted" style="font-size:13px;margin:0 0 10px">
                  Only for an <span class="mono">https</span> endpoint whose certificate the machine does
                  not already trust — which is the normal case for Elasticsearch, because version 8 and the
                  Kubernetes operator both generate their own CA.</p>

                <div class="field"><label>Certificate fingerprint (SHA-256)</label>
                  <input class="mono" name="tls.fingerprint"
                         placeholder="5F:5A:… — printed by Elasticsearch on first start">
                  <div class="hint">Pins this exact certificate. Neither its name nor its issuer is
                    consulted, which is why it works when the address is not on the certificate — the usual
                    situation when a cluster service is reached through a node address or a port-forward.</div></div>

                <div class="field"><label>CA certificate (PEM)</label>
                  <textarea class="mono" name="tls.caCertificate" rows="5" spellcheck="false"
                            placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"></textarea>
                  <div class="hint">Verifies the chain against this root instead of the machine's store.
                    Everything else still applies, including the name — so the address must be one the
                    certificate covers.</div></div>

                <div class="field"><label><input type="checkbox" name="tls.allowInvalidCertificates"
                  style="width:auto;margin-right:6px"> Accept any certificate</label>
                  <div class="hint">Verifies nothing. Anything able to answer on that address is trusted
                    with this connection's credentials — use it to get moving, not to stay there.</div></div>
              </fieldset>

              <div class="field"><label><input type="checkbox" name="enabled" style="width:auto;margin-right:6px"
                ${existing?.enabled !== false ? 'checked' : ''}> Enabled</label></div>

              <div class="row">
                <button class="btn primary" type="submit">${isNew ? 'Create' : 'Save'}</button>
                <button class="btn" type="button" id="cancel">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      </div>`);

    const secretsFor = (mode) => ({
      api_key: [['apiKey', 'API key']],
      bearer: [['token', 'Token']],
      basic: [['username', 'Username'], ['password', 'Password']],
      none: []
    })[mode] || [];

    const drawSecrets = () => {
      const mode = view.querySelector('#auth').value;
      const fields = secretsFor(mode);
      const box = view.querySelector('#secrets');

      box.innerHTML = '<legend>Credentials</legend>' + (fields.length === 0
        ? '<div class="muted" style="font-size:13.5px">This mode needs no credential.</div>'
        : fields.map(([key, label]) => `
            <div class="field"><label>${label}</label>
              <input name="secret.${key}" type="password" autocomplete="new-password"
                     placeholder="${existing ? 'leave blank to keep the stored value' : ''}">
            </div>`).join(''));
    };

    // One path field per action that could run through a connection of this type, offered from the
    // catalogue the backend publishes — this form knows nothing about what any action is, and a new
    // provider appears here without the console changing. Elasticsearch is a source rather than a service,
    // so nothing calls an endpoint on it and the section stays out of its way.
    const drawPaths = () => {
      const type = view.querySelector('[name=type]').value;
      const stored = readPaths(existing?.configurationJson);
      const box = view.querySelector('#paths');

      const users = (state.data.actionTypes || []).filter(a => a.requiredConnectionType === type);

      if (users.length === 0) {
        box.innerHTML = '<legend>Endpoints</legend>' +
          '<div class="muted" style="font-size:13.5px">Nothing sends to this kind of connection — rules ' +
          'read from it instead, and the index patterns are set on the rule.</div>';
        return;
      }

      box.innerHTML = '<legend>Endpoints</legend>' +
        '<p class="muted" style="font-size:13px;margin:0 0 10px">Where each action calls on this service. ' +
        'Set here rather than on the rule, because it describes the service: every rule using it calls the ' +
        'same endpoint. Leave one blank for the conventional path.</p>' +
        users.map(a => `
          <div class="field"><label>${esc(a.displayName)}</label>
            <input class="mono" name="path.${esc(a.type)}" value="${esc(stored[a.type] || '')}"
                   placeholder="${esc(a.defaultPath || '')}">
            <div class="hint">Appended to the address above. A path such as
              ${esc(a.defaultPath || '/send')}, never a full URL.</div></div>`).join('');
    };

    // Fill the certificate fields from what is stored. They are ordinary configuration rather than
    // secrets — a CA certificate is public and a fingerprint is a hash — so unlike credentials they come
    // back and can be edited in place.
    const stored = readTls(existing?.configurationJson);

    view.querySelector('[name="tls.fingerprint"]').value = stored.fingerprint || '';
    view.querySelector('[name="tls.caCertificate"]').value = stored.caCertificate || '';
    view.querySelector('[name="tls.allowInvalidCertificates"]').checked = !!stored.allowInvalidCertificates;

    view.querySelector('#auth').addEventListener('change', drawSecrets);
    view.querySelector('[name=type]').addEventListener('change', drawPaths);
    drawSecrets();
    drawPaths();

    const close = () => { state.drawer = null; render(); };
    view.querySelector('#close').addEventListener('click', close);
    view.querySelector('#cancel').addEventListener('click', close);
    view.addEventListener('click', e => { if (e.target === view) close(); });

    view.querySelector('#form').addEventListener('submit', (event) => {
      event.preventDefault();
      const form = new FormData(event.target);

      const secrets = {};
      const paths = {};

      for (const [key, value] of form.entries()) {
        if (key.startsWith('secret.') && value) secrets[key.slice(7)] = value;

        // Kept even when blank, so clearing a path removes it rather than silently leaving the old one.
        if (key.startsWith('path.')) paths[key.slice(5)] = (value || '').trim();
      }

      // Merged into whatever else the connection's configuration holds, so a setting stored beside the
      // paths survives somebody editing one.
      const configuration = (() => {
        let root;
        try { root = JSON.parse(existing?.configurationJson || '{}') || {}; } catch { root = {}; }

        const kept = Object.fromEntries(Object.entries(paths).filter(([, path]) => path));

        if (Object.keys(kept).length) root.paths = kept;
        else delete root.paths;

        // Certificate settings, written only when something is set — an empty tls block would be noise in
        // every connection's configuration.
        const tls = {};

        const fingerprint = (form.get('tls.fingerprint') || '').trim();
        const ca = (form.get('tls.caCertificate') || '').trim();

        if (fingerprint) tls.fingerprint = fingerprint;
        if (ca) tls.caCertificate = ca;
        if (form.get('tls.allowInvalidCertificates') === 'on') tls.allowInvalidCertificates = true;

        if (Object.keys(tls).length) root.tls = tls;
        else delete root.tls;

        return JSON.stringify(root);
      })();

      const body = {
        name: form.get('name').trim(),
        displayName: form.get('displayName') || '',
        description: '',
        type: form.get('type'),
        endpoint: form.get('endpoint').trim(),
        authenticationMode: form.get('authenticationMode'),
        timeoutSeconds: +form.get('timeoutSeconds'),
        enabled: form.get('enabled') === 'on',
        // Omitted rather than sent empty, so editing a timeout does not wipe a stored key.
        secrets: Object.keys(secrets).length ? secrets : null,
        configurationJson: configuration
      };

      guard(async () => {
        if (existing) await api(`/api/connections/${existing.id}`, { method: 'PUT', body });
        else await api('/api/connections', { method: 'POST', body });

        close();
        notify(existing ? 'Connection saved.' : 'Connection created. Test it before pointing a rule at it.');
        await load('connections');
      });
    });

    return view;
  };

  render();
}
