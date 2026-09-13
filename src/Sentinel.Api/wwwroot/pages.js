/* ==========================================================================
   Alerts, action executions, the audit trail and users.

   The alert view is the one that matters most: an operator opening an alert
   is asking "why did this fire, and what did the platform then do to my
   estate?" — so it shows the rule version that produced it, the evidence,
   and every action with its retries, rather than a status word.
   ========================================================================== */

function alertsPage() {
  const payload = state.data.alerts || { items: [], total: 0 };
  const rows = payload.items || [];

  const view = el(`
    <div>
      <div class="page-head">
        <div><h1>Alerts</h1>
          <p>${payload.total} in total. Open one to see why it fired and what was done about it.</p></div>
        <div class="row">
          ${['', 'DETECTED', 'ACKNOWLEDGED', 'RESOLVED'].map(s =>
            `<button class="btn small" data-filter="${s}">${s || 'All'}</button>`).join('')}
        </div>
      </div>

      <div class="card">
        <div class="scroller"><table>
          <thead><tr><th>When</th><th>Rule</th><th>Severity</th><th>Subject</th><th>Events</th><th>Status</th></tr></thead>
          <tbody>
            ${rows.length === 0 ? '<tr><td colspan="6" class="empty">No alerts. Either nothing has triggered, or no rule is armed yet.</td></tr>' : ''}
            ${rows.map(a => `
              <tr class="clickable" data-open="${a.id}">
                <td class="nowrap muted">${when(a.detectedAt)}</td>
                <td>${esc(a.ruleName)} <span class="muted">v${a.ruleVersion}</span></td>
                <td>${pill('sev', a.severity)}</td>
                <td class="mono">${esc(a.subject)}</td>
                <td class="nowrap">${a.eventCount}</td>
                <td>${pill('st', a.status)}</td>
              </tr>`).join('')}
          </tbody>
        </table></div>
      </div>
    </div>`);

  view.querySelectorAll('[data-filter]').forEach(b => b.addEventListener('click', () => guard(async () => {
    const status = b.dataset.filter;
    state.data.alerts = await api(`/api/alerts?take=100${status ? `&status=${status}` : ''}`);
  })));

  view.querySelectorAll('[data-open]').forEach(row => row.addEventListener('click', () => guard(async () => {
    openAlert(await api(`/api/alerts/${row.dataset.open}`));
  })));

  return view;
}

function openAlert(detail) {
  const alert = detail.alert;
  const version = detail.ruleVersion;
  const executions = detail.executions || [];

  const readJson = (value) => { try { return JSON.parse(value || '{}'); } catch { return {}; } };
  const evidence = readJson(alert.evidenceJson);
  const subject = readJson(alert.subjectJson);

  state.drawer = () => {
    const view = el(`
      <div class="drawer-back">
        <div class="drawer">
          <div class="drawer-head">
            <div><h1>${esc(alert.ruleName)}</h1>
              <p class="muted">${pill('sev', alert.severity)} ${pill('st', alert.status)}
                 <span class="mono" style="margin-left:8px">${esc(alert.alertId)}</span></p></div>
            <button class="btn" id="close">Close</button>
          </div>

          <div class="card">
            <h3>Why it fired</h3>
            <dl class="kv">
              <dt>Subject</dt><dd class="mono">${esc(alert.subject)}</dd>
              <dt>Events</dt><dd>${alert.eventCount} in the window</dd>
              <dt>Window</dt><dd class="mono">${exact(alert.windowFrom)} &rarr; ${exact(alert.windowTo)}</dd>
              <dt>Detected</dt><dd>${exact(alert.detectedAt)}</dd>
              ${alert.sourceIp ? `<dt>Source IP</dt><dd class="mono">${esc(alert.sourceIp)}</dd>` : ''}
              ${alert.userId ? `<dt>User</dt><dd class="mono">${esc(alert.userId)}</dd>` : ''}
            </dl>
            ${Object.keys(evidence).length ? `<h3 style="margin-top:14px">Evidence</h3>
              <pre>${esc(JSON.stringify(evidence, null, 2))}</pre>` : ''}
          </div>

          ${alert.sampleJson ? `
            <div class="card">
              <h3>One of the events</h3>
              <p class="muted" style="font-size:13px;margin:0 0 10px">
                ${alert.eventCount > 1
                  ? `The most recent of the ${alert.eventCount} events behind this alert. Its fields
                     describe that line, not all of them.`
                  : 'The event that matched.'}
                A message or a payload reaches these as <span class="mono">{{sample.&lt;field&gt;}}</span>.</p>
              <dl class="kv">${Object.entries(readJson(alert.sampleJson))
                .map(([field, value]) =>
                  `<dt class="mono">${esc(field)}</dt><dd class="mono">${esc(String(value))}</dd>`)
                .join('')}</dl>
            </div>` : ''}

          ${version ? `
            <div class="card">
              <h3>The rule as it was, version ${version.version}</h3>
              <p class="muted" style="font-size:13px;margin:0 0 10px">
                Not the rule as it is now — it may have been edited because of this alert.</p>
              <dl class="kv">
                <dt>Indices</dt><dd class="mono">${esc(version.indexPatternsJson)}</dd>
                <dt>Query</dt><dd class="mono">${esc(version.queryJson || 'everything in the window')}</dd>
                <dt>Group by</dt><dd class="mono">${esc(version.groupByJson)}</dd>
                <dt>Threshold</dt><dd>more than ${version.threshold} in ${version.windowSeconds}s</dd>
                <dt>Cooldown</dt><dd>${version.cooldownSeconds}s</dd>
              </dl>
            </div>` : ''}

          <div class="card">
            <h3>What the platform did</h3>
            ${executions.length === 0
              ? '<div class="empty">No actions. This rule alerts and nothing more.</div>'
              : `<div class="scroller"><table>
                  <thead><tr><th>Action</th><th>Target</th><th>Status</th><th>Tries</th><th>Took</th><th>Detail</th></tr></thead>
                  <tbody>${executions.map(e => `
                    <tr>
                      <td class="nowrap">${esc(e.actionType)}<div class="muted" style="font-size:12px">${esc(e.connectionName)}</div></td>
                      <td class="mono">${esc(e.target || '')}</td>
                      <td>${pill('st', e.status)}</td>
                      <td>${e.retryCount ?? 0}</td>
                      <td class="nowrap muted">${e.durationMs != null ? e.durationMs + 'ms' : ''}</td>
                      <td class="muted" style="font-size:12.5px">${esc(e.errorMessage || e.errorCode || '')}</td>
                    </tr>`).join('')}</tbody>
                </table></div>`}
          </div>

          <div class="row">
            ${can('alerts.acknowledge') && alert.status === 'DETECTED'
              ? '<button class="btn" id="ack">Acknowledge</button>' : ''}
            ${can('alerts.resolve') && alert.status !== 'RESOLVED'
              ? '<button class="btn primary" id="resolve">Resolve</button>' : ''}
          </div>
        </div>
      </div>`);

    const close = () => { state.drawer = null; render(); };
    view.querySelector('#close').addEventListener('click', close);
    view.addEventListener('click', e => { if (e.target === view) close(); });

    view.querySelector('#ack')?.addEventListener('click', () => guard(async () => {
      await api(`/api/alerts/${alert.id}/acknowledge`, { method: 'POST' });
      close(); notify('Acknowledged.'); await load('alerts');
    }));

    view.querySelector('#resolve')?.addEventListener('click', () => guard(async () => {
      const note = prompt('What was done about it? (optional)') || null;
      await api(`/api/alerts/${alert.id}/resolve`, { method: 'POST', body: { note } });
      close(); notify('Resolved.'); await load('alerts');
    }));

    return view;
  };

  render();
}

// -- action executions ------------------------------------------------------

function executionsPage() {
  const rows = state.data.executions || [];

  return el(`
    <div>
      <div class="page-head">
        <div><h1>Actions</h1>
          <p>Every response the platform attempted, including the ones it deliberately held back.
             A skipped action means a rule fired and a safety rail stopped it — worth reading.</p></div>
      </div>

      <div class="card">
        <div class="scroller"><table>
          <thead><tr><th>When</th><th>Action</th><th>Target</th><th>Status</th><th>Tries</th><th>Detail</th></tr></thead>
          <tbody>
            ${rows.length === 0 ? '<tr><td colspan="6" class="empty">Nothing yet.</td></tr>' : ''}
            ${rows.map(e => `
              <tr>
                <td class="nowrap muted">${when(e.createdAt)}</td>
                <td class="nowrap">${esc(e.actionType)}<div class="muted" style="font-size:12px">${esc(e.connectionName)}</div></td>
                <td class="mono">${esc(e.target || '')}</td>
                <td>${pill('st', e.status)}</td>
                <td>${e.retryCount ?? 0}</td>
                <td class="muted" style="font-size:12.5px">${esc(e.errorMessage || e.errorCode || '')}</td>
              </tr>`).join('')}
          </tbody>
        </table></div>
      </div>
    </div>`);
}

// -- audit ------------------------------------------------------------------

function auditPage() {
  const rows = state.data.audit || [];

  return el(`
    <div>
      <div class="page-head">
        <div><h1>Audit</h1>
          <p>What people did to the platform, as opposed to what the platform did to the estate.
             Refused attempts are recorded too — a run of those is the signal that matters.</p></div>
      </div>

      <div class="card">
        <div class="scroller"><table>
          <thead><tr><th>When</th><th>Who</th><th>Did</th><th>To</th><th>Result</th><th>Detail</th></tr></thead>
          <tbody>
            ${rows.length === 0 ? '<tr><td colspan="6" class="empty">Nothing recorded yet.</td></tr>' : ''}
            ${rows.map(a => `
              <tr>
                <td class="nowrap muted">${when(a.occurredAt)}</td>
                <td class="nowrap">${esc(a.actor)}${a.sourceIp ? `<div class="muted mono" style="font-size:12px">${esc(a.sourceIp)}</div>` : ''}</td>
                <td class="nowrap mono" style="font-size:12.5px">${esc(a.operation)}</td>
                <td class="nowrap">${esc(a.resourceType)}/${esc(a.resourceId)}</td>
                <td>${a.result === 'SUCCESS'
                      ? '<span class="pill on">ok</span>'
                      : `<span class="pill st-FAILED">${esc(a.result)}</span>`}</td>
                <td class="muted mono" style="font-size:12px">${esc((a.detail || a.changes || '').slice(0, 160))}</td>
              </tr>`).join('')}
          </tbody>
        </table></div>
      </div>
    </div>`);
}

// -- users ------------------------------------------------------------------

function usersPage() {
  const rows = state.data.users || [];
  const roles = state.data.roles || [];

  const view = el(`
    <div>
      <div class="page-head">
        <div><h1>Users</h1>
          <p>Authoring a rule and reading a connection's credentials are separate permissions on purpose.
             A rule manager composes what the platform does; only a connection manager holds the key it does it with.</p></div>
        <button class="btn primary" id="add">New user</button>
      </div>

      <div class="card">
        <div class="scroller"><table>
          <thead><tr><th>Username</th><th>Name</th><th>Roles</th><th>Last signed in</th><th>State</th><th></th></tr></thead>
          <tbody>
            ${rows.map(u => `
              <tr>
                <td class="mono">${esc(u.username)}</td>
                <td>${esc(u.displayName)}</td>
                <td>${(u.roles || []).map(r => `<span class="chip" style="cursor:default">${esc(r)}</span>`).join(' ') || '<span class="muted">none</span>'}</td>
                <td class="nowrap muted">${when(u.lastLoginAt)}</td>
                <td><span class="pill ${u.enabled ? 'on' : 'off'}">${u.enabled ? 'enabled' : 'disabled'}</span></td>
                <td class="nowrap"><button class="btn small" data-toggle="${u.id}" data-on="${u.enabled ? '0' : '1'}">
                  ${u.enabled ? 'Disable' : 'Enable'}</button></td>
              </tr>`).join('')}
          </tbody>
        </table></div>
      </div>

      <div class="card">
        <h3>Roles</h3>
        ${roles.map(r => `
          <div style="margin-bottom:12px">
            <strong>${esc(r.name)}</strong>
            <div class="muted" style="font-size:13px;margin-bottom:5px">${esc(r.description)}</div>
            <div class="chips">${(r.permissions || []).map(p => `<span class="chip" style="cursor:default">${esc(p)}</span>`).join('')}</div>
          </div>`).join('')}
      </div>
    </div>`);

  view.querySelectorAll('[data-toggle]').forEach(b => b.addEventListener('click', () => guard(async () => {
    const on = b.dataset.on === '1';
    await api(`/api/users/${b.dataset.toggle}/${on ? 'enable' : 'disable'}`, { method: 'POST' });
    notify(on ? 'User enabled.' : 'User disabled. Their open sessions stop working immediately.');
    await load('users');
  })));

  view.querySelector('#add').addEventListener('click', () => {
    const username = prompt('Username');
    if (!username) return;

    const password = prompt('Password (at least 12 characters — length matters more than punctuation)');
    if (!password) return;

    const role = prompt(`Role\n\n${roles.map(r => '  ' + r.name).join('\n')}`, 'Read Only');
    if (!role) return;

    guard(async () => {
      await api('/api/users', {
        method: 'POST',
        body: { username, displayName: username, password, roles: [role] }
      });
      notify('User created.');
      await load('users');
    });
  });

  return view;
}

// -- boot -------------------------------------------------------------------

async function start() {
  try {
    state.me = await api('/api/auth/me');
  } catch {
    state.me = null;
    render();
    return;
  }

  const wanted = location.hash.replace('#', '') || 'dashboard';
  const allowed = ROUTES.find(r => r.id === wanted && can(r.needs));

  await go(allowed ? wanted : (ROUTES.find(r => can(r.needs))?.id || 'dashboard'));
}

window.addEventListener('hashchange', () => {
  const wanted = location.hash.replace('#', '');
  if (wanted && wanted !== state.route && state.me) go(wanted);
});

start();
