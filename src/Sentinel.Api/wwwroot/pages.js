/* ==========================================================================
   Alerts, action executions, the audit trail and users.

   The alert view is the one that matters most: an operator opening an alert
   is asking "why did this fire, and what did the platform then do to my
   estate?" — so it shows the rule version that produced it, the evidence,
   and every action with its retries, rather than a status word.
   ========================================================================== */

/* What an alert turned out to be, asked for when it is closed.

   Four rather than two, because "the rule was wrong" and "the rule was right
   and the activity was authorised" are different facts and only the first is
   a defect. The wording matters: people pick the leftmost plausible option,
   so each says plainly what it will be counted as. */
const DISPOSITIONS = [
  ['TRUE_POSITIVE', 'Real', 'Genuine, and worth acting on. Counts in the rule\'s favour.'],
  ['FALSE_POSITIVE', 'The rule was wrong',
   'It matched something it should not have. This is the only one counted against the rule.'],
  ['BENIGN', 'Real but authorised',
   'The rule was right and the activity was expected — a backup job, a scheduled scan. Not held against ' +
   'the rule; an exception suits it better than a change to the condition.'],
  ['DUPLICATE', 'Already covered',
   'The same event as another alert. A grouping problem, not a detection one.']
];

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
              ${alert.resolvedAt ? `
                <dt>Closed</dt><dd>${exact(alert.resolvedAt)} by ${esc(alert.resolvedBy || '')}</dd>
                <dt>Turned out to be</dt><dd>${alert.disposition
                  ? esc(DISPOSITIONS.find(d => d[0] === alert.disposition)?.[1] || alert.disposition)
                  : '<span class="muted">not recorded — closed before this was asked for</span>'}</dd>` : ''}
              ${alert.resolutionNote ? `<dt>Note</dt><dd>${esc(alert.resolutionNote)}</dd>` : ''}
            </dl>
            ${Object.keys(evidence).length ? `<h3 style="margin-top:14px">Evidence</h3>
              <pre>${esc(JSON.stringify(evidence, null, 2))}</pre>` : ''}
          </div>

          ${alert.enrichmentJson ? `
            <div class="card">
              <h3>What we know about ${esc(alert.subject)}</h3>
              <p class="muted" style="font-size:13px;margin:0 0 10px">
                Looked up when the alert was written, and stored with it — so this is what the platform
                knew when it decided, not what the inventory says today. A message or a payload reaches
                these as <span class="mono">{{enrich.&lt;name&gt;}}</span>.</p>
              <dl class="kv">${Object.entries(readJson(alert.enrichmentJson))
                .map(([fact, value]) =>
                  `<dt class="mono">${esc(fact)}</dt><dd class="mono">${esc(String(value))}</dd>`)
                .join('')}</dl>
            </div>` : ''}

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

          ${can('alerts.resolve') && alert.status !== 'RESOLVED' ? `
            <div class="card">
              <h3>Close this alert</h3>
              <div class="hint" style="margin-bottom:10px">What it turned out to be is what tells you
                whether the rule is any good. It is the only measure of a detection nobody can infer from
                the outside, so it is asked for rather than guessed.</div>

              <div class="field"><label>It was</label>
                <div class="chips" id="dispositions">
                  ${DISPOSITIONS.map(([value, label, why]) => `
                    <button class="btn small" type="button" data-disposition="${value}" title="${esc(why)}">
                      ${esc(label)}</button>`).join('')}
                </div>
                <div class="hint" id="dispositionhint">&nbsp;</div></div>

              <div class="field"><label>Note</label>
                <input id="resolvenote" placeholder="What was done about it. Optional."></div>
            </div>` : ''}

          <div class="row">
            ${can('alerts.acknowledge') && alert.status === 'DETECTED'
              ? '<button class="btn" id="ack">Acknowledge</button>' : ''}
            ${can('alerts.resolve') && alert.status !== 'RESOLVED'
              ? '<button class="btn primary" id="resolve" disabled>Resolve</button>' : ''}
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

    // Resolve stays disabled until one is chosen. The API refuses without it, and a button that fails
    // on click teaches people the form is broken rather than that the field is required.
    let disposition = null;

    view.querySelectorAll('[data-disposition]').forEach(button => button.addEventListener('click', () => {
      disposition = button.dataset.disposition;

      view.querySelectorAll('[data-disposition]').forEach(other =>
        other.classList.toggle('primary', other === button));

      view.querySelector('#dispositionhint').textContent =
        DISPOSITIONS.find(d => d[0] === disposition)?.[2] ?? '';

      view.querySelector('#resolve').disabled = false;
    }));

    view.querySelector('#resolve')?.addEventListener('click', () => guard(async () => {
      const note = view.querySelector('#resolvenote')?.value || null;

      await api(`/api/alerts/${alert.id}/resolve`, { method: 'POST', body: { note, disposition } });
      close(); notify('Resolved.'); await load('alerts');
    }));

    return view;
  };

  render();
}

// -- action executions ------------------------------------------------------

function executionsPage() {
  const rows = state.data.executions || [];
  const types = state.data.actionTypes || [];

  // Which actions can be taken back at all, from the published catalogue rather than a list here. An
  // address can be unblocked; a message cannot be unsent.
  const reversible = new Set(types.filter(t => t.isReversible).map(t => t.type));

  const inEffect = rows.filter(e => e.status === 'SUCCESS' && !e.reversedAt && reversible.has(e.actionType));
  const waiting = rows.filter(e => e.status === 'PENDING_APPROVAL');

  const view = el(`
    <div>
      <div class="page-head">
        <div><h1>Actions</h1>
          <p>Every response the platform attempted, including the ones it deliberately held back.
             A skipped action means a rule fired and a safety rail stopped it — worth reading.</p></div>
      </div>

      ${waiting.length ? `<div class="notice warn">
        <strong>${waiting.length}</strong> action${waiting.length === 1 ? '' : 's'} waiting for a decision.
        Nothing has been done to the estate yet, and nothing will be unless somebody approves — unanswered,
        ${waiting.length === 1 ? 'it expires' : 'they expire'} without being carried out.</div>` : ''}

      ${inEffect.length ? `<div class="notice info">
        <strong>${inEffect.length}</strong> automated ${inEffect.length === 1 ? 'change is' : 'changes are'}
        still in force. Each was made by a rule rather than a person; any of them can be taken back
        below.</div>` : ''}

      <div class="card">
        <div class="scroller"><table>
          <thead><tr><th>When</th><th>Action</th><th>Target</th><th>Status</th><th>Tries</th><th>Detail</th><th></th></tr></thead>
          <tbody>
            ${rows.length === 0 ? '<tr><td colspan="7" class="empty">Nothing yet.</td></tr>' : ''}
            ${rows.map(e => `
              <tr>
                <td class="nowrap muted">${when(e.createdAt)}</td>
                <td class="nowrap">${esc(e.actionType)}<div class="muted" style="font-size:12px">${esc(e.connectionName)}</div></td>
                <td class="mono">${esc(e.target || '')}</td>
                <td>${pill('st', e.status)}
                  ${e.reversedAt
                    ? `<div class="muted" style="font-size:12px">reversed ${when(e.reversedAt)}
                       by ${esc(e.reversedBy || '')}</div>` : ''}</td>
                <td>${e.retryCount ?? 0}</td>
                <td class="muted" style="font-size:12.5px">${esc(e.errorMessage || e.errorCode || '')}
                  ${e.reversalError
                    ? `<div style="color:var(--crit)">undo failed: ${esc(e.reversalError)}</div>` : ''}</td>
                <td class="nowrap"><div class="row">
                  ${can('engine.operate') && e.status === 'PENDING_APPROVAL' ? `
                    <button class="btn small primary" data-approve="${e.id}"
                            data-what="${esc(e.actionType)} on ${esc(e.target || '')}">Approve</button>
                    <button class="btn small danger" data-reject="${e.id}">Decline</button>` : ''}
                  ${can('engine.operate') && e.status === 'SUCCESS' && !e.reversedAt && reversible.has(e.actionType)
                    ? `<button class="btn small danger" data-reverse="${e.id}"
                         data-what="${esc(e.actionType)} on ${esc(e.target || '')}">Undo</button>` : ''}
                </div></td>
              </tr>`).join('')}
          </tbody>
        </table></div>
      </div>
    </div>`);

  view.querySelectorAll('[data-approve]').forEach(button => button.addEventListener('click', () => {
    if (!confirm(`Approve ${button.dataset.what}?\n\nIt is carried out now.`)) return;

    guard(async () => {
      const result = await api(`/api/action-executions/${button.dataset.approve}/approve`, { method: 'POST' });

      // The approval succeeded; the action it released may still have failed at the far end, and saying
      // "approved" for a block that the gateway refused would be the wrong half of the story.
      notify(result.status === 'SUCCESS'
        ? 'Approved and carried out.'
        : `Approved, but the action ended as ${result.status}. ${result.errorMessage || ''}`,
        result.status === 'SUCCESS' ? 'ok' : 'err');

      await load('executions');
    });
  }));

  view.querySelectorAll('[data-reject]').forEach(button => button.addEventListener('click', () => {
    const reason = prompt('Why is this being declined? (optional, and worth more than the decision alone)');

    // Cancel on the prompt is not a decision. Only null means cancelled — an empty string is somebody
    // declining without giving a reason, which is allowed.
    if (reason === null) return;

    guard(async () => {
      await api(`/api/action-executions/${button.dataset.reject}/reject`, {
        method: 'POST', body: { reason: reason || null }
      });

      notify('Declined. It was not carried out.');
      await load('executions');
    });
  }));

  view.querySelectorAll('[data-reverse]').forEach(button => button.addEventListener('click', () => {
    // Confirmed, because this reaches a live system and the row it sits on is one of many. Undoing the
    // wrong block during an incident is its own incident.
    if (!confirm(`Undo ${button.dataset.what}?\n\nThis calls the service and lifts it now.`)) return;

    guard(async () => {
      await api(`/api/action-executions/${button.dataset.reverse}/reverse`, { method: 'POST' });
      notify('Reversed.');
      await load('executions');
    });
  }));

  return view;
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

/* ==========================================================================
   The asset inventory.

   The smallest thing that changes a decision: what the platform needs before
   it blocks an address is whether that address is a laptop or a domain
   controller, and who to ask. Everything an asset database holds beyond that
   belongs to a different tool.
   ========================================================================== */

const ASSET_KINDS = [
  ['ADDRESS', 'One address', '10.5.5.5'],
  ['NETWORK', 'A range', '10.5.5.0/24'],
  ['ACCOUNT', 'An account', 'svc-backup']
];

const CRITICALITIES = [
  ['CRITICAL', 'Critical', 'Alerts about it are raised to CRITICAL.'],
  ['HIGH', 'High', 'Alerts about it are raised to HIGH.'],
  ['NORMAL', 'Normal', 'Most of the estate. Changes nothing about severity.'],
  ['LOW', 'Low', 'A lab, a test box. Changes nothing either — severity is never lowered.']
];

function assetsPage() {
  const rows = state.data.assets || [];

  const view = el(`
    <div>
      <div class="page-head">
        <div><h1>Assets</h1>
          <p>What the estate knows about the things alerts are about. An alert whose subject matches an
             entry carries its name and owner into every message, and one about a critical asset is raised
             to CRITICAL — severity is only ever raised, never lowered.</p></div>
        ${can('connections.manage') ? '<button class="btn primary" id="add">Add entry</button>' : ''}
      </div>

      ${rows.length === 0 ? `<div class="notice info">
        Nothing here yet, so every alert is as serious as its rule assumed and no message can say whose
        machine it is about. Start with the handful that would change what somebody does at two in the
        morning — the controllers, the payment hosts, the service accounts.</div>` : ''}

      <div class="card">
        <div class="scroller"><table>
          <thead><tr><th>Name</th><th>Matches</th><th>Criticality</th><th>Owner</th>
            <th>Environment</th><th></th></tr></thead>
          <tbody>
            ${rows.map(a => `
              <tr>
                <td><strong>${esc(a.name)}</strong>
                  ${a.notes ? `<div class="muted" style="font-size:12.5px">${esc(a.notes)}</div>` : ''}</td>
                <td class="mono">${esc(a.identifier)}
                  <div class="muted" style="font-size:12px">${esc(a.kind.toLowerCase())}</div></td>
                <td>${pill('sev', a.criticality === 'NORMAL' || a.criticality === 'LOW' ? 'LOW' : a.criticality)}
                  <div class="muted" style="font-size:12px">${esc(a.criticality.toLowerCase())}</div></td>
                <td>${esc(a.owner || '')}</td>
                <td>${esc(a.environment || '')}</td>
                <td class="nowrap"><div class="row">
                  ${can('connections.manage')
                    ? `<button class="btn small" data-edit="${a.id}">Edit</button>
                       <button class="btn small danger" data-drop="${a.id}"
                               data-name="${esc(a.name)}">Remove</button>` : ''}
                </div></td>
              </tr>`).join('')}
          </tbody>
        </table></div>
      </div>
    </div>`);

  view.querySelector('#add')?.addEventListener('click', () => openAsset(null));

  view.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () =>
    openAsset(rows.find(a => a.id === +b.dataset.edit))));

  view.querySelectorAll('[data-drop]').forEach(b => b.addEventListener('click', () => {
    // Confirmed, because removing an entry silently lowers the severity of every future alert about that
    // thing — a quiet change whose effect shows up weeks later.
    if (!confirm(`Remove ${b.dataset.name}?\n\nAlerts about it stop being raised and stop carrying its owner.`))
      return;

    guard(async () => {
      await api(`/api/assets/${b.dataset.drop}`, { method: 'DELETE' });
      notify('Removed.');
      await load('assets');
    });
  }));

  return view;
}

function openAsset(existing) {
  state.drawer = () => {
    const view = el(`
      <div class="drawer-back">
        <div class="drawer">
          <div class="drawer-head">
            <div><h1>${existing ? esc(existing.name) : 'Add to the inventory'}</h1>
              <p class="muted">One entry per thing. An exact address beats a range that contains it and
                 the narrowest range wins, so a /8 for the estate and a row for the controller inside it
                 both make sense.</p></div>
            <button class="btn" id="close">Close</button>
          </div>

          <div class="card">
            <form id="form">
              <div class="grid2">
                <div class="field"><label>Name</label>
                  <input name="name" value="${esc(existing?.name || '')}" required
                         placeholder="dc01 — something a reader would recognise"></div>
                <div class="field"><label>Criticality</label>
                  <select name="criticality">
                    ${CRITICALITIES.map(([value, label]) =>
                      `<option value="${value}"
                        ${(existing?.criticality || 'NORMAL') === value ? 'selected' : ''}>${label}</option>`).join('')}
                  </select>
                  <div class="hint" id="crithint"></div></div>
              </div>

              <div class="grid2">
                <div class="field"><label>Kind</label>
                  <select name="kind">
                    ${ASSET_KINDS.map(([value, label]) =>
                      `<option value="${value}"
                        ${(existing?.kind || 'ADDRESS') === value ? 'selected' : ''}>${label}</option>`).join('')}
                  </select></div>
                <div class="field"><label>Matches</label>
                  <input name="identifier" class="mono" value="${esc(existing?.identifier || '')}" required>
                  <div class="hint" id="kindhint"></div></div>
              </div>

              <div class="grid2">
                <div class="field"><label>Owner</label>
                  <input name="owner" value="${esc(existing?.owner || '')}"
                         placeholder="Who to wake. Carried into the message."></div>
                <div class="field"><label>Environment</label>
                  <input name="environment" value="${esc(existing?.environment || '')}"
                         placeholder="production, staging, lab"></div>
              </div>

              <div class="field"><label>Notes</label>
                <input name="notes" value="${esc(existing?.notes || '')}"></div>

              <div class="row">
                <button class="btn primary" type="submit">${existing ? 'Save' : 'Add'}</button>
                <button class="btn" type="button" id="cancel">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      </div>`);

    const close = () => { state.drawer = null; render(); };
    view.querySelector('#close').addEventListener('click', close);
    view.querySelector('#cancel').addEventListener('click', close);
    view.addEventListener('click', e => { if (e.target === view) close(); });

    // Both hints follow the selects, because what "Matches" means depends on the kind: an address, a
    // range or a name, and only the other field says which.
    const describe = () => {
      const kind = view.querySelector('[name=kind]').value;
      const criticality = view.querySelector('[name=criticality]').value;

      view.querySelector('#kindhint').textContent =
        'For example ' + (ASSET_KINDS.find(k => k[0] === kind)?.[2] ?? '');

      view.querySelector('#crithint').textContent =
        CRITICALITIES.find(c => c[0] === criticality)?.[2] ?? '';
    };

    view.querySelector('[name=kind]').addEventListener('change', describe);
    view.querySelector('[name=criticality]').addEventListener('change', describe);
    describe();

    view.querySelector('#form').addEventListener('submit', (event) => {
      event.preventDefault();
      const form = new FormData(event.target);

      const body = {
        identifier: form.get('identifier').trim(),
        kind: form.get('kind'),
        name: form.get('name').trim(),
        criticality: form.get('criticality'),
        owner: form.get('owner') || null,
        environment: form.get('environment') || null,
        notes: form.get('notes') || null
      };

      guard(async () => {
        if (existing) await api(`/api/assets/${existing.id}`, { method: 'PUT', body });
        else await api('/api/assets', { method: 'POST', body });

        close();
        notify(existing ? 'Saved.' : 'Added to the inventory.');
        await load('assets');
      });
    });

    return view;
  };

  render();
}
