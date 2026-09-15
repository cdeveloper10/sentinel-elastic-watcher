/* ==========================================================================
   The rule builder.

   Three things here are the difference between a form and a usable console:
   the field picker is fed from the cluster's real mapping rather than being
   a text box, a condition is built from rows rather than typed as query
   syntax, and both can be tested against real data before anything is saved.
   For a platform that blocks addresses automatically, that rehearsal is the
   only honest basis for trusting a rule.

   The compiler that turns rows into a query lives on the server and is asked
   for over HTTP. That looks like an extra round trip and is a deliberate one:
   a second compiler here would mean the query an author previewed and the
   query the engine runs are two compilations of the same intent, which stays
   true right up until they differ and nothing says so.

   Every edit is written into `draft` as it happens, and the form is rendered
   from `draft`. Anything that calls render() — a notification, a background
   load — rebuilds this drawer from scratch, and before that was true a failed
   discovery emptied a half-filled form.

   Action forms are generated from the schema the backend publishes, so adding
   a provider needs no change to this file.
   ========================================================================== */

/* Field mapping types that mean a value should be written as a number or a
   boolean rather than quoted. The distinction is not cosmetic: a term query
   for "500" against an integer field matches nothing. */
const NUMERIC_TYPES = [
  'long', 'integer', 'short', 'byte', 'double', 'float', 'half_float', 'scaled_float', 'unsigned_long'
];

const kindOfType = (type) =>
  NUMERIC_TYPES.includes(type) ? 'number' : type === 'boolean' ? 'boolean' : 'text';

/* What each kind of field can usefully be asked. Kept to comparisons whose
   behaviour an author can predict — anything else belongs in the raw editor
   rather than in a vocabulary that grows until it is the query language with
   worse names. */
const OPERATORS = {
  text: [
    ['is', 'is'], ['is_not', 'is not'], ['one_of', 'is one of'],
    ['contains', 'contains'], ['starts_with', 'starts with'],
    ['exists', 'exists'], ['missing', 'is missing']
  ],
  number: [
    ['is', 'is'], ['is_not', 'is not'], ['one_of', 'is one of'],
    ['gte', 'is at least'], ['gt', 'is more than'],
    ['lte', 'is at most'], ['lt', 'is less than'],
    ['between', 'is between'], ['exists', 'exists'], ['missing', 'is missing']
  ],
  boolean: [['is', 'is'], ['exists', 'exists'], ['missing', 'is missing']],

  // For a field the mapping has not been asked about. Offering only the text comparisons here looks
  // tidier and makes "latency is more than 3000" impossible to express until somebody has pressed
  // Discover fields, which is a rule the author has no way of guessing.
  unknown: [
    ['is', 'is'], ['is_not', 'is not'], ['one_of', 'is one of'],
    ['contains', 'contains'], ['starts_with', 'starts with'],
    ['gte', 'is at least'], ['gt', 'is more than'],
    ['lte', 'is at most'], ['lt', 'is less than'],
    ['between', 'is between'], ['exists', 'exists'], ['missing', 'is missing']
  ]
};

const arityOf = (op) => op === 'exists' || op === 'missing' ? 0 : op === 'between' ? 2 : 1;

/* What a value looks like, for a field whose mapping is not known. The mapping is the better answer and
   is used whenever it is available — this is the fallback, and the row says out loud that it guessed. */
function inferKind(values, operator) {
  const given = (values || []).map(v => String(v ?? '').trim()).filter(v => v !== '');

  if (given.length === 0) return 'text';
  if (given.every(v => /^-?\d+(\.\d+)?$/.test(v))) return 'number';
  if (operator !== 'between' && given.every(v => /^(true|false)$/i.test(v))) return 'boolean';

  return 'text';
}

const LOOKBACKS = [[15, 'last 15 minutes'], [60, 'last hour'], [360, 'last 6 hours'], [1440, 'last 24 hours']];

/* ==========================================================================
   The placeholder menu

   Typing {{ offers what this rule will actually carry. The chips below each
   action already do that, but they are a list to go and read; this is the
   same list arriving where the author is already typing, which is the
   difference between knowing the vocabulary exists and using it.

   The offered set is the one the API validates against — the same call that
   feeds the chips — so it cannot drift into suggesting a placeholder that a
   save would then refuse.
   ========================================================================== */

const PLACEHOLDER_OPEN = /\{\{([A-Za-z0-9_.\-@]*)$/;

/* Whether an offset sits inside a JSON string literal.
   Placeholders never contain a quote, so they cannot affect the count and this needs no knowledge of
   them — only of escaping. */
function inStringAt(text, index) {
  let inside = false;
  let escaped = false;

  for (let i = 0; i < index && i < text.length; i++) {
    const c = text[i];

    if (escaped) { escaped = false; continue; }
    if (c === '\\') { escaped = true; continue; }
    if (c === '"') inside = !inside;
  }

  return inside;
}

/* The first placeholder written where a JSON value goes without quotes around it.

   This is the mistake worth naming, because the body is parsed as JSON *before* any placeholder is
   filled in — so `"text": {{message}}` is not a template that produces bad JSON later, it is a body
   that is not JSON now. The parser's own message for it is "Expected property name or '}'", which
   points at a brace and explains nothing. */
function bareePlaceholder(text) {
  const pattern = /\{\{([A-Za-z0-9_.\-@]+)\}\}/g;
  let found;

  while ((found = pattern.exec(text)) !== null) {
    if (!inStringAt(text, found.index)) return found[1];
  }

  return null;
}

/* Putting a placeholder into a field, given what is already around the caret.

   One implementation for all three ways of asking — the menu, the chips under an action, and the fields
   of a previewed event — because the braces were being written blindly and every one of them produced
   {{message}}}} for an author who had typed both halves first.

   Two things are read before anything is written. What follows the caret, so a closer already there is
   used rather than duplicated; and whether the caret is inside a JSON string, because in a request body
   a placeholder standing where a value goes has to carry its own quotes: the body is parsed as JSON
   before any substitution happens, so `"text": {{message}}` is not a template that breaks later, it is
   a body that is not JSON now. */
function placePlaceholder(input, path) {
  const text = input.value;
  const caret = input.selectionStart ?? text.length;
  const json = input.dataset.json === '1';

  // Completing something already begun, or inserting at a bare caret.
  const opened = text.slice(0, caret).match(PLACEHOLDER_OPEN);
  const from = opened ? caret - opened[0].length : caret;

  // Closers are only taken when completing, and only as a full pair. A single "}" is far more likely
  // to end the JSON object than half a placeholder, and eating it would break the body to fix a brace
  // nobody had got wrong. Spaces and tabs are crossed — "{{ }}" is typed that way — but never a
  // newline, where a "}}" belongs to the document rather than to what is being typed.
  const closer = opened ? text.slice(caret).match(/^[ \t]*\}\}/) : null;

  let end = caret + (closer ? closer[0].length : 0);

  const quote = json && !inStringAt(text, from);

  // An author who typed the quotes as well should not end up with two pairs.
  if (quote && text[end] === '"') end++;

  const insert = quote ? `"{{${path}}}"` : `{{${path}}}`;

  input.value = text.slice(0, from) + insert + text.slice(end);

  const at = from + insert.length;

  input.setSelectionRange(at, at);
  input.focus();
  input.dispatchEvent(new Event('input', { bubbles: true }));
}

/* What to say about a request body while it is being typed. */
function describePayload(text) {
  if (!text.trim())
    return { state: 'none', note: 'Empty — the platform’s default body is sent.' };

  const bare = bareePlaceholder(text);

  if (bare) {
    return {
      state: 'bad',
      note: `{{${bare}}} is a value here, but it is not quoted. Write "…": "{{${bare}}}" — the body is ` +
            'parsed as JSON before any placeholder is filled in, so the quotes have to be in what you type.'
    };
  }

  try {
    const parsed = JSON.parse(text);

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
      return { state: 'bad', note: 'The body must be a JSON object.' };

    return { state: 'ok', note: 'Valid JSON object.' };
  } catch (error) {
    const opens = (text.match(/\{/g) || []).length;
    const closes = (text.match(/\}/g) || []).length;

    // Counting braces is crude and it is still the most useful thing to say when they do not match:
    // the parser reports where it gave up, which is rarely where the brace is missing.
    if (opens !== closes) {
      return {
        state: 'bad',
        note: `${Math.abs(opens - closes)} ${opens > closes ? 'closing' : 'opening'} brace(s) missing — ` +
              `${opens} “{” against ${closes} “}”. Remember a placeholder needs two of each.`
      };
    }

    return { state: 'bad', note: error.message };
  }
}

/* Where the caret is on screen. A textarea gives no such answer, so the text
   before the caret is laid out again in a hidden copy of the field and the
   marker at its end is measured. The alternative is a menu pinned under the
   field, which for a six-line payload lands nowhere near what is being typed. */
function caretPoint(input) {
  const rect = input.getBoundingClientRect();
  const style = getComputedStyle(input);
  const multiline = input.tagName === 'TEXTAREA';

  const mirror = document.createElement('div');

  for (const property of [
    'fontFamily', 'fontSize', 'fontWeight', 'fontStyle', 'letterSpacing', 'lineHeight',
    'textTransform', 'wordSpacing', 'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft',
    'borderTopWidth', 'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth', 'boxSizing'
  ]) mirror.style[property] = style[property];

  Object.assign(mirror.style, {
    position: 'absolute', top: '0', left: '-9999px', visibility: 'hidden',
    width: `${rect.width}px`,
    whiteSpace: multiline ? 'pre-wrap' : 'pre',
    overflowWrap: 'break-word'
  });

  mirror.textContent = input.value.slice(0, input.selectionStart);

  const marker = document.createElement('span');
  marker.textContent = '​';
  mirror.appendChild(marker);

  document.body.appendChild(mirror);

  const point = {
    x: rect.left + marker.offsetLeft - input.scrollLeft,
    y: rect.top + marker.offsetTop - input.scrollTop,
    line: parseFloat(style.lineHeight) || 18,
    rect
  };

  mirror.remove();

  return point;
}

/* One menu element for the whole console, reused. Several would be several
   things to remember to close. */
function placeholderMenu() {
  if (!placeholderMenu.box) {
    placeholderMenu.box = el('<div class="ac" hidden></div>');
    document.body.appendChild(placeholderMenu.box);
  }

  return placeholderMenu.box;
}

function attachPlaceholderMenu(input, getOptions) {
  let matches = [];
  let cursor = 0;
  let from = -1;

  const box = placeholderMenu();

  const close = () => {
    if (box.hidden) return;

    box.hidden = true;
    box.innerHTML = '';
    from = -1;
  };

  const draw = () => {
    box.innerHTML = matches.length === 0
      ? '<div class="ac-empty">Nothing matching. Discover fields to be offered the log\'s own.</div>'
      : matches.map((path, i) => `
          <div class="ac-item ${i === cursor ? 'on' : ''}" data-pick="${esc(path)}">
            <span>${highlight(path)}</span>
            <span class="tag">${esc(family(path))}</span>
          </div>`).join('');

    // mousedown, not click: click arrives after blur has already closed this.
    box.querySelectorAll('[data-pick]').forEach(item => item.addEventListener('mousedown', (event) => {
      event.preventDefault();
      take(item.dataset.pick);
    }));

    const point = caretPoint(input);

    box.hidden = false;

    // Flipped above the caret when there is no room below, so the menu is never the thing that
    // pushes what you are typing off the bottom of the screen.
    const height = Math.min(box.scrollHeight, 232);
    const below = point.y + point.line;

    box.style.top = below + height > window.innerHeight - 8
      ? `${Math.max(8, point.y - height - 2)}px`
      : `${below + 2}px`;

    box.style.left = `${Math.min(point.x, window.innerWidth - box.offsetWidth - 8)}px`;

    box.querySelector('.ac-item.on')?.scrollIntoView({ block: 'nearest' });
  };

  const highlight = (path) => {
    const typed = input.value.slice(from + 2, input.selectionStart);

    if (!typed) return esc(path);

    const at = path.toLowerCase().indexOf(typed.toLowerCase());

    return at < 0
      ? esc(path)
      : esc(path.slice(0, at)) + '<b>' + esc(path.slice(at, at + typed.length)) + '</b>' +
        esc(path.slice(at + typed.length));
  };

  const family = (path) => {
    const prefix = path.split('.')[0];
    return ['event', 'sample', 'enrich', 'evidence', 'alert', 'rule'].includes(prefix) ? prefix : 'value';
  };

  // Closed first: the insertion dispatches an input event, and reopening the menu on top of a
  // placeholder that was just completed would be the menu arguing with itself.
  const take = (path) => {
    close();
    placePlaceholder(input, path);
  };

  const refresh = () => {
    const before = input.value.slice(0, input.selectionStart);
    const opened = before.match(PLACEHOLDER_OPEN);

    if (!opened) { close(); return; }

    from = input.selectionStart - opened[0].length;

    const typed = opened[1].toLowerCase();
    const all = getOptions();

    // Anything containing what was typed, but what starts with it first: an author typing "api" means
    // sample.ApiName long before they mean event.service.apiVersion.
    matches = all
      .filter(p => p.toLowerCase().includes(typed))
      .sort((a, b) => {
        const first = b.toLowerCase().startsWith(typed) - a.toLowerCase().startsWith(typed);
        return first !== 0 ? first : a.length - b.length;
      })
      .slice(0, 40);

    cursor = 0;
    draw();
  };

  input.addEventListener('input', refresh);
  input.addEventListener('click', refresh);
  input.addEventListener('blur', close);

  input.addEventListener('keydown', (event) => {
    // Ctrl+Space asks for the menu without typing the braces, the way an editor does. Both properties
    // are checked because key and code disagree under some layouts, and a shortcut that works on one
    // keyboard is not a shortcut.
    if ((event.key === ' ' || event.code === 'Space') && (event.ctrlKey || event.metaKey)) {
      const caret = input.selectionStart;
      const before = input.value.slice(0, caret);

      // Only the braces that are missing. Asking for the menu when one or both are already typed is
      // the normal way to reach it, and answering with {{{ would be the same bug at the other end.
      const opening = before.endsWith('{{') ? '' : before.endsWith('{') ? '{' : '{{';

      input.value = before + opening + input.value.slice(caret);
      input.setSelectionRange(caret + opening.length, caret + opening.length);

      event.preventDefault();
      refresh();
      return;
    }

    if (box.hidden) return;

    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      cursor = (cursor + (event.key === 'ArrowDown' ? 1 : matches.length - 1)) % Math.max(matches.length, 1);
      event.preventDefault();
      draw();
      return;
    }

    if ((event.key === 'Enter' || event.key === 'Tab') && matches.length > 0) {
      // The reason Enter is safe to take here: in a single-line field it would otherwise submit the
      // form, and in a textarea it would insert a newline in the middle of a placeholder.
      event.preventDefault();
      take(matches[cursor]);
      return;
    }

    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      close();
    }
  });

  // Scrolling moves the field out from under the menu, and a menu pointing at nothing is worse than
  // no menu.
  input.closest('.drawer')?.addEventListener('scroll', close, { passive: true });
}

/* How a verdict from /api/rules/quality is shown. Colour is carried by the same pill classes severities
   use, so a rule doing harm reads the way a critical alert does — which is what it is. */
const VERDICTS = {
  HARMFUL:  ['sev-CRITICAL', 'harmful'],
  TUNE:     ['sev-HIGH', 'tune it'],
  SILENT:   ['sev-MEDIUM', 'never fired'],
  HEALTHY:  ['st-RESOLVED', 'healthy'],
  UNJUDGED: ['off', 'unjudged']
};

function rulesPage() {
  const rows = state.data.rules || [];
  const quality = state.data.quality || [];

  const view = el(`
    <div>
      <div class="page-head">
        <div>
          <h1>Rules</h1>
          <p>A saved rule does nothing. An armed rule evaluates on its interval and acts on what it finds —
             rehearse it against real data before arming it.</p>
        </div>
        ${can('rules.create') ? '<button class="btn primary" id="add">New rule</button>' : ''}
      </div>

      <div class="card">
        <div class="scroller"><table>
          <thead><tr><th>Rule</th><th>Severity</th><th>Quality</th><th>State</th><th>Last run</th><th>Alerts</th><th></th></tr></thead>
          <tbody>
            ${rows.length === 0 ? '<tr><td colspan="7" class="empty">No rules yet.</td></tr>' : ''}
            ${rows.map(r => {
              const q = quality.find(x => x.ruleId === r.id);
              const [style, label] = VERDICTS[q?.verdict] || VERDICTS.UNJUDGED;

              return `
              <tr>
                <td><strong>${esc(r.name)}</strong>
                  <div class="muted" style="font-size:12.5px">${esc(r.description || '')}</div>
                  ${r.consecutiveFailures > 0
                    ? `<div class="pill st-FAILED" style="margin-top:4px">failing x${r.consecutiveFailures}</div>
                       <div class="muted mono" style="font-size:12px">${esc(r.lastError || '')}</div>` : ''}</td>
                <td>${pill('sev', r.severity)}</td>
                <td class="nowrap">
                  <span class="pill ${style}" title="${esc(q?.advice || '')}">${label}</span>
                  ${q && q.judged > 0
                    ? `<div class="muted" style="font-size:12px">${Math.round(q.falsePositiveRate * 100)}% false
                       &middot; ${q.judged} judged</div>` : ''}</td>
                <td><span class="pill ${r.enabled ? 'on' : 'off'}">${r.enabled ? 'armed' : 'draft'}</span>
                    <div class="muted" style="font-size:12px">v${r.currentVersion}</div></td>
                <td class="nowrap muted">${when(r.lastRunAt)}</td>
                <td class="nowrap">${r.lastRunAlerts ?? 0}</td>
                <td class="nowrap"><div class="row">
                  <button class="btn small" data-open="${r.id}">Open</button>
                  ${can('rules.create')
                    ? `<button class="btn small" data-copy="${r.id}" title="Open a copy of this rule as a new one">Duplicate</button>` : ''}
                  ${can('rules.test') ? `<button class="btn small" data-dry="${r.id}">Dry run</button>` : ''}
                  ${can('rules.enable') ? `<button class="btn small ${r.enabled ? 'danger' : 'primary'}"
                     data-arm="${r.id}" data-on="${r.enabled ? '0' : '1'}">${r.enabled ? 'Disarm' : 'Arm'}</button>` : ''}
                </div></td>
              </tr>`;
            }).join('')}
          </tbody>
        </table></div>
      </div>
    </div>`);

  view.querySelector('#add')?.addEventListener('click', () => openTemplates());

  view.querySelectorAll('[data-open]').forEach(b => b.addEventListener('click', () => guard(async () => {
    await openRule(await api(`/api/rules/${b.dataset.open}`));
  })));

  // The second rule of any family is the first with two numbers changed. Copying one is the difference
  // between a thirty-second edit and rebuilding it from an empty form.
  view.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => guard(async () => {
    await openRule(await api(`/api/rules/${b.dataset.copy}`), { duplicate: true });
  })));

  view.querySelectorAll('[data-arm]').forEach(b => b.addEventListener('click', () => guard(async () => {
    const on = b.dataset.on === '1';
    await api(`/api/rules/${b.dataset.arm}/${on ? 'enable' : 'disable'}`, { method: 'POST' });
    notify(on ? 'Rule armed. It evaluates on its next tick.' : 'Rule disarmed.');
    await load('rules');
  })));

  view.querySelectorAll('[data-dry]').forEach(b => b.addEventListener('click', () => guard(async () => {
    const result = await api(`/api/rules/${b.dataset.dry}/dry-run`, {
      method: 'POST', body: { lookbackMinutes: 60 }
    });
    openDryRun(rows.find(r => r.id === +b.dataset.dry), result);
  })));

  return view;
}

/* ==========================================================================
   Starting from something
   ========================================================================== */

function openTemplates() {
  const templates = state.data.templates || [];

  state.drawer = () => {
    const view = el(`
      <div class="drawer-back">
        <div class="drawer">
          <div class="drawer-head">
            <div><h1>New rule</h1>
              <p class="muted">Start from a shape that already works, or from nothing. A template fills in
                 the condition, the grouping and the timings — you still choose the connection, the
                 indices and whether it does anything beyond alerting.</p></div>
            <button class="btn" id="close">Close</button>
          </div>

          <div class="card">
            <div class="spread">
              <div>
                <strong>Start from scratch</strong>
                <div class="muted" style="font-size:13px">An empty form.</div>
              </div>
              <button class="btn" id="scratch">Empty rule</button>
            </div>
          </div>

          <div class="card">
            <h3>Templates</h3>
            <div class="template-grid">
              ${templates.map(t => `
                <button class="template-card" type="button" data-pick="${esc(t.id)}">
                  <strong>${esc(t.name)}</strong>
                  <div class="sum">${esc(t.summary)}</div>
                  <div class="why">${esc(t.purpose)}</div>
                  <div class="meta">
                    ${pill('sev', t.severity)}
                    <span class="chip">${esc(t.groupBy.join(', ') || 'no grouping')}</span>
                    <span class="chip">${t.threshold} in ${Math.round(t.windowSeconds / 60)}m</span>
                  </div>
                </button>`).join('')
                || '<div class="empty">No templates are published.</div>'}
            </div>
            <div class="hint" style="margin-top:12px">Field names follow ECS and will not match every
              index. Pick a template, discover your fields, and the builder marks any row pointing at a
              field your indices do not have.</div>
          </div>
        </div>
      </div>`);

    const close = () => { state.drawer = null; render(); };
    view.querySelector('#close').addEventListener('click', close);
    view.addEventListener('click', e => { if (e.target === view) close(); });

    view.querySelector('#scratch').addEventListener('click', () => guard(() => openRule(null)));

    view.querySelectorAll('[data-pick]').forEach(card => card.addEventListener('click', () => guard(() =>
      openRule(null, { template: templates.find(t => t.id === card.dataset.pick) }))));

    return view;
  };

  render();
}

/* ==========================================================================
   Rehearsal
   ========================================================================== */

function openDryRun(rule, result) {
  const detections = result.wouldDetect || [];
  const actions = result.wouldExecute || [];

  state.drawer = () => {
    const view = el(`
      <div class="drawer-back">
        <div class="drawer">
          <div class="drawer-head">
            <div><h1>Rehearsal</h1>
              <p class="muted">${esc(rule?.name || '')} — real data, nothing executed.
                 No address was blocked and no message was sent.</p></div>
            <button class="btn" id="close">Close</button>
          </div>

          ${result.succeeded === false
            ? `<div class="notice err">${esc(result.failure || result.message || 'The rehearsal failed.')}</div>` : ''}

          <div class="tiles">
            <div class="tile"><div class="n">${detections.length}</div><div class="k">Would detect</div></div>
            <div class="tile"><div class="n">${actions.length}</div><div class="k">Actions each</div></div>
            <div class="tile"><div class="n">${detections.length * actions.length}</div><div class="k">Actions in total</div></div>
          </div>

          ${detections.length ? `
            <div class="card" style="margin-top:14px">
              <h3>What would have triggered</h3>
              <div class="scroller"><table>
                <thead><tr><th>Subject</th><th>Events</th></tr></thead>
                <tbody>${detections.map(d => `
                  <tr><td class="mono">${esc(subjectOf(d))}</td><td>${esc(d.eventCount ?? '')}</td></tr>`).join('')}
                </tbody></table></div>
            </div>`
            : `<div class="card" style="margin-top:14px"><div class="empty">
                 Nothing in this window would have triggered the rule. That is either a quiet period or a
                 threshold set too high — widen the lookback or lower it and try again.</div></div>`}

          ${actions.length ? `
            <div class="card"><h3>What it would then do</h3>
              <div class="chips">${actions.map(a =>
                `<span class="chip">${esc(a.type ?? a)}${a.connection ? ' &rarr; ' + esc(a.connection) : ''}</span>`).join('')}</div>
            </div>` : ''}
        </div>
      </div>`);

    const close = () => { state.drawer = null; render(); };
    view.querySelector('#close').addEventListener('click', close);
    view.addEventListener('click', e => { if (e.target === view) close(); });

    return view;
  };

  render();
}

function subjectOf(detection) {
  const subject = detection.subject || detection.Subject;
  if (!subject) return JSON.stringify(detection);

  return Object.entries(subject).map(([key, value]) => `${key}=${value}`).join('  ');
}

/* ==========================================================================
   The rule form
   ========================================================================== */

async function openRule(detail, options = {}) {
  const { template, duplicate } = options;

  const rule = duplicate ? null : detail?.rule;
  const current = detail?.current;
  const identity = duplicate ? null : detail?.rule;

  const sources = (state.data.connections || []).filter(c => c.type === 'elasticsearch');
  const actionTypes = state.data.actionTypes || [];
  const strategies = state.data.strategies || ['threshold', 'match'];

  const readJson = (value, fallback) => { try { return JSON.parse(value || ''); } catch { return fallback; } };

  // Rule versions are immutable history, and the versions written before the API stored these in
  // camelCase are PascalCase for ever. Reading either is not tidiness: an action whose `type` did not
  // resolve rendered no settings at all, so reopening a rule silently emptied its own action form.
  const readAction = a => ({
    type: a.type ?? a.Type ?? '',
    connection: a.connection ?? a.Connection ?? '',
    settings: { ...(a.settings ?? a.Settings ?? {}) },

    // Absent on every version stored before gating existed, and false is the only reading that does not
    // silently start holding an action somebody has been relying on.
    requiresApproval: (a.requiresApproval ?? a.RequiresApproval) === true
  });

  // Everything the form edits, in one place. The drawer renders from this and writes back to it on every
  // keystroke, so a rebuild — which any notification causes — restores the form rather than emptying it.
  const draft = {
    name: template ? template.name : duplicate ? `${detail.rule.name} (copy)` : detail?.rule?.name || '',
    description: template ? template.summary : detail?.rule?.description || '',
    severity: template ? template.severity : detail?.rule?.severity || 'HIGH',
    connectionId: detail?.rule?.connectionId || sources[0]?.id || 0,
    indexPatterns: current ? readJson(current.indexPatternsJson, []).join(', ') : '',
    timestampField: current?.timestampField || '@timestamp',
    strategyType: template ? template.strategyType : current?.strategyType || 'threshold',
    groupBy: (template ? template.groupBy : current ? readJson(current.groupByJson, []) : []).join(', '),
    threshold: template ? template.threshold : current?.threshold ?? 20,
    windowSeconds: template ? template.windowSeconds : current?.windowSeconds ?? 300,
    intervalSeconds: template ? template.intervalSeconds : current?.intervalSeconds ?? 60,
    queryDelaySeconds: template ? template.queryDelaySeconds : current?.queryDelaySeconds ?? 30,
    cooldownSeconds: template ? template.cooldownSeconds : current?.cooldownSeconds ?? 1800,
    changeNote: '',

    actions: current && !template ? readJson(current.actionsJson, []).map(readAction) : [],

    conditions: template ? template.conditions.map(c => ({ ...c })) : [],
    queryJson: template ? template.queryJson : current?.queryJson || '',
    mode: 'builder',
    queryError: '',

    // A template's message is a starting point that gets copied into the first action that takes one.
    // A live reference would mean editing one template silently rewrote what twenty rules send.
    suggestedMessage: template?.message || '',
    expects: template?.fields || [],

    fields: null,
    preview: null,
    previewError: '',
    lookback: 15,
    scroll: 0
  };

  // An existing rule's query has to be read back into rows before the form opens, or every saved rule
  // would land in the raw editor regardless of how simple its condition is.
  if (!template && draft.queryJson) {
    try {
      const read = await api('/api/rules/condition', { method: 'POST', body: { queryJson: draft.queryJson } });
      draft.conditions = read.conditions || [];
      draft.mode = read.representable ? 'builder' : 'raw';
    } catch {
      // A stored query the server will not even parse. The raw editor is where that can be fixed.
      draft.mode = 'raw';
    }
  }

  state.drawer = () => {
    const view = el(`
      <div class="drawer-back">
        <div class="drawer">
          <div class="drawer-head">
            <div><h1>${identity ? esc(identity.name) : template ? esc(template.name) : 'New rule'}</h1>
              <p class="muted">${identity
                ? `Version ${identity.currentVersion}. Saving creates a new one — alerts cite the version that produced them, so versions are never rewritten.`
                : duplicate
                  ? 'A copy. It is a separate rule from here on, and it starts disarmed.'
                  : 'Created disarmed. Rehearse it, then arm it.'}</p></div>
            <button class="btn" id="close">Close</button>
          </div>

          ${sources.length === 0
            ? '<div class="notice warn">No Elasticsearch connection exists yet. Add one under Connections first.</div>' : ''}

          ${template ? `<div class="notice info">Started from <strong>${esc(template.name)}</strong>.
             ${esc(template.purpose)}</div>` : ''}

          <div class="card">
            <form id="form">
              <div class="grid2">
                <div class="field"><label>Name</label>
                  <input name="name" value="${esc(draft.name)}" required></div>
                <div class="field"><label>Severity</label>
                  <select name="severity">${['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s =>
                    `<option ${draft.severity === s ? 'selected' : ''}>${s}</option>`).join('')}</select></div>
              </div>

              <div class="field"><label>Description</label>
                <input name="description" value="${esc(draft.description)}"
                       placeholder="What this rule looks for, in a sentence."></div>

              <fieldset><legend>Source</legend>
                <div class="grid2">
                  <div class="field"><label>Connection</label>
                    <select name="connectionId">
                      ${sources.map(c => `<option value="${c.id}" ${draft.connectionId === c.id ? 'selected' : ''}>${esc(c.name)}</option>`).join('')}
                    </select></div>
                  <div class="field"><label>Index patterns</label>
                    <input name="indexPatterns" value="${esc(draft.indexPatterns)}" placeholder="gateway-logs-*">
                    <div class="hint">Comma separated. A bare <span class="mono">*</span> is refused: it would read the whole cluster on every tick.</div></div>
                </div>
                <button class="btn small" type="button" id="discover">Discover fields</button>
                <div id="fieldbox" style="margin-top:10px"></div>
              </fieldset>

              <fieldset><legend>Condition</legend>
                <div class="tabs">
                  <button type="button" data-mode="builder" class="${draft.mode === 'builder' ? 'on' : ''}">Builder</button>
                  <button type="button" data-mode="raw" class="${draft.mode === 'raw' ? 'on' : ''}">Query JSON</button>
                </div>

                <div id="condition"></div>

                <div class="grid2">
                  <div class="field"><label>Strategy</label>
                    <select name="strategyType">${strategies.map(s =>
                      `<option ${draft.strategyType === s ? 'selected' : ''}>${esc(s)}</option>`).join('')}</select></div>
                  <div class="field"><label>Timestamp field</label>
                    <input name="timestampField" value="${esc(draft.timestampField)}"></div>
                </div>

                <div class="field"><label>Group by</label>
                  <input name="groupBy" value="${esc(draft.groupBy)}" placeholder="source.ip">
                  <div class="hint">Comma separated. Only aggregatable fields work — discover fields above to see which are.</div></div>

                <div class="grid2">
                  <div class="field"><label>Threshold</label>
                    <input name="threshold" type="number" min="1" value="${draft.threshold}"></div>
                  <div class="field"><label>Window (seconds)</label>
                    <input name="windowSeconds" type="number" min="1" value="${draft.windowSeconds}"></div>
                </div>

                <div id="previewbox"></div>
              </fieldset>

              <fieldset><legend>Timing</legend>
                <div class="grid2">
                  <div class="field"><label>Interval (seconds)</label>
                    <input name="intervalSeconds" type="number" min="1" value="${draft.intervalSeconds}">
                    <div class="hint">How often it evaluates.</div></div>
                  <div class="field"><label>Ingest delay (seconds)</label>
                    <input name="queryDelaySeconds" type="number" min="0" value="${draft.queryDelaySeconds}">
                    <div class="hint">How far behind real time to look. A log written now may not be searchable for a few seconds, and a window that has passed is never examined again.</div></div>
                </div>
                <div class="field"><label>Cooldown (seconds)</label>
                  <input name="cooldownSeconds" type="number" min="0" value="${draft.cooldownSeconds}">
                  <div class="hint">Per rule <em>and</em> subject. One address staying over the threshold produces one alert, not one per tick.</div></div>
              </fieldset>

              <fieldset><legend>Actions</legend>
                <div id="actions"></div>
                <div class="row" style="margin-top:8px">
                  ${actionTypes.map(t => `<button class="btn small" type="button" data-add="${esc(t.type)}">+ ${esc(t.displayName)}</button>`).join('')}
                </div>
              </fieldset>

              ${identity ? `<div class="field"><label>What changed</label>
                <input name="changeNote" value="${esc(draft.changeNote)}" placeholder="Shown beside this version in the history."></div>` : ''}

              <div class="row">
                <button class="btn primary" type="submit">${identity ? 'Save as new version' : 'Create'}</button>
                <button class="btn" type="button" id="cancel">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      </div>`);

    const drawer = view.querySelector('.drawer');

    // The menu lives on the body, so a rebuild of this drawer would leave it floating over a field that
    // no longer exists. Anything that re-renders starts with it shut.
    placeholderMenu().hidden = true;

    // Rebuilt drawers used to land back at the top, which after a failed discovery meant scrolling down
    // to find the form again.
    drawer.addEventListener('scroll', () => { draft.scroll = drawer.scrollTop; });
    requestAnimationFrame(() => { drawer.scrollTop = draft.scroll; });

    // One listener for the whole form: every named input writes straight into the draft. Numbers are
    // kept as numbers so a rebuild does not turn 300 into "300" and back.
    view.querySelector('#form').addEventListener('input', (event) => {
      const field = event.target.name;
      if (!field || !(field in draft)) return;

      draft[field] = event.target.type === 'number' ? +event.target.value : event.target.value;
    });

    view.querySelector('#form').addEventListener('change', (event) => {
      const field = event.target.name;
      if (!field || !(field in draft)) return;

      draft[field] = field === 'connectionId' ? +event.target.value : event.target.value;
    });

    // -- the field picker ---------------------------------------------------

    const fieldByPath = (path) => (draft.fields?.fields || []).find(f => f.path === path);

    const drawFields = () => {
      const box = view.querySelector('#fieldbox');
      if (!draft.fields) { box.innerHTML = ''; return; }

      const stamps = draft.fields.fields.filter(f => f.isTimestamp);
      const groupable = draft.fields.fields.filter(f => f.aggregatable && !f.isTimestamp);

      box.innerHTML = `
        <div class="muted" style="font-size:13px;margin-bottom:8px">
          ${draft.fields.fields.length} field(s) across ${draft.fields.indicesInspected.length} index(es). Click one to use it.
        </div>
        <div style="font-size:11.5px;font-weight:700;color:var(--muted);margin:8px 0 4px">TIMESTAMP</div>
        <div class="chips">${stamps.map(f => `<span class="chip" data-ts="${esc(f.path)}">${esc(f.path)}</span>`).join('')
          || '<span class="muted" style="font-size:13px">none found</span>'}</div>
        <div style="font-size:11.5px;font-weight:700;color:var(--muted);margin:12px 0 4px">GROUPABLE</div>
        <div class="chips">${groupable.slice(0, 80).map(f =>
          `<span class="chip" data-gb="${esc(f.path)}" title="${esc(f.type)}">${esc(f.path)}</span>`).join('')
          || '<span class="muted" style="font-size:13px">none found</span>'}</div>`;

      box.querySelectorAll('[data-ts]').forEach(chip => chip.addEventListener('click', () => {
        draft.timestampField = chip.dataset.ts;
        view.querySelector('[name=timestampField]').value = chip.dataset.ts;
      }));

      box.querySelectorAll('[data-gb]').forEach(chip => chip.addEventListener('click', () => {
        const have = draft.groupBy.split(',').map(s => s.trim()).filter(Boolean);
        if (!have.includes(chip.dataset.gb)) have.push(chip.dataset.gb);

        draft.groupBy = have.join(', ');
        view.querySelector('[name=groupBy]').value = draft.groupBy;
        drawActions();
      }));
    };

    view.querySelector('#discover').addEventListener('click', async () => {
      if (!draft.connectionId) { notify('Pick a connection first.', 'err'); return; }
      if (!draft.indexPatterns.trim()) { notify('Enter at least one index pattern.', 'err'); return; }

      try {
        draft.fields = await api(
          `/api/connections/${draft.connectionId}/fields?patterns=${encodeURIComponent(draft.indexPatterns)}`);

        drawFields();
        drawConditions();

        // The discovered mapping is also where the sample.* placeholders come from, so the action forms
        // gain them the moment the fields are known.
        drawActions();
      } catch (error) {
        notify(error.message, 'err');
      }
    });

    // -- the condition ------------------------------------------------------

    view.querySelectorAll('[data-mode]').forEach(tab => tab.addEventListener('click', () => guard(async () => {
      const wanted = tab.dataset.mode;
      if (wanted === draft.mode) return;

      if (wanted === 'raw') {
        // Leaving the builder: compile once so the raw editor opens showing what the rows meant, rather
        // than whatever was last in the box.
        await compile();
        draft.mode = 'raw';
      } else {
        const read = await api('/api/rules/condition', {
          method: 'POST', body: { queryJson: draft.queryJson }
        });

        if (!read.representable) {
          notify('This query uses clauses the builder cannot show as rows. It stays here, unchanged.', 'err');
          return;
        }

        draft.conditions = read.conditions || [];
        draft.mode = 'builder';
      }

      render();
    })));

    // Compiling is the server's job, so this is debounced rather than run per keystroke. The query it
    // returns is what gets saved — there is no second compilation anywhere.
    let pending = null;

    const compile = async () => {
      if (draft.mode !== 'builder') return draft.queryJson;

      try {
        const result = await api('/api/rules/condition', {
          method: 'POST', body: { conditions: draft.conditions }
        });

        draft.queryJson = result.queryJson;
        draft.queryError = '';
      } catch (error) {
        draft.queryError = error.message;
      }

      showQuery();
      return draft.queryJson;
    };

    const compileSoon = () => {
      clearTimeout(pending);
      pending = setTimeout(() => compile(), 300);
    };

    const showQuery = () => {
      const box = view.querySelector('#queryout');
      if (!box) return;

      box.className = `query-out ${draft.queryError ? 'bad' : ''}`;
      box.textContent = draft.queryError
        || draft.queryJson
        || 'No condition — every event in the window matches.';
    };

    const drawConditions = () => {
      const box = view.querySelector('#condition');

      if (draft.mode === 'raw') {
        box.innerHTML = `
          <div class="field"><label>Query</label>
            <textarea name="queryJson" class="mono" rows="6" spellcheck="false"
              placeholder='{"term": {"event.type": "authentication_failed"}}'>${esc(draft.queryJson)}</textarea>
            <div class="hint">An Elasticsearch query clause. Leave it empty to match everything in the
              window — the time bound is always added for you.</div></div>
          ${previewControls()}`;

        box.querySelector('[name=queryJson]').addEventListener('input', e => {
          draft.queryJson = e.target.value;
        });

        wirePreview();
        return;
      }

      const known = (draft.fields?.fields || []).map(f => f.path);

      box.innerHTML = `
        <div id="rows">
          ${draft.conditions.map((row, i) => conditionRow(row, i, known)).join('')
            || '<div class="muted" style="font-size:13.5px;margin-bottom:10px">No condition. Every event in the window matches — add a row to narrow it.</div>'}
        </div>
        <datalist id="fieldnames">
          ${known.map(p => `<option value="${esc(p)}"></option>`).join('')}
        </datalist>
        <div class="row" style="margin:4px 0 14px">
          <button class="btn small" type="button" id="addcond">+ Add condition</button>
          ${draft.expects.length ? `<span class="muted" style="font-size:12.5px">
             This template expects: ${draft.expects.map(f => esc(f.path)).join(', ')}</span>` : ''}
        </div>

        <div class="field"><label>The query this will run</label>
          <div id="queryout" class="query-out"></div></div>

        ${previewControls()}`;

      showQuery();

      box.querySelector('#addcond').addEventListener('click', () => {
        draft.conditions.push({ field: '', operator: 'is', values: [''], kind: 'text' });
        drawConditions();
      });

      box.querySelectorAll('[data-drop-cond]').forEach(b => b.addEventListener('click', () => {
        draft.conditions.splice(+b.dataset.dropCond, 1);
        drawConditions();
        compileSoon();
      }));

      // The field decides what can be asked of it, so a new field redraws the row: picking a numeric
      // field and being offered "contains" would be offering a query that cannot work.
      box.querySelectorAll('[data-cond-field]').forEach(input => input.addEventListener('change', () => {
        const row = draft.conditions[+input.dataset.condField];
        row.field = input.value.trim();

        const described = fieldByPath(row.field);

        if (described) {
          // The mapping is the authority once it has been read. It can also invalidate the comparison
          // already chosen — "contains" against an integer is not a query anyone meant.
          row.kind = kindOfType(described.type);

          if (!OPERATORS[row.kind].some(([op]) => op === row.operator))
            row.operator = 'is';
        } else {
          row.kind = inferKind(row.values, row.operator);
        }

        drawConditions();
        compileSoon();
      }));

      box.querySelectorAll('[data-cond-op]').forEach(select => select.addEventListener('change', () => {
        const row = draft.conditions[+select.dataset.condOp];
        row.operator = select.value;

        const arity = arityOf(row.operator);
        row.values = arity === 0 ? [] : Array.from({ length: Math.max(arity, 1) }, (_, i) => row.values[i] || '');

        if (!fieldByPath(row.field)) row.kind = inferKind(row.values, row.operator);

        drawConditions();
        compileSoon();
      }));

      // Values do not redraw: typing would lose the cursor on every character.
      box.querySelectorAll('[data-cond-value]').forEach(input => input.addEventListener('input', () => {
        const [index, slot] = input.dataset.condValue.split('|');
        const row = draft.conditions[+index];

        if (row.operator === 'one_of') row.values = input.value.split(',').map(s => s.trim()).filter(Boolean);
        else row.values[+slot] = input.value;

        // Only while the mapping cannot answer. Once it has, what the field is does not change because
        // of what was typed into it — an account number written in digits is still a keyword.
        if (!fieldByPath(row.field)) {
          row.kind = inferKind(row.values, row.operator);

          const note = box.querySelector(`[data-guess="${index}"]`);

          if (note) {
            note.innerHTML = guessText(row);
            note.hidden = note.innerHTML === '';
          }
        }

        compileSoon();
      }));

      // The one-click fix for the commonest mistake: an exact match against an analysed text field
      // matches tokens, not the value, and the .keyword twin is what was meant.
      box.querySelectorAll('[data-keyword]').forEach(b => b.addEventListener('click', () => {
        draft.conditions[+b.dataset.keyword].field += '.keyword';
        drawConditions();
        compileSoon();
      }));

      wirePreview();
    };

    // Updated in place as the value is typed rather than by redrawing the row, which would take the
    // cursor with it. Blank when the mapping has answered, because then nothing was guessed.
    const guessText = (row) =>
      !fieldByPath(row.field) && row.field && row.kind !== 'text'
        ? `Treating this value as <strong>${row.kind === 'number' ? 'a number' : 'true or false'}</strong>. ` +
          'Discover fields to have the mapping decide instead of a guess.'
        : '';

    const conditionRow = (row, index, known) => {
      const arity = arityOf(row.operator);
      const described = fieldByPath(row.field);

      // Narrowed to what the field can answer once the mapping says what it is; everything on offer
      // until then. A shorter list is only helpful when it is right.
      const operators = described ? OPERATORS[kindOfType(described.type)] : OPERATORS.unknown;

      // Two different warnings, and they are not the same problem. One says the field is not in this
      // mapping at all — a template pointed at a name this estate does not use, or a typo. The other says
      // the field exists but an exact match on it will not behave the way it reads.
      const unknown = draft.fields && row.field && !known.includes(row.field);

      // Said out loud rather than assumed, because the difference decides whether 500 is written as a
      // number or as "500", and only one of those matches an integer field.
      const guessed = !described && row.field && row.kind !== 'text';

      const analysed = described && described.type === 'text' &&
        ['is', 'is_not', 'one_of'].includes(row.operator) &&
        known.includes(`${row.field}.keyword`);

      const value = (slot) => `
        <input data-cond-value="${index}|${slot}" value="${esc(row.values[slot] ?? '')}"
               placeholder="${slot === 0 && arity === 2 ? 'from' : arity === 2 ? 'to' : 'value'}">`;

      return `
        <div class="cond-row ${arity === 0 ? 'no-value' : arity === 2 ? 'two-values' : ''}">
          <input data-cond-field="${index}" list="fieldnames" value="${esc(row.field)}"
                 placeholder="field" ${described ? `title="${esc(described.type)}"` : ''}>
          <select data-cond-op="${index}">
            ${operators.map(([op, label]) =>
              `<option value="${op}" ${row.operator === op ? 'selected' : ''}>${esc(label)}</option>`).join('')}
          </select>
          ${arity === 0 ? '' : row.operator === 'one_of'
            ? `<input data-cond-value="${index}|0" value="${esc((row.values || []).join(', '))}"
                      placeholder="value, value, value">`
            : arity === 2 ? value(0) + value(1) : value(0)}
          <button class="btn small drop" type="button" data-drop-cond="${index}" title="Remove this row">&times;</button>
          ${unknown ? `<div class="cond-warn">Your indices have no field called
             <span class="mono">${esc(row.field)}</span>. Pick one from the list, or discover fields again.</div>` : ''}
          <div class="cond-warn" data-guess="${index}" ${guessed ? '' : 'hidden'}>${guessText(row)}</div>
          ${analysed ? `<div class="cond-warn">
             <span class="mono">${esc(row.field)}</span> is analysed text, so an exact match compares tokens
             rather than the whole value.
             <button class="btn small" type="button" data-keyword="${index}">Use ${esc(row.field)}.keyword</button></div>` : ''}
        </div>`;
    };

    // -- the preview --------------------------------------------------------

    const previewControls = () => `
      <div class="row" style="margin-bottom:10px">
        ${can('rules.test')
          ? `<button class="btn" type="button" id="testcond">Test condition</button>
             <select id="lookback" style="max-width:190px">
               ${LOOKBACKS.map(([m, label]) =>
                 `<option value="${m}" ${draft.lookback === m ? 'selected' : ''}>${label}</option>`).join('')}
             </select>`
          : ''}
        <span class="muted" style="font-size:12.5px">Reads events. Executes nothing.</span>
      </div>`;

    const wirePreview = () => {
      const test = view.querySelector('#testcond');
      if (!test) return;

      view.querySelector('#lookback').addEventListener('change', e => { draft.lookback = +e.target.value; });

      test.addEventListener('click', async () => {
        if (!draft.connectionId) { notify('Pick a connection first.', 'err'); return; }
        if (!draft.indexPatterns.trim()) { notify('Enter at least one index pattern.', 'err'); return; }

        test.disabled = true;
        test.textContent = 'Testing…';

        try {
          if (draft.mode === 'builder') await compile();

          draft.preview = await api('/api/rules/preview', {
            method: 'POST',
            body: {
              connectionId: draft.connectionId,
              indexPatterns: draft.indexPatterns.split(',').map(s => s.trim()).filter(Boolean),
              conditions: draft.mode === 'builder' ? draft.conditions : null,
              queryJson: draft.mode === 'builder' ? null : draft.queryJson,
              timestampField: draft.timestampField,
              groupBy: draft.groupBy.split(',').map(s => s.trim()).filter(Boolean),
              threshold: +draft.threshold || 0,
              lookbackMinutes: draft.lookback
            }
          });

          draft.previewError = '';
        } catch (error) {
          draft.preview = null;
          draft.previewError = error.message;
        } finally {
          test.disabled = false;
          test.textContent = 'Test condition';
          drawPreview();
        }
      });
    };

    const drawPreview = () => {
      const box = view.querySelector('#previewbox');

      if (draft.previewError) {
        box.innerHTML = `<div class="notice err">${esc(draft.previewError)}</div>`;
        return;
      }

      const result = draft.preview;
      if (!result) { box.innerHTML = ''; return; }

      const sample = (result.samples || [])[0];

      box.innerHTML = `
        <div class="card" style="background:var(--surface-2);margin-bottom:14px">
          <div class="spread" style="margin-bottom:10px">
            <h3 style="margin:0">What this matches right now</h3>
            <button class="btn small" type="button" id="hidepreview">Hide</button>
          </div>

          <div class="notice ${result.succeeded === false ? 'err' : result.wouldTrigger > 0 ? 'ok' : 'info'}"
               style="margin-bottom:12px">${esc(result.message)}</div>

          ${result.succeeded === false ? '' : `
            <div class="tiles">
              <div class="tile"><div class="n">${result.totalIsLowerBound ? '≥' : ''}${result.totalMatched}</div>
                <div class="k">Events matched</div></div>
              <div class="tile"><div class="n">${(result.groups || []).length}${result.groupsTruncated ? '+' : ''}</div>
                <div class="k">Subjects</div></div>
              <div class="tile ${result.wouldTrigger > 0 ? 'ok' : ''}"><div class="n">${result.wouldTrigger}</div>
                <div class="k">Reach the threshold</div></div>
            </div>

            ${(result.groups || []).length ? `
              <div class="scroller" style="margin-top:12px"><table>
                <thead><tr><th>Subject</th><th>Events</th><th></th></tr></thead>
                <tbody>${result.groups.map(g => `
                  <tr>
                    <td class="mono">${esc(Object.entries(g.key).map(([k, v]) => `${k}=${v}`).join('  '))}</td>
                    <td class="nowrap">${g.count}</td>
                    <td>${g.reachesThreshold ? '<span class="pill on">would fire</span>' : ''}</td>
                  </tr>`).join('')}</tbody>
              </table></div>` : ''}

            ${sample ? `
              <div style="margin-top:14px">
                <div style="font-size:11.5px;font-weight:700;color:var(--muted);margin-bottom:6px">
                  A MATCHING EVENT</div>
                <div class="sample-doc">
                  ${Object.entries(sample).slice(0, 40).map(([path, value]) => `
                    <div class="sample-line">
                      <span class="p">${esc(path)}</span>
                      <span class="v">${esc(Array.isArray(value) ? value.join(', ') : value)}</span>
                      <span class="acts">
                        <button class="btn small" type="button" data-narrow="${esc(path)}"
                                title="Add a condition matching this value">+ condition</button>
                        <button class="btn small" type="button" data-place="${esc(path)}"
                                title="Insert this field into the action you were editing">{{ }}</button>
                      </span>
                    </div>`).join('')}
                </div>
                <div class="hint">This is one of the events behind the numbers above — the most recent.
                  Clicking a field narrows the condition to that value, or drops its placeholder into
                  whichever action field you were last typing in.</div>
              </div>` : ''}`}
        </div>`;

      box.querySelector('#hidepreview').addEventListener('click', () => {
        draft.preview = null;
        drawPreview();
      });

      // Building the next condition out of a real event rather than out of memory. The .keyword twin is
      // preferred when the mapping has one, because that is what an exact match needs.
      box.querySelectorAll('[data-narrow]').forEach(b => b.addEventListener('click', () => {
        if (draft.mode !== 'builder') {
          notify('Switch to the builder to add rows from an event.', 'err');
          return;
        }

        const path = b.dataset.narrow;
        const value = sample[path];
        const exact = fieldByPath(`${path}.keyword`) ? `${path}.keyword` : path;
        const described = fieldByPath(path);

        draft.conditions.push({
          field: exact,
          operator: 'is',
          values: [String(Array.isArray(value) ? value[0] : value)],
          kind: described ? kindOfType(described.type) : 'text'
        });

        // No notification: the row appearing is the feedback, and notify() rebuilds the whole drawer,
        // which would throw away the scroll position on every click of a field.
        drawConditions();
        compileSoon();
      }));

      box.querySelectorAll('[data-place]').forEach(b => b.addEventListener('click', () => {
        insertPlaceholder(`sample.${b.dataset.place}`);
      }));
    };

    // -- action rows, generated from the published schema --------------------

    // What this rule's alerts will carry — the same list the API validates against, assembled from the
    // catalogue the backend publishes rather than from anything hard-coded here. Recomputed as the form
    // changes, because grouping by another field changes the answer.
    const placeholders = () => {
      const catalogue = state.data.placeholders || {};
      const groupBy = draft.groupBy.split(',').map(s => s.trim()).filter(Boolean);

      return [
        ...(catalogue.always || []),
        catalogue.message || 'message',
        ...((catalogue.evidence || {})[draft.strategyType] || []).map(k => `evidence.${k}`),
        ...groupBy.map(f => `event.${f}`),

        // What the registered enrichments will attach. Unlike sample.*, these are knowable in advance —
        // each enrichment declares the facts it produces — so they are offered rather than guessed at.
        ...(catalogue.enrich || []).flatMap(e => e.paths || []),

        // Fields of the log line itself. The API cannot enumerate these — which fields the one returned
        // event carries is not known until an alert is raised — but this form has already discovered the
        // real mapping, so it can offer them rather than leaving an author to guess at spelling.
        ...sampleFields()
      ];
    };

    // The mapping's own fields, minus the .keyword subfields that exist for aggregating rather than for
    // reading: a message wants ApiName, not ApiName.keyword. Capped, because a wide index has hundreds and
    // a wall of chips helps nobody.
    const sampleFields = () => {
      if (!draft.fields) return [];

      return draft.fields.fields
        .filter(f => !f.path.endsWith('.keyword'))
        .slice(0, 60)
        .map(f => `sample.${f.path}`);
    };

    // Which template field was last typed in, across the whole form. Held here rather than inside the
    // action editor so the preview's fields can reach it too.
    let lastFocused = null;

    const insertPlaceholder = (path) => {
      const target = lastFocused || view.querySelector('[data-setting]');

      if (!target) {
        notify('Add an action first — there is nowhere to put it yet.', 'err');
        return;
      }

      // The same insertion the menu performs. Clicking a chip used to write its braces blindly, which
      // is the same duplication by another route.
      placePlaceholder(target, path);
    };

    const drawActions = () => {
      const box = view.querySelector('#actions');

      if (draft.actions.length === 0) {
        box.innerHTML = '<div class="muted" style="font-size:13.5px">No actions. The rule will alert and do nothing else.</div>';
        return;
      }

      const available = placeholders();

      box.innerHTML = draft.actions.map((action, index) => {
        const schema = actionTypes.find(t => t.type === action.type);
        const usable = (state.data.connections || [])
          .filter(c => !schema || c.type === schema.requiredConnectionType);

        // Offered once per action rather than per field: clicking one appends it to whichever text field
        // was last focused, so an author writing a payload never has to remember the spelling of a path.
        const chips = available
          .map(p => `<button class="btn small" type="button" data-insert="${esc(p)}">${esc(p)}</button>`)
          .join('');

        return `
          <div class="card" style="margin-bottom:10px;background:var(--surface-2)">
            <div class="spread" style="margin-bottom:8px">
              <strong>${esc(schema?.displayName || action.type)}</strong>
              <button class="btn small danger" type="button" data-drop="${index}">Remove</button>
            </div>
            ${schema?.isDisruptive
              ? '<div class="notice warn" style="margin-bottom:10px">This changes a live system. The never-block list and the rate caps apply.</div>' : ''}
            <div class="field">
              <label><input type="checkbox" data-approval="${index}" style="width:auto;margin-right:6px"
                     ${action.requiresApproval ? 'checked' : ''}> Hold for approval before this runs</label>
              <div class="hint">The rule still fires and the alert is still raised; this action waits for a
                person instead of happening. Unanswered, it expires without being carried out. The actions
                after it can read <span class="mono">{{actions.${esc(action.type)}.status}}</span>, so a
                message can say that something is waiting rather than that it was done.</div></div>
            ${schema?.isReversible === false && action.requiresApproval
              ? '<div class="notice warn" style="margin-bottom:10px">This cannot be undone once it runs, which is the case approval is most worth having for.</div>' : ''}
            <div class="field"><label>Connection</label>
              <select data-conn="${index}">
                ${usable.length === 0
                  ? `<option value="">no ${esc(schema?.requiredConnectionType || '')} connection exists</option>` : ''}
                ${usable.map(c => `<option value="${esc(c.name)}" ${action.connection === c.name ? 'selected' : ''}>${esc(c.name)}</option>`).join('')}
              </select></div>
            <div class="grid2">
              ${(schema?.settings || []).map(s => `
                <div class="field" ${s.type === 'json' || s.type === 'template' ? 'style="grid-column:1/-1"' : ''}>
                  <label>${esc(s.label)}${s.required ? ' *' : ''}</label>
                  ${s.type === 'template'
                    ? `<textarea data-setting="${index}|${esc(s.key)}" rows="4" placeholder="${esc(s.default || '')}">${esc(action.settings?.[s.key] ?? '')}</textarea>`
                    : s.type === 'json'
                      ? `<textarea class="mono" data-setting="${index}|${esc(s.key)}" data-json="1" rows="7" spellcheck="false" placeholder='{ "to": "+98...", "text": "{{message}}" }'>${esc(action.settings?.[s.key] ?? '')}</textarea>`
                      : `<input data-setting="${index}|${esc(s.key)}" value="${esc(action.settings?.[s.key] ?? '')}" placeholder="${esc(s.default || '')}">`}
                  ${s.help ? `<div class="hint">${esc(s.help)}</div>` : ''}
                  ${s.type === 'json' ? `<div class="hint" data-jsonstate="${index}"></div>` : ''}
                </div>`).join('')}
            </div>
            <div class="field" style="margin-top:4px">
              <label>This rule's placeholders</label>
              <div class="chips" style="max-height:150px;overflow-y:auto">${chips}</div>
              <div class="hint">Type <span class="mono">{{</span> in any field above to search these
                without leaving the keyboard (<span class="mono">Ctrl</span>+<span class="mono">Space</span>
                also opens it); or click one to insert it where you were typing.
                <strong>event.</strong> is what the rule grouped by and is true of every event;
                <strong>sample.</strong> is one of the events behind the alert — the most recent — so its
                fields describe that line only. Values arrive as text; write a number or true/false
                directly if the gateway needs one.
                ${draft.fields ? '' : ' Discover fields above to be offered the log\'s own fields.'}</div>
            </div>
          </div>`;
      }).join('');

      box.querySelectorAll('[data-drop]').forEach(b => b.addEventListener('click', () => {
        draft.actions.splice(+b.dataset.drop, 1);
        drawActions();
      }));

      box.querySelectorAll('[data-conn]').forEach(input => input.addEventListener('change', () => {
        draft.actions[+input.dataset.conn].connection = input.value;
      }));

      box.querySelectorAll('[data-approval]').forEach(input => input.addEventListener('change', () => {
        draft.actions[+input.dataset.approval].requiresApproval = input.checked;
        drawActions();
      }));

      box.querySelectorAll('[data-setting]').forEach(input => {
        input.addEventListener('focus', () => { lastFocused = input; });

        // Read when the menu opens rather than captured now: grouping by another field changes what the
        // rule will carry, and the menu has to offer that without the action being redrawn first.
        attachPlaceholderMenu(input, placeholders);

        input.addEventListener('input', () => {
          const [index, key] = input.dataset.setting.split('|');
          draft.actions[+index].settings = draft.actions[+index].settings || {};
          draft.actions[+index].settings[key] = input.value;

          if (input.dataset.json) reportJson(input, index);
        });

        if (input.dataset.json) reportJson(input, input.dataset.setting.split('|')[0]);
      });

      box.querySelectorAll('[data-insert]').forEach(button => button.addEventListener('click', () => {
        insertPlaceholder(button.dataset.insert);
      }));

      // Says whether the body is usable while it is being typed. The API rejects a malformed one on
      // save; this is so an author sees the problem before then — and, where the problem is one this
      // console can recognise, hears it in words rather than as a character offset.
      function reportJson(input, index) {
        const note = box.querySelector(`[data-jsonstate="${index}"]`);
        if (!note) return;

        const verdict = describePayload(input.value);

        note.textContent = verdict.note;
        note.style.color = verdict.state === 'bad' ? 'var(--crit)' : '';

        // The field itself carries the verdict too, so a body that will not save is visible without
        // reading the line under it.
        input.style.borderColor = verdict.state === 'bad' ? 'var(--crit)' : '';
      }
    };

    view.querySelectorAll('[data-add]').forEach(button => button.addEventListener('click', () => {
      const schema = actionTypes.find(t => t.type === button.dataset.add);
      if (!schema) return;

      const settings = {};
      schema.settings.forEach(s => { if (s.default) settings[s.key] = s.default; });

      // A template's suggested message goes into the first action that takes one, copied rather than
      // referenced — so editing it later changes this rule and nothing else.
      const message = schema.settings.find(s => s.type === 'template');

      if (message && draft.suggestedMessage) settings[message.key] = draft.suggestedMessage;

      const first = (state.data.connections || []).find(c => c.type === schema.requiredConnectionType);

      draft.actions.push({
        type: schema.type, connection: first?.name || '', settings, requiresApproval: false
      });
      drawActions();
    }));

    drawFields();
    drawConditions();
    drawPreview();
    drawActions();

    // A rebuild — any notification causes one — discards the debounce timer that was going to refresh the
    // compiled query, and the box would then show a query older than the rows above it. Recompiling once
    // here keeps "the query this will run" true of what is on screen, whatever caused the redraw.
    if (draft.mode === 'builder' && draft.conditions.length > 0) compileSoon();

    // Changing the grouping or the strategy changes what an alert will carry, so the offered placeholders
    // have to follow. Redrawing keeps what is on screen equal to what the API will accept on save.
    ['[name=groupBy]', '[name=strategyType]'].forEach(selector =>
      view.querySelector(selector)?.addEventListener('change', drawActions));

    const close = () => { state.drawer = null; render(); };
    view.querySelector('#close').addEventListener('click', close);
    view.querySelector('#cancel').addEventListener('click', close);
    view.addEventListener('click', e => { if (e.target === view) close(); });

    view.querySelector('#form').addEventListener('submit', (event) => {
      event.preventDefault();

      const split = (value) => (value || '').split(',').map(s => s.trim()).filter(Boolean);

      guard(async () => {
        // A request body that is not JSON is refused here rather than by the API, so the message names
        // the action it belongs to. The API refuses it too — this is the earlier, clearer half.
        for (let i = 0; i < draft.actions.length; i++) {
          const schema = actionTypes.find(t => t.type === draft.actions[i].type);

          for (const setting of (schema?.settings || []).filter(s => s.type === 'json')) {
            const verdict = describePayload(draft.actions[i].settings?.[setting.key] || '');

            if (verdict.state === 'bad')
              throw new Error(`${schema.displayName} — ${setting.label}: ${verdict.note}`);
          }
        }

        // Compiled once more before saving, so a rule cannot be stored carrying a query older than the
        // rows on screen — the debounce means the last keystroke may not have reached the server yet.
        clearTimeout(pending);
        const queryJson = await compile();

        if (draft.queryError) throw new Error(draft.queryError);

        const body = {
          name: draft.name.trim(),
          description: draft.description || '',
          severity: draft.severity,
          connectionId: +draft.connectionId || 0,
          indexPatterns: split(draft.indexPatterns),
          queryJson: queryJson || '',
          timestampField: draft.timestampField || '@timestamp',
          strategyType: draft.strategyType,
          groupBy: split(draft.groupBy),
          threshold: +draft.threshold,
          windowSeconds: +draft.windowSeconds,
          queryDelaySeconds: +draft.queryDelaySeconds,
          intervalSeconds: +draft.intervalSeconds,
          cooldownSeconds: +draft.cooldownSeconds,
          actions: draft.actions,
          changeNote: draft.changeNote || null
        };

        if (identity) await api(`/api/rules/${identity.id}`, { method: 'PUT', body });
        else await api('/api/rules', { method: 'POST', body });

        close();
        notify(identity
          ? 'Saved as a new version.'
          : 'Rule created, disarmed. Rehearse it before arming it.');

        await load('rules');
      });
    });

    return view;
  };

  render();
}
