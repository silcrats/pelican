'use strict';
// Pelican admin portal. One page, routed on the URL hash. Everything shown
// comes from the API and is set with textContent, never as HTML.

const state = { me: null, sources: [], timer: null };

const LABELS = {
  server: ['Server', 'Host name or IP address of the file server.'],
  share: ['Share', 'Share name on that server.'],
  path: ['Folder', 'Folder inside the share, with backslashes, e.g. Finance\\Reports. Empty crawls the whole share.'],
  encrypt: ['Require encryption', 'Refuse to crawl unless SMB 3 encryption is used.'],
  acl_scope: ['Permission checks', '"directory": one lookup per folder (files inherit). "file": exact per-file lookups, slower.'],
  exclude_extensions: ['Skip extensions', 'One per line, without the dot. Replaces the global list for this source.'],
  exclude_no_extension: ['Skip files without an extension', ''],
  user: ['Mailbox', 'UPN or primary SMTP address.'],
  since: ['Only items since', 'Leave empty for everything.'],
  exclude_folders: ['Skip folders', 'One per line. Replaces the global list for this mailbox.'],
  full_access: ['Use Exchange Full Access', 'No: ignore who has Full Access and use only the grants below.'],
  archive: ['Online archive', 'Not supported yet: the crawl reports it as failed.'],
  url: ['Site URL', 'The site\'s full address, e.g. https://contoso.sharepoint.com/sites/Finance.'],
  libraries: ['Only these libraries', 'One per line. Empty: every document library.'],
  exclude_libraries: ['Skip libraries', 'One per line. Replaces the global list for this site.'],
  include_extensions: ['Only these extensions', 'One per line. Replaces the global list for this site.'],
  group: ['Microsoft 365 group', 'If it differs from the site URL name. Super admins only: it decides who can see the documents.'],
  mirror_members: ['Mirror group members', 'No: ignore the site\'s group and use only the grants below.'],
};
const KIND_SHORT = { smb: 'SMB', exchange: 'Mail', sharepoint: 'SharePoint' };
const JOB_LABELS = { crawl: 'Crawl', acl: 'ACL sync', test: 'Test', purge: 'Removal' };

// ---------------------------------------------------------------- helpers

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'hidden') el[k] = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (method !== 'GET') opts.headers['X-Pelican-Admin'] = '1';
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (e) { /* empty */ }
  if (res.status === 401 && path !== '/api/login') {
    showSignIn();
    throw new Error('Please sign in again.');
  }
  if (!res.ok) {
    const message = (data && data.error) || `Request failed (${res.status})`;
    throw new Error(message.charAt(0).toUpperCase() + message.slice(1));
  }
  return data;
}

function toast(message, bad) {
  const t = document.getElementById('toast');
  t.textContent = message;
  t.className = 'toast' + (bad ? ' bad' : '');
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, bad ? 7000 : 3500);
}

function when(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const secs = (Date.now() / 1000) - ts;
  let rel;
  if (secs < -60) rel = 'in ' + span(-secs);
  else if (secs < 60) rel = 'just now';
  else rel = span(secs) + ' ago';
  return { rel, abs: d.toLocaleString() };
}

function span(secs) {
  if (secs < 60) return Math.max(1, Math.round(secs)) + ' s';
  if (secs < 3600) return Math.round(secs / 60) + ' min';
  if (secs < 86400 * 2) return Math.round(secs / 3600) + ' h';
  return Math.round(secs / 86400) + ' days';
}

function timeEl(ts) {
  const w = when(ts);
  return w ? h('time', { title: w.abs }, w.rel) : '';
}

function every(minutes) {
  if (!minutes) return 'manual';
  if (minutes % 1440 === 0) return `every ${minutes / 1440} day${minutes === 1440 ? '' : 's'}`;
  if (minutes % 60 === 0) return `every ${minutes / 60} h`;
  return `every ${minutes} min`;
}

function statusChip(status) {
  const cls = { done: 'ok', failed: 'bad', running: 'run', queued: '', cancelled: 'warn' }[status] || '';
  return h('span', { class: 'chip ' + cls }, status);
}

function sourcePlace(s) {
  const c = s.config;
  if (s.kind === 'smb') return `\\\\${c.server}\\${c.share}${c.path ? '\\' + c.path : ''}`;
  if (s.kind === 'exchange') return c.user + (c.archive ? ' (archive)' : '');
  return c.url;
}

function setMain(...children) {
  const main = document.getElementById('main');
  main.replaceChildren(...children.filter(c => c !== null && c !== undefined && c !== false));
}

function scopeById(id) {
  return state.me.scopes.find(s => s.id === id);
}

// ---------------------------------------------------------- sign-in shell

function showSignIn() {
  state.me = null;
  clearInterval(state.timer);
  document.getElementById('app').hidden = true;
  document.getElementById('signin').hidden = false;
  document.querySelector('#signin-form input[name=username]').focus();
}

function showApp() {
  document.getElementById('signin').hidden = true;
  document.getElementById('app').hidden = false;
  document.getElementById('who-name').textContent =
    state.me.display_name + (state.me.super_admin ? ' · super admin' : '');
  document.getElementById('version').textContent = 'Pelican admin ' + state.me.version;
  const links = [['#/sources', 'Sources'], ['#/activity', 'Activity'], ['#/storage', 'Storage'], ['#/access', 'Access'], ['#/scopes', 'Scopes']];
  if (state.me.super_admin) {
    links.splice(3, 0, ['#/index', 'Index']);
    links.push(['#/credentials', 'Credentials'], ['#/settings', 'Settings']);
  }
  links.push(['#/audit', 'Audit log'], ['#/help', 'Help']);
  document.getElementById('nav').replaceChildren(...links.map(([href, text]) => h('a', { href }, text)));
  route();
}

document.getElementById('signin-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = ev.target;
  const err = document.getElementById('signin-error');
  err.hidden = true;
  const button = form.querySelector('button');
  button.disabled = true;
  try {
    state.me = await api('POST', '/api/login', { username: form.username.value, password: form.password.value });
    form.password.value = '';
    showApp();
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  } finally {
    button.disabled = false;
  }
});

document.getElementById('signout').addEventListener('click', async () => {
  try { await api('POST', '/api/logout'); } catch (e) { /* signed out anyway */ }
  showSignIn();
});

// ------------------------------------------------------------------ router

function route() {
  if (!state.me) return;
  clearInterval(state.timer);
  const hash = location.hash || '#/sources';
  for (const a of document.querySelectorAll('#nav a')) {
    a.classList.toggle('active', hash.startsWith(a.getAttribute('href')) ||
      (a.getAttribute('href') === '#/sources' && (hash.startsWith('#/source') || hash.startsWith('#/new'))));
  }
  const parts = hash.slice(2).split('/');
  const views = {
    sources: viewSources, source: () => viewSource(parseInt(parts[1], 10)), new: () => viewNew(parts[1]),
    activity: viewActivity, storage: viewStorage, index: viewIndex, access: () => viewAccess(decodeURIComponent(parts.slice(1).join('/'))), scopes: viewScopes, credentials: viewCredentials, settings: viewSettings, audit: viewAudit, help: viewHelp,
  };
  (views[parts[0]] || viewSources)().catch(e => setMain(h('p', { class: 'error' }, e.message)));
  document.getElementById('main').focus({ preventScroll: true });
}
window.addEventListener('hashchange', route);

// ---------------------------------------------------------------- sources

async function viewSources() {
  const filters = viewSources.filters || (viewSources.filters = { q: '', kind: '', scope: '' });
  const body = h('div');
  const search = h('input', { type: 'search', placeholder: 'Filter by name or location', value: filters.q,
    'aria-label': 'Filter sources', oninput: (e) => { filters.q = e.target.value; draw(); } });
  const kindSel = h('select', { 'aria-label': 'Source type', onchange: (e) => { filters.kind = e.target.value; draw(); } },
    h('option', { value: '' }, 'All types'),
    Object.entries(state.me.kind_info).map(([k, v]) => h('option', { value: k, selected: filters.kind === k }, v.label)));
  const scopeSel = h('select', { 'aria-label': 'Scope', onchange: (e) => { filters.scope = e.target.value; draw(); } },
    h('option', { value: '' }, 'All scopes'),
    state.me.super_admin ? h('option', { value: 'none', selected: filters.scope === 'none' }, 'No scope (super admins)') : null,
    state.me.scopes.map(s => h('option', { value: String(s.id), selected: filters.scope === String(s.id) }, s.name)));
  const addButton = state.me.kinds.length
    ? h('button', { class: 'primary', onclick: () => { location.hash = '#/new'; } }, 'Add source') : null;

  setMain(
    h('div', { class: 'pagehead' },
      h('div', { class: 'grow' }, h('h1', {}, 'Sources'),
        h('div', { class: 'muted' }, 'What Pelican crawls. Changes reach the crawlers on their next run.')),
      addButton),
    h('div', { class: 'toolbar' }, search, kindSel, scopeSel),
    body);

  async function load() {
    state.sources = await api('GET', '/api/sources');
    draw();
  }

  function draw() {
    const q = filters.q.trim().toLowerCase();
    const rows = state.sources.filter(s =>
      (!filters.kind || s.kind === filters.kind) &&
      (!filters.scope || (filters.scope === 'none' ? s.scope_id === null : String(s.scope_id) === filters.scope)) &&
      (!q || s.name.toLowerCase().includes(q) || sourcePlace(s).toLowerCase().includes(q)));
    if (!state.sources.length) {
      body.replaceChildren(h('div', { class: 'tablewrap' }, h('div', { class: 'empty' },
        state.me.kinds.length ? 'No sources yet. Add one to start crawling.' : 'You have no sources to manage yet.')));
      return;
    }
    body.replaceChildren(h('div', { class: 'tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Name', 'Location', 'Scope', 'Schedule', 'Last crawl', ''].map((t, i) =>
        h('th', { class: i >= 1 && i <= 3 ? 'hide-sm' : null }, t)))),
      h('tbody', {}, rows.length ? rows.map(sourceRow) :
        h('tr', {}, h('td', { colspan: 6, class: 'empty' }, 'No sources match.'))))));
  }

  function sourceRow(s) {
    const crawl = s.jobs.crawl;
    const last = s.jobs.last_crawl;
    let lastCell;
    if (s.removing) lastCell = h('span', { class: 'chip warn' }, 'removing');
    else if (crawl && (crawl.status === 'running' || crawl.status === 'queued'))
      lastCell = [statusChip(crawl.status), ' ', last ? timeEl(last.finished_at) : ''];
    else if (last) lastCell = [statusChip(last.status), ' ', timeEl(last.finished_at)];
    else lastCell = h('span', { class: 'muted' }, 'never');
    const busy = s.removing || !s.enabled || (crawl && (crawl.status === 'running' || crawl.status === 'queued'));
    return h('tr', {},
      h('td', {}, h('a', { href: `#/source/${s.id}` }, s.name), h('br'),
        h('span', { class: 'kind' }, KIND_SHORT[s.kind]), ' ',
        s.enabled ? null : h('span', { class: 'chip warn' }, s.removing ? 'removing' : 'disabled'),
        h('div', { class: 'loc show-sm' }, sourcePlace(s))),
      h('td', { class: 'loc hide-sm' }, sourcePlace(s)),
      h('td', { class: 'hide-sm' }, s.scope_name || h('span', { class: 'muted' }, '—')),
      h('td', { class: 'hide-sm' }, every(s.crawl_minutes), s.kind === 'smb' && s.acl_minutes
        ? h('div', { class: 'muted' }, 'ACLs ' + every(s.acl_minutes)) : null),
      h('td', {}, lastCell),
      h('td', { class: 'actions' },
        h('button', { class: 'small', disabled: busy, onclick: () => runJob(s, 'crawl', load) }, 'Crawl now'),
        h('button', { class: 'small', disabled: s.removing, onclick: () => runJob(s, 'test', load) }, 'Test')));
  }

  await load();
  state.timer = setInterval(() => { if (!document.hidden) load().catch(() => {}); }, 15000);
}

async function runJob(source, type, after) {
  try {
    await api('POST', `/api/sources/${source.id}/jobs`, { type });
    toast(`${JOB_LABELS[type]} queued for ${source.name}. A worker picks it up shortly.`);
    if (after) await after();
  } catch (e) {
    toast(e.message, true);
  }
}

// ------------------------------------------------------------- source form

function fieldInput(kind, key, spec, value, opts) {
  const [label, help] = LABELS[key] || [key, ''];
  const disabled = (opts.editing && spec.fixed) || (spec.super_admin && !state.me.super_admin);
  let input;
  const id = 'f-' + key;
  if (spec.type === 'bool') {
    input = h('select', { id, name: key, disabled },
      h('option', { value: '' }, 'Default'),
      h('option', { value: 'true', selected: value === true }, 'Yes'),
      h('option', { value: 'false', selected: value === false }, 'No'));
  } else if (spec.type === 'choice') {
    input = h('select', { id, name: key, disabled }, h('option', { value: '' }, 'Default'),
      spec.choices.map(c => h('option', { value: c, selected: value === c }, c)));
  } else if (spec.type === 'list') {
    input = h('textarea', { id, name: key, disabled, placeholder: 'Default', value: (value || []).join('\n') });
  } else if (spec.type === 'date') {
    input = h('input', { id, name: key, type: 'date', disabled, value: value || '' });
  } else {
    input = h('input', { id, name: key, disabled, value: value || '', required: spec.required && !disabled,
      autocomplete: 'off', list: opts.datalist && opts.datalist[key] ? 'dl-' + key : null });
  }
  return h('div', {},
    h('label', { for: id }, label, input),
    help ? h('div', { class: 'help' }, help) : null,
    opts.datalist && opts.datalist[key]
      ? h('datalist', { id: 'dl-' + key }, opts.datalist[key].map(v => h('option', { value: v }))) : null);
}

function readField(form, key, spec) {
  const el = form.elements[key];
  if (!el) return undefined;
  const v = el.value;
  if (spec.type === 'bool') return v === '' ? null : v === 'true';
  if (spec.type === 'list') {
    const items = v.split('\n').map(s => s.trim()).filter(Boolean);
    return items.length ? items : null;
  }
  return v.trim() || null;
}

function scheduleInput(name, minutes, label, help) {
  let unit = 'hours', n = minutes / 60;
  if (!minutes) { unit = 'manual'; n = ''; }
  else if (minutes % 1440 === 0) { unit = 'days'; n = minutes / 1440; }
  else if (minutes % 60 !== 0) { unit = 'minutes'; n = minutes; }
  const num = h('input', { type: 'number', min: 1, name: name + '_n', value: n, disabled: unit === 'manual',
    'aria-label': label + ' interval' });
  const sel = h('select', { name: name + '_u', 'aria-label': label + ' unit', onchange: () => {
    num.disabled = sel.value === 'manual';
    if (!num.disabled && !num.value) num.value = 1;
  } }, ['minutes', 'hours', 'days', 'manual'].map(u => h('option', { value: u, selected: u === unit },
    u === 'manual' ? 'manual only' : u)));
  return h('div', {}, h('label', {}, label, h('div', { class: 'sched' }, h('span', { class: 'muted' }, 'every'), num, sel)),
    help ? h('div', { class: 'help' }, help) : null);
}

function readSchedule(form, name) {
  const unit = form.elements[name + '_u'].value;
  if (unit === 'manual') return 0;
  const n = parseInt(form.elements[name + '_n'].value, 10) || 0;
  return n * { minutes: 1, hours: 60, days: 1440 }[unit];
}

function grantsBlock(kind, perms, scope) {
  const allowed = (gk) => scope ? scope['grant_' + gk] : null;
  const block = (gk, label, help) => h('div', {},
    h('label', { for: 'g-' + gk }, label,
      h('textarea', { id: 'g-' + gk, name: 'grant_' + gk, value: ((perms || {})[gk] || []).join('\n') })),
    h('div', { class: 'help' }, help,
      !state.me.super_admin && scope ? (allowed(gk).length
        ? ` Allowed in ${scope.name}: ${allowed(gk).join(', ')}.` : ` ${scope.name} allows none.`) : ''));
  return h('div', { class: 'panel' },
    h('h3', {}, 'Extra access'),
    h('p', { class: 'muted' }, kind === 'exchange'
      ? 'Added on top of the people with Full Access to the mailbox.'
      : 'Added on top of the members of the site\'s Microsoft 365 group.'),
    h('div', { class: 'grid' },
      block('users', 'Users', 'AD usernames, one per line.'),
      block('groups', 'Groups', 'AD group names, one per line (direct members only).'),
      block('roles', 'Roles', 'Named roles, one per line.')));
}

function sourceForm(kind, source, onSaved) {
  const editing = !!source;
  const info = state.me.kind_info[kind];
  const cfg = editing ? source.config : {};
  const usableScopes = state.me.super_admin ? state.me.scopes : state.me.scopes.filter(s => s.kinds.includes(kind));
  const form = h('form', { novalidate: true });

  const scopeSel = h('select', { name: 'scope_id', id: 'f-scope', disabled: editing && !state.me.super_admin,
    onchange: () => redrawGrants() },
    state.me.super_admin ? h('option', { value: '' }, 'No scope (super admins only)') : null,
    usableScopes.map(s => h('option', { value: String(s.id), selected: editing && source.scope_id === s.id }, s.name)));

  const currentScope = () => scopeById(scopeSel.value ? parseInt(scopeSel.value, 10) : null);
  const datalist = {};
  if (kind === 'smb') {
    const servers = new Set();
    for (const s of usableScopes) for (const v of s.smb_servers) servers.add(v);
    datalist.server = [...servers];
  }

  const general = h('div', { class: 'grid' },
    h('div', {}, h('label', { for: 'f-name' }, 'Name',
      h('input', { id: 'f-name', name: 'name', value: editing ? source.name : '', disabled: editing, required: true,
        autocomplete: 'off', pattern: '[A-Za-z0-9][A-Za-z0-9_.\\-]{0,63}' })),
      h('div', { class: 'help' }, editing ? 'Fixed: it is on every document this source indexed.'
        : 'Shown as the source in search. Letters, digits, . _ -; unique across all types.')),
    h('div', {}, h('label', { for: 'f-scope' }, 'Scope', scopeSel),
      h('div', { class: 'help' }, 'Who besides super admins can manage this source.')),
    h('div', {}, h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'enabled',
      checked: editing ? source.enabled : true }), 'Crawl this source'),
      h('div', { class: 'help' }, 'Disabled: no crawls, but its documents stay searchable.')));

  const fieldsGrid = h('div', { class: 'grid' },
    Object.entries(info.fields).map(([key, spec]) => fieldInput(kind, key, spec, cfg[key], { editing, datalist })));

  let credSel = null;
  if (kind === 'smb') {
    const allowedCreds = () => {
      const sc = currentScope();
      if (state.me.super_admin) return ['default', ...state.me.credentials];
      return sc ? sc.credentials : [];
    };
    credSel = h('select', { name: 'credential', id: 'f-cred' });
    const fillCreds = () => {
      const chosen = credSel.value || (editing ? (source.credential || 'default') : 'default');
      credSel.replaceChildren(...allowedCreds().map(c => h('option', { value: c, selected: c === chosen },
        c === 'default' ? 'Default crawl account' : c)));
    };
    fillCreds();
    scopeSel.addEventListener('change', fillCreds);
    fieldsGrid.append(h('div', {}, h('label', { for: 'f-cred' }, 'Crawl account', credSel),
      h('div', { class: 'help' }, 'A credential profile: which environment variables on the workers hold the account.')));
  }

  const schedGrid = h('div', { class: 'grid' },
    scheduleInput('crawl', editing ? source.crawl_minutes : state.me.defaults.crawl_minutes, 'Crawl',
      'Each crawl only fetches what changed.'),
    kind === 'smb' ? scheduleInput('acl', editing ? source.acl_minutes : state.me.defaults.acl_minutes,
      'Permission sync', 'Re-reads folder permissions without downloading files.') : null);

  const grantsHolder = h('div');
  function redrawGrants() {
    if (info.permissions) grantsHolder.replaceChildren(grantsBlock(kind, cfg.permissions, currentScope()));
  }
  redrawGrants();

  const err = h('p', { class: 'error', role: 'alert', hidden: true });
  const save = h('button', { type: 'submit', class: 'primary' }, editing ? 'Save changes' : 'Add source');
  form.append(
    h('div', { class: 'panel' }, h('h3', {}, 'General'), general),
    h('div', { class: 'panel' }, h('h3', {}, info.label), fieldsGrid),
    grantsHolder,
    h('div', { class: 'panel' }, h('h3', {}, 'Schedule'), schedGrid),
    err,
    h('div', { class: 'formactions' }, save,
      h('button', { type: 'button', onclick: () => { location.hash = editing ? `#/source/${source.id}` : '#/sources'; } },
        'Cancel')));

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    err.hidden = true;
    const config = {};
    for (const [key, spec] of Object.entries(info.fields)) {
      const v = readField(form, key, spec);
      if (v !== null && v !== undefined) config[key] = v;
    }
    if (editing) {
      // Keep settings an import carried that this form doesn't show.
      for (const [k, v] of Object.entries(source.config)) {
        if (!(k in info.fields) && k !== 'permissions') config[k] = v;
      }
    }
    if (info.permissions) {
      const perms = {};
      for (const gk of ['users', 'groups', 'roles']) {
        const items = form.elements['grant_' + gk].value.split('\n').map(s => s.trim()).filter(Boolean);
        if (items.length) perms[gk] = items;
      }
      config.permissions = perms;
    }
    const body = {
      kind, config,
      scope_id: scopeSel.value ? parseInt(scopeSel.value, 10) : null,
      enabled: form.elements.enabled.checked,
      crawl_minutes: readSchedule(form, 'crawl'),
    };
    if (!editing) body.name = form.elements.name.value.trim();
    if (kind === 'smb') {
      body.acl_minutes = readSchedule(form, 'acl');
      body.credential = credSel.value;
    }
    save.disabled = true;
    try {
      const saved = editing ? await api('PUT', `/api/sources/${source.id}`, body) : await api('POST', '/api/sources', body);
      toast(editing ? 'Saved.' : `Added ${saved.name}.`);
      onSaved(saved);
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
      err.scrollIntoView({ block: 'nearest' });
    } finally {
      save.disabled = false;
    }
  });
  return form;
}

async function viewNew(kind) {
  const kinds = state.me.kinds;
  if (!kinds.length) return setMain(h('p', {}, 'None of your scopes can hold new sources.'));
  if (!kinds.includes(kind)) kind = kinds[0];
  const picker = h('div', { class: 'toolbar' }, kinds.map(k =>
    h('button', { class: k === kind ? 'primary' : '', type: 'button', onclick: () => { location.hash = `#/new/${k}`; } },
      state.me.kind_info[k].label)));
  setMain(
    h('div', { class: 'pagehead' }, h('div', { class: 'grow' },
      h('a', { href: '#/sources' }, '← Sources'), h('h1', {}, 'Add a source'))),
    picker,
    sourceForm(kind, null, (saved) => { location.hash = `#/source/${saved.id}`; }));
}

// ----------------------------------------------------------- source detail

async function viewSource(id) {
  const s = await api('GET', `/api/sources/${id}`);
  const info = state.me.kind_info[s.kind];
  const scope = scopeById(s.scope_id);
  const editing = viewSource.editing === id;
  viewSource.editing = null;

  const reload = () => viewSource(id);
  const busy = (type) => s.jobs.some(j => j.type === type && (j.status === 'queued' || j.status === 'running'));
  const removal = h('div');
  const removeButton = h('button', { class: 'danger', disabled: s.removing, onclick: () => {
    if (removal.firstChild) { removal.replaceChildren(); return; }
    removal.replaceChildren(removalPanel(s, () => removal.replaceChildren()));
    removal.querySelector('input').focus();
  } }, 'Remove source…');
  const actions = h('div', { class: 'toolbar' },
    h('button', { disabled: s.removing || !s.enabled, onclick: () => runJob(s, 'crawl', refresh) }, 'Crawl now'),
    s.kind === 'smb' ? h('button', { disabled: s.removing || !s.enabled, onclick: () => runJob(s, 'acl', refresh) },
      'Sync permissions') : null,
    h('button', { disabled: s.removing, onclick: () => runJob(s, 'test', refresh) }, 'Test connection'),
    h('button', { disabled: s.removing, onclick: () => { viewSource.editing = id; reload(); } }, 'Edit'),
    h('span', { class: 'spacer' }),
    removeButton);

  const head = h('div', { class: 'pagehead' }, h('div', { class: 'grow' },
    h('a', { href: '#/sources' }, '← Sources'),
    h('h1', {}, s.name),
    h('div', { class: 'muted' }, info.label, ' · ', h('span', { class: 'loc' }, sourcePlace(s)),
      s.removing ? h('span', {}, ' · ', h('span', { class: 'chip warn' }, 'being removed'))
        : (s.enabled ? '' : h('span', {}, ' · ', h('span', { class: 'chip warn' }, 'disabled'))))));

  if (editing) {
    return setMain(head, sourceForm(s.kind, s, () => reload()));
  }

  const facts = h('dl', { class: 'facts' },
    h('dt', {}, 'Scope'), h('dd', {}, scope ? scope.name : (s.scope_id ? `#${s.scope_id}` : 'none (super admins only)')),
    s.storage_available ? [h('dt', {}, 'In the index'), h('dd', {}, s.storage
      ? [`${s.storage.docs.toLocaleString()} documents · about ${fmtBytes(s.storage.est_index_bytes)} · `,
         h('a', { href: '#/storage' }, 'storage')]
      : h('span', { class: 'muted' }, 'no documents yet'))] : null,
    h('dt', {}, 'Crawl'), h('dd', {}, every(s.crawl_minutes)),
    s.kind === 'smb' ? [h('dt', {}, 'Permission sync'), h('dd', {}, every(s.acl_minutes))] : null,
    s.kind === 'smb' ? [h('dt', {}, 'Crawl account'), h('dd', {}, s.credential || 'default')] : null,
    Object.entries(s.config).filter(([k]) => !['server', 'share', 'path', 'user', 'url'].includes(k)).map(([k, v]) =>
      [h('dt', {}, (LABELS[k] || [k])[0]), h('dd', {}, k === 'permissions'
        ? Object.entries(v).map(([gk, vals]) => `${gk}: ${vals.join(', ')}`).join('; ')
        : Array.isArray(v) ? v.join(', ') : String(v))]),
    h('dt', {}, 'Added'), h('dd', {}, s.created_by || '', ' ', timeEl(s.created_at)),
    h('dt', {}, 'Last changed'), h('dd', {}, s.updated_by || '', ' ', timeEl(s.updated_at)));

  // Refreshed in place, so an open log stays open (and keeps updating).
  const openLogs = new Set();
  const tbody = h('tbody');
  function drawJobs(jobs) {
    tbody.replaceChildren(...(jobs.length ? jobs.flatMap(j => jobRow(j, openLogs, refresh)) :
      [h('tr', {}, h('td', { colspan: 7, class: 'empty' }, 'No jobs yet.'))]));
  }
  async function refresh() {
    const now = await api('GET', `/api/sources/${id}`);
    if (now.removing !== s.removing || now.enabled !== s.enabled) return reload();
    s.jobs = now.jobs;
    drawJobs(now.jobs);
    actions.querySelectorAll('button').forEach(b => {
      if (b.textContent === 'Crawl now') b.disabled = s.removing || !s.enabled || busy('crawl');
      if (b.textContent === 'Sync permissions') b.disabled = s.removing || !s.enabled || busy('acl');
    });
  }
  drawJobs(s.jobs);

  const removing = s.removing
    ? h('div', { class: 'panel danger' }, h('h3', {}, 'Being removed'),
        h('p', {}, 'A worker is deleting this source\'s documents from the index. It disappears from this list when that finishes.'))
    : null;

  setMain(head, actions, removal, removing,
    h('div', { class: 'panel' }, facts,
      h('details', {}, h('summary', {}, 'As the crawler sees it (YAML)'), h('pre', {}, s.rendered))),
    h('h2', {}, 'Jobs'),
    h('div', { class: 'tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Job', 'Status', 'Requested', 'Started', 'Took', 'Result', ''].map(t => h('th', {}, t)))),
      tbody)));

  state.timer = setInterval(() => {
    if (document.hidden || !s.jobs.some(j => j.status === 'running' || j.status === 'queued')) return;
    refresh().catch(() => {});
  }, 5000);
}

function jobRow(j, openLogs, refresh) {
  const live = j.status === 'running' || j.status === 'queued';
  const took = j.started_at && j.finished_at ? span(j.finished_at - j.started_at)
    : (j.started_at ? span(Date.now() / 1000 - j.started_at) + ' so far' : '');
  const pre = h('pre', {}, '');
  const logRow = h('tr', { hidden: !openLogs.has(j.id) }, h('td', { colspan: 7 }, pre));
  async function loadLog() {
    const full = await api('GET', `/api/jobs/${j.id}`);
    const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 4;
    pre.textContent = full.log || (live ? '(no output yet)' : '(no output)');
    if (atBottom) pre.scrollTop = pre.scrollHeight;   // follow new output unless scrolled up
  }
  if (openLogs.has(j.id)) loadLog().catch(() => {});
  const toggle = h('button', { class: 'small', onclick: async () => {
    if (openLogs.has(j.id)) {
      openLogs.delete(j.id);
      logRow.hidden = true;
      toggle.textContent = 'Log';
      return;
    }
    openLogs.add(j.id);
    logRow.hidden = false;
    toggle.textContent = 'Hide log';
    pre.textContent = 'Loading…';
    await loadLog().catch(e => toast(e.message, true));
    pre.scrollTop = pre.scrollHeight;
  } }, openLogs.has(j.id) ? 'Hide log' : 'Log');
  const cancellable = live && j.type !== 'purge';
  return [h('tr', {},
    h('td', {}, JOB_LABELS[j.type] || j.type),
    h('td', {}, statusChip(j.status), j.cancel && j.status === 'running' ? h('span', { class: 'muted' }, ' stopping') : null),
    h('td', {}, j.requested_by, h('br'), h('span', { class: 'muted' }, timeEl(j.created_at))),
    h('td', {}, j.started_at ? timeEl(j.started_at) : '', j.worker ? h('div', { class: 'muted' }, j.worker) : null),
    h('td', {}, took),
    h('td', { class: live ? 'run' : null }, j.summary || (j.status === 'running' ? 'starting…' : '')),
    h('td', { class: 'actions' }, toggle,
      cancellable ? h('button', { class: 'small', onclick: async () => {
        try { await api('POST', `/api/jobs/${j.id}/cancel`); toast('Cancelling.'); refresh(); }
        catch (e) { toast(e.message, true); }
      } }, 'Cancel') : null)), logRow];
}

function removalPanel(s, close) {
  const count = h('span', { class: 'muted' }, 'Counting documents…');
  api('GET', `/api/sources/${s.id}/count`).then(r => {
    count.textContent = r.count === null ? 'The document count isn\'t available.'
      : `${r.count.toLocaleString()} document${r.count === 1 ? '' : 's'} will be deleted from the index.`;
  }).catch(() => { count.textContent = 'The document count isn\'t available.'; });
  const confirmInput = h('input', { placeholder: s.name, autocomplete: 'off', 'aria-label': 'Type the source name to confirm' });
  const button = h('button', { class: 'danger solid', disabled: true }, 'Remove source and its documents');
  confirmInput.addEventListener('input', () => { button.disabled = confirmInput.value !== s.name; });
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      await api('DELETE', `/api/sources/${s.id}`, { confirm: confirmInput.value });
      toast(`Removing ${s.name}.`);
      viewSource(s.id);
    } catch (e) {
      toast(e.message, true);
      button.disabled = false;
    }
  });
  return h('div', { class: 'panel danger' }, h('h3', {}, 'Remove this source'),
    h('p', {}, 'Stops crawling it and deletes everything it indexed. To stop crawling but keep the documents searchable, ',
      'edit it and untick "Crawl this source" instead.'),
    h('p', {}, count),
    h('div', { class: 'toolbar' }, h('label', {}, 'Type ', h('code', {}, s.name), ' to confirm', confirmInput)),
    h('div', { class: 'formactions' }, button, h('button', { onclick: close }, 'Cancel')));
}

// ---------------------------------------------------------------- activity

async function viewActivity() {
  const workersBox = h('div');
  const jobsBox = h('div');
  setMain(h('div', { class: 'pagehead' }, h('div', { class: 'grow' }, h('h1', {}, 'Activity'),
    h('div', { class: 'muted' }, 'Queued, running and recent jobs for the sources you manage.'))), workersBox, jobsBox);

  function slotsSelect(value, withDefault, max, label, onchange) {
    const options = [];
    if (withDefault) options.push(h('option', { value: '' }, `Default (${withDefault})`));
    for (let n = 1; n <= max; n++) options.push(h('option', { value: String(n) }, String(n)));
    const sel = h('select', { class: 'inline', 'aria-label': label }, options);
    sel.value = value === null ? '' : String(value);
    sel.addEventListener('change', () => onchange(sel.value === '' ? null : parseInt(sel.value, 10), sel));
    return sel;
  }

  async function save(path, slots, sel, what) {
    sel.disabled = true;
    try {
      await api('PUT', path, { slots });
      toast(`${what} saved. Workers pick it up within a few seconds.`);
      await load(true);
    } catch (e) {
      toast(e.message, true);
      await load(true);
    }
  }

  function drawWorkers(a) {
    const intro = h('p', {}, 'Each worker runs up to ',
      slotsSelect(a.default_slots, null, a.max_slots, 'Default jobs at once',
        (n, sel) => save('/api/workers/default', n, sel, 'Default')),
      ' jobs at once, unless it has its own setting below.');
    const table = a.workers.length ? h('div', { class: 'tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Worker', 'Running', 'Jobs at once', 'Last seen', 'Version'].map(t => h('th', {}, t)))),
      h('tbody', {}, a.workers.map(w => {
        const stale = a.now - w.last_seen > 120;
        return h('tr', {},
          h('td', {}, w.name),
          h('td', {}, String(w.running)),
          h('td', {}, slotsSelect(w.own_slots ? w.slots : null, a.default_slots, a.max_slots, `Jobs at once on ${w.name}`,
            (n, sel) => save(`/api/workers/${encodeURIComponent(w.name)}`, n, sel, `${w.name}'s setting`))),
          h('td', { class: stale ? 'warn' : '' }, timeEl(w.last_seen), stale ? ' (not responding)' : ''),
          h('td', {}, w.version || ''));
      }))))
      : h('p', { class: 'warn' }, 'No worker has checked in. Jobs wait until one does: start a pelican-worker container.');
    workersBox.replaceChildren(h('h2', {}, 'Workers'), intro, table,
      h('p', { class: 'help' }, 'To add workers, scale the worker service: ',
        h('code', {}, 'docker compose … up -d --scale worker=3'), '. Workers not heard from for an hour leave this list.'));
  }

  function drawJobs(a) {
    const order = { running: 0, queued: 1 };
    a.jobs.sort((x, y) => (order[x.status] ?? 2) - (order[y.status] ?? 2) || y.id - x.id);
    jobsBox.replaceChildren(h('h2', {}, 'Jobs'), h('div', { class: 'tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Source', 'Job', 'Status', 'Requested', 'Started', 'Result'].map(t => h('th', {}, t)))),
      h('tbody', {}, a.jobs.length ? a.jobs.map(j => h('tr', {},
        h('td', {}, h('a', { href: `#/source/${j.source_id}` }, j.source_name), ' ',
          h('span', { class: 'kind' }, KIND_SHORT[j.kind])),
        h('td', {}, JOB_LABELS[j.type] || j.type),
        h('td', {}, statusChip(j.status)),
        h('td', {}, j.requested_by, ' ', h('span', { class: 'muted' }, timeEl(j.created_at))),
        h('td', {}, timeEl(j.started_at), j.worker ? h('span', { class: 'muted' }, ' on ' + j.worker) : ''),
        h('td', { class: j.status === 'running' ? 'run' : null }, j.summary || '')))
        : h('tr', {}, h('td', { colspan: 6, class: 'empty' }, 'Nothing in the last week.'))))));
  }

  async function load(force) {
    const a = await api('GET', '/api/activity');
    // Not while someone is choosing a setting: a redraw would close the list.
    if (state.me.super_admin && (force || !workersBox.contains(document.activeElement))) drawWorkers(a);
    drawJobs(a);
  }
  await load(true);
  state.timer = setInterval(() => { if (!document.hidden) load().catch(() => {}); }, 10000);
}

// ----------------------------------------------------------------- storage

function fmtBytes(n) {
  if (n === null || n === undefined || isNaN(n)) return '–';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (Math.abs(n) >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? Math.round(n) : n.toFixed(n >= 100 ? 0 : 1)) + ' ' + units[i];
}

const HOST_KIND = { 'smb-share': 'smb', 'exchange-online': 'exchange', 'sharepoint-online': 'sharepoint' };

async function viewStorage() {
  const body = h('div');
  const refreshButton = state.me.super_admin ? h('button', { onclick: async () => {
    refreshButton.disabled = true;
    try {
      await api('POST', '/api/storage/refresh');
      toast('Refreshing. New figures appear in a minute or so.');
      setTimeout(() => load().catch(() => {}), 15000);
    } catch (e) {
      toast(e.message, true);
      refreshButton.disabled = false;
    }
  } }, 'Refresh now') : null;
  setMain(h('div', { class: 'pagehead' }, h('div', { class: 'grow' }, h('h1', {}, 'Storage'),
    h('div', { class: 'muted' }, state.me.super_admin
      ? 'How much of the index and the disk each source takes, and how fast it grows.'
      : 'How much of the index your sources take.')), refreshButton), body);

  async function load() {
    const d = await api('GET', '/api/storage');
    if (!d.available) {
      body.replaceChildren(h('div', { class: 'panel empty' },
        'Storage figures aren\'t set up: the portal needs OS_HOST and a read-only OpenSearch account.'));
      return;
    }
    if (!d.updated) {
      body.replaceChildren(h('div', { class: 'panel empty' }, d.error
        ? `Couldn't read the storage figures: ${d.error}` : 'Collecting the first figures…'));
      return;
    }
    const parts = [];
    if (d.error) parts.push(h('p', { class: 'warn' }, `Last refresh failed, showing older figures: ${d.error}`));
    if (state.me.super_admin && d.index_bytes !== undefined) {
      const used = d.disk_total - d.disk_free;
      const usedPct = d.disk_total ? 100 * used / d.disk_total : 0;
      const g = d.growth;
      parts.push(h('div', { class: 'stats' },
        stat('Index', fmtBytes(d.index_bytes), `${d.docs.toLocaleString()} documents · avg ` +
          fmtBytes(d.docs ? d.index_bytes / d.docs : 0) +
          (d.deleted_docs ? ` · ${d.deleted_docs.toLocaleString()} deleted index entries, freed on merge` : '')),
        stat('Disk', `${usedPct.toFixed(0)}% used`, `${fmtBytes(used)} of ${fmtBytes(d.disk_total)} · ` +
          `${fmtBytes(d.disk_free)} free`, usedPct >= 85 ? 'warn' : ''),
        stat('Growth', g ? `${fmtBytes(g.index_bytes_per_day)}/day` : '–', g
          ? `over ${g.window_days} days` + (g.days_until_full ? ` · disk full in about ${Math.round(g.days_until_full)} days` : '')
          : 'needs about a day of history')));
    }
    const rows = d.sources.slice().sort((a, b) => b.est_index_bytes - a.est_index_bytes);
    parts.push(h('div', { class: 'tablewrap' }, h('table', { class: 'numbers' },
      h('thead', {}, h('tr', {}, ['Source', 'Documents', 'Raw file size', 'Avg stored doc', 'Est. index size',
        '% of index', 'Sized', 'Docs/day'].map((t, i) => h('th', { class: i ? 'num' : null }, t)))),
      h('tbody', {}, rows.length ? rows.map(r => h('tr', {},
        h('td', {}, r.source_id ? h('a', { href: `#/source/${r.source_id}` }, r.name) : r.name, ' ',
          h('span', { class: 'kind' }, KIND_SHORT[r.kind || HOST_KIND[r.host]] || r.host),
          r.source_id ? null : h('div', { class: 'muted' }, 'not a source in the portal')),
        h('td', { class: 'num' }, r.docs.toLocaleString()),
        h('td', { class: 'num' }, fmtBytes(r.raw_bytes)),
        h('td', { class: 'num' }, fmtBytes(r.avg_doc_bytes)),
        h('td', { class: 'num' }, h('b', {}, fmtBytes(r.est_index_bytes))),
        h('td', { class: 'num' }, r.pct.toFixed(1) + '%'),
        h('td', { class: 'num' + (r.measured_pct < 100 ? ' warn' : '') }, r.measured_pct.toFixed(0) + '%'),
        h('td', { class: 'num' }, r.docs_per_day === null || r.docs_per_day === undefined ? '–'
          : Math.round(r.docs_per_day).toLocaleString())))
        : h('tr', {}, h('td', { colspan: 8, class: 'empty' }, 'None of your sources has documents in the index yet.'))))));
    parts.push(h('p', { class: 'help' },
      'Documents and raw file size are exact. OpenSearch reports the size of the whole index, not of each source, so ',
      'Est. index size splits it by each source\'s document bytes. Sized is the share of a source\'s documents measured ',
      'when they were indexed; older ones are estimated from a sample', d.sample_docs ? ` of ${d.sample_docs}` : '',
      ', so a source below 100% is less certain. Updated ', timeEl(d.updated), '.'));
    body.replaceChildren(...parts);
    if (refreshButton) refreshButton.disabled = d.refreshing;
  }

  function stat(label, value, detail, cls) {
    return h('div', { class: 'panel stat' }, h('div', { class: 'muted' }, label),
      h('div', { class: 'big ' + (cls || '') }, value), h('div', { class: 'muted small' }, detail));
  }

  await load();
  state.timer = setInterval(() => { if (!document.hidden) load().catch(() => {}); }, 30000);
}

// ------------------------------------------------------------------ access

// ------------------------------------------------------------------- index

const INDEX_ACTIONS = { check: 'Check server', rebuild: 'Rebuild', switch_back: 'Switch back', drop_previous: 'Delete previous', tidy: 'Tidy up' };
const VECTOR_KEYS = ['embeddings_url', 'model', 'chunk_words', 'chunk_overlap', 'max_chunks'];

function vectorText(i) {
  if (!i.vectors) return 'No vectors (keyword search only)';
  const m = i.meta || {};
  if (!m.model) return `Vectors (${i.dimension} dimensions), set up from .env`;
  return `${m.model}, ${m.dimension} dimensions · passages of ${m.chunk_words} words, ` +
    `${Math.round(m.chunk_overlap * 100)}% overlap, up to ${m.max_chunks} per document`;
}

// What a rebuild with these settings would change, compared with the live index.
function rebuildChanges(settings, live) {
  if (!live) return [];
  const m = live.meta || {};
  if (!settings.enabled) return live.vectors ? ['Turns vector search off: the new index has no vectors, so it\'s smaller.'] : ['Copies the index as it is, without vectors.'];
  if (!live.vectors) return ['Turns vector search on: every document is embedded.'];
  const out = [];
  if (!m.model) out.push('Moves the vector settings from .env to this portal.');
  if (m.model && m.model !== settings.model) out.push(`New model: ${m.model} → ${settings.model}.`);
  if (m.embeddings_url && m.embeddings_url !== settings.embeddings_url) out.push(`New embeddings server: ${settings.embeddings_url}.`);
  if (m.chunk_words && m.chunk_words !== settings.chunk_words) out.push(`Passage size ${m.chunk_words} → ${settings.chunk_words} words.`);
  if (m.chunk_overlap !== undefined && m.chunk_overlap !== settings.chunk_overlap) out.push(`Overlap ${Math.round(m.chunk_overlap * 100)}% → ${Math.round(settings.chunk_overlap * 100)}%.`);
  if (m.max_chunks && m.max_chunks !== settings.max_chunks) out.push(`Passages per document ${m.max_chunks} → ${settings.max_chunks}.`);
  if (!out.length) out.push('Same settings as the live index: every document is embedded again.');
  return out;
}

async function viewIndex() {
  const body = h('div');
  setMain(h('div', { class: 'pagehead' }, h('div', { class: 'grow' }, h('h1', {}, 'Index'),
    h('div', { class: 'muted' }, 'Which index search uses, and how its vectors are made.'))), body);
  const openLogs = new Set();
  let form = null;   // kept across refreshes so typing isn't lost
  let confirming = null;

  async function run(action, done) {
    try {
      await api('POST', '/api/index/jobs', { action });
      toast(`${INDEX_ACTIONS[action]} queued.`);
      confirming = null;
      if (done) done();
      await load(true);
    } catch (e) { toast(e.message, true); }
  }

  function settingsPanel(d) {
    if (form && body.contains(form.panel)) return form.panel;
    const v = d.settings;
    const enabled = h('input', { type: 'checkbox', name: 'enabled', checked: v.enabled });
    const url = h('input', { name: 'embeddings_url', value: v.embeddings_url, autocomplete: 'off' });
    const model = h('input', { name: 'model', value: v.model, autocomplete: 'off' });
    const words = h('input', { name: 'chunk_words', type: 'number', min: 50, max: 2000, value: v.chunk_words });
    const overlap = h('input', { name: 'chunk_overlap', type: 'number', min: 0, max: 50, value: Math.round(v.chunk_overlap * 100) });
    const chunks = h('input', { name: 'max_chunks', type: 'number', min: 1, max: 1000, value: v.max_chunks });
    const err = h('p', { class: 'error', role: 'alert', hidden: true });
    const fields = h('div', { class: 'grid' },
      h('label', { class: 'wide' }, 'Embeddings server', url,
        h('div', { class: 'help' }, 'A Text Embeddings Inference server\'s /embed address, as OpenSearch reaches it. Its API key is EMBEDDINGS_API_KEY on the workers.')),
      h('label', {}, 'Model', model, h('div', { class: 'help' }, 'The model that server runs, for the record. The server decides which model is used.')),
      h('label', {}, 'Passage size (words)', words, h('div', { class: 'help' }, 'About 380 words fit a 512-token model.')),
      h('label', {}, 'Overlap (%)', overlap, h('div', { class: 'help' }, 'How much neighbouring passages share.')),
      h('label', {}, 'Passages per document', chunks, h('div', { class: 'help' }, 'Text after that stays keyword-searchable.')));
    const sync = () => { fields.hidden = !enabled.checked; };
    enabled.addEventListener('change', sync);
    sync();
    const read = () => ({
      enabled: enabled.checked, embeddings_url: url.value.trim(), model: model.value.trim(),
      chunk_words: parseInt(words.value, 10), chunk_overlap: (parseFloat(overlap.value) || 0) / 100,
      max_chunks: parseInt(chunks.value, 10),
    });
    async function save(quiet) {
      err.hidden = true;
      try {
        await api('PUT', '/api/index/settings', read());
        if (!quiet) toast('Saved. A rebuild applies them.');
        form = null;
        return true;
      } catch (e) { err.textContent = e.message; err.hidden = false; return false; }
    }
    const panel = h('div', { class: 'panel' }, h('h2', {}, 'Vector settings'),
      h('label', { class: 'check' }, enabled, 'Vector search (semantic and hybrid search modes)'),
      fields, err,
      h('div', { class: 'formactions' },
        h('button', { class: 'primary', onclick: async () => { if (await save()) load(true); } }, 'Save'),
        h('button', { onclick: async () => { if (await save(true)) run('check'); } }, 'Check server'),
        h('span', { class: 'muted' }, 'Saving changes nothing in the index until you rebuild it.')));
    form = { panel, save };
    return panel;
  }

  function indexPanel(i, title, extra) {
    return h('div', { class: 'panel' }, h('h2', {}, title),
      h('p', {}, h('b', {}, i.name), ' · ', i.docs === null || i.docs === undefined ? '' : `${i.docs.toLocaleString()} documents · `,
        fmtBytes(i.bytes)),
      h('p', {}, vectorText(i)),
      i.meta && i.meta.built_at ? h('p', { class: 'muted' }, `Built ${new Date(i.meta.built_at).toLocaleString()}`,
        i.meta.built_by ? ` by ${i.meta.built_by}` : '', i.meta.built_from ? ` from ${i.meta.built_from}` : '') : null,
      extra);
  }

  function rebuildPanel(d, live, previous) {
    const changes = rebuildChanges(d.settings, live);
    const embed = d.settings.enabled;
    const start = h('button', { class: 'primary', disabled: !live || d.busy, onclick: () => { confirming = 'rebuild'; draw(d); } }, 'Rebuild…');
    const confirm = confirming === 'rebuild' ? h('div', { class: 'note' },
      h('p', {}, h('b', {}, 'While it runs, crawls, ACL syncs and removals wait. '),
        'Search keeps using the current index until the new one is complete and checked, then switches to it.'),
      previous ? h('p', {}, `The older previous index, ${previous.name}, is deleted once the new index is live.`) : null,
      h('div', { class: 'formactions' },
        h('button', { class: 'primary', onclick: async () => {
          // Rebuild with what's in the form, not just what was last saved.
          if (form && !(await form.save(true))) return;
          run('rebuild');
        } }, 'Start rebuild'),
        h('button', { onclick: () => { confirming = null; draw(d); } }, 'Cancel'))) : null;
    return h('div', { class: 'panel' }, h('h2', {}, 'Rebuild'),
      h('p', {}, 'Builds a new index from the documents already in the live one, with the saved vector settings. Nothing is crawled again.'),
      live ? h('ul', {}, changes.map(c => h('li', {}, c))) : h('p', { class: 'warn' }, 'There\'s no index yet: crawl a source first.'),
      live ? h('p', { class: 'muted' }, `${(live.docs || 0).toLocaleString()} documents to copy` +
        (embed ? ', each embedded on the way: expect it to take hours on a large index.' : '.') +
        ` Needs about ${fmtBytes(live.bytes)} of free disk while it runs.`) : null,
      d.busy ? h('p', { class: 'muted' }, 'Another index job is queued or running.') : null,
      confirm || h('div', { class: 'formactions' }, start));
  }

  function previousPanel(d, previous) {
    const confirmDrop = confirming === 'drop' ? h('div', { class: 'note' },
      h('p', {}, `Deletes ${previous.name} and the model and pipelines only it used. You can't switch back afterwards.`),
      h('div', { class: 'formactions' },
        h('button', { class: 'danger solid', onclick: () => run('drop_previous') }, 'Delete it'),
        h('button', { onclick: () => { confirming = null; draw(d); } }, 'Cancel'))) : null;
    const confirmBack = confirming === 'back' ? h('div', { class: 'note' },
      h('p', {}, `Search switches to ${previous.name}. The current index is kept as the previous one, so you can switch again.`),
      h('div', { class: 'formactions' },
        h('button', { class: 'primary', onclick: () => run('switch_back') }, 'Switch back'),
        h('button', { onclick: () => { confirming = null; draw(d); } }, 'Cancel'))) : null;
    return indexPanel(previous, 'Previous index', [
      d.switch_back ? null : h('p', { class: 'muted' }, d.switch_back_why),
      confirmDrop || confirmBack || h('div', { class: 'formactions' },
        h('button', { disabled: !d.switch_back || d.busy, onclick: () => { confirming = 'back'; draw(d); } }, 'Switch back…'),
        h('button', { class: 'danger', disabled: d.busy, onclick: () => { confirming = 'drop'; draw(d); } }, 'Delete previous index…')),
    ]);
  }

  function jobsPanel(d) {
    const rows = d.jobs.map(j => {
      const live = j.status === 'running' || j.status === 'queued';
      const took = j.started_at && j.finished_at ? span(j.finished_at - j.started_at)
        : (j.started_at ? span(d.now - j.started_at) + ' so far' : '');
      const pre = h('pre', {}, '');
      const logRow = h('tr', { hidden: !openLogs.has(j.id) }, h('td', { colspan: 6 }, pre));
      const loadLog = async () => {
        const full = await api('GET', `/api/index/jobs/${j.id}`);
        pre.textContent = full.log || (live ? '(no output yet)' : '(no output)');
        pre.scrollTop = pre.scrollHeight;
      };
      if (openLogs.has(j.id)) loadLog().catch(() => {});
      const toggle = h('button', { class: 'small', onclick: () => {
        if (openLogs.has(j.id)) openLogs.delete(j.id); else openLogs.add(j.id);
        logRow.hidden = !openLogs.has(j.id);
        toggle.textContent = openLogs.has(j.id) ? 'Hide log' : 'Log';
        if (openLogs.has(j.id)) { pre.textContent = 'Loading…'; loadLog().catch(e => toast(e.message, true)); }
      } }, openLogs.has(j.id) ? 'Hide log' : 'Log');
      return [h('tr', {},
        h('td', {}, INDEX_ACTIONS[j.action] || j.action),
        h('td', {}, statusChip(j.status), j.cancel && j.status === 'running' ? h('span', { class: 'muted' }, ' stopping') : null),
        h('td', {}, j.requested_by, ' ', h('span', { class: 'muted' }, timeEl(j.created_at))),
        h('td', {}, took, j.worker ? h('div', { class: 'muted' }, j.worker) : null),
        h('td', { class: live ? 'run' : null }, j.summary || (j.status === 'running' ? 'starting…' : (j.status === 'queued' && j.action !== 'check' && j.action !== 'drop_previous' ? 'waits for running crawls to finish' : ''))),
        h('td', { class: 'actions' }, toggle, live ? h('button', { class: 'small', onclick: async () => {
          try { await api('POST', `/api/index/jobs/${j.id}/cancel`); toast('Cancelling.'); load(true); }
          catch (e) { toast(e.message, true); }
        } }, 'Cancel') : null)), logRow];
    });
    return h('div', {}, h('h2', {}, 'Index jobs'), h('div', { class: 'tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Job', 'Status', 'Requested', 'Took', 'Result', ''].map(t => h('th', {}, t)))),
      h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 6, class: 'empty' }, 'No index jobs yet.'))))));
  }

  function draw(d) {
    const parts = [];
    if (d.holding) parts.push(h('div', { class: 'panel note' }, h('b', {}, 'A rebuild or switch is under way. '),
      d.held ? `${d.held} crawl${d.held === 1 ? '' : 's'}, ACL sync${d.held === 1 ? '' : 's'} or removal${d.held === 1 ? '' : 's'} wait${d.held === 1 ? 's' : ''} until it finishes.`
        : 'New crawls, ACL syncs and removals wait until it finishes.'));
    if (d.state_error) parts.push(h('div', { class: 'panel' }, h('p', { class: 'warn' }, d.state_error)));
    if (d.state && (d.state.leftovers.length || d.state.blocked)) {
      parts.push(h('div', { class: 'panel danger' }, h('h2', {}, 'A rebuild didn\'t finish'),
        d.state.blocked ? h('p', { class: 'warn' }, `Writes to ${d.state.alias} are blocked, so crawls fail until this is tidied up.`) : null,
        d.state.leftovers.length ? h('p', {}, `Left behind: ${d.state.leftovers.join(', ')}. Search doesn't use ${d.state.leftovers.length === 1 ? 'it' : 'them'}.`) : null,
        h('div', { class: 'formactions' }, h('button', { class: 'primary', disabled: d.busy, onclick: () => run('tidy') }, 'Tidy up'),
          h('span', { class: 'muted' }, 'Deletes what the unfinished rebuild made; a new rebuild also does this first.'))));
    }
    const st = d.state;
    const live = st ? st.indexes.find(i => i.live) : null;
    const previous = st && d.previous ? st.indexes.find(i => i.name === d.previous) : null;
    if (st) {
      const note = st.plain ? h('p', { class: 'muted' }, `${st.alias} is a plain index. The first rebuild keeps it as ${st.alias}-1 and makes ${st.alias} point to the new one.`)
        : live ? h('p', { class: 'muted' }, `Search uses ${st.alias}, which points to ${live.name}.`) : null;
      const counted = live && live.vectors && st.with_vectors !== null
        ? h('p', {}, `${st.with_vectors.toLocaleString()} of ${(live.docs || 0).toLocaleString()} documents have vectors; the rest have no text to embed.`) : null;
      parts.push(live ? indexPanel(live, 'In use', [counted, note]) : h('div', { class: 'panel empty' }, `There's no ${st.alias} index yet.`));
      if (previous) parts.push(previousPanel(d, previous));
    }
    parts.push(settingsPanel(d));
    if (st) parts.push(rebuildPanel(d, live, previous));
    parts.push(jobsPanel(d));
    body.replaceChildren(...parts);
  }

  async function load(force) {
    const d = await api('GET', '/api/index');
    d.busy = d.jobs.some(j => j.status === 'queued' || j.status === 'running');
    if (force) form = null;
    // Not while someone is typing in the settings: a redraw would lose it.
    if (!force && form && form.panel.contains(document.activeElement)) return;
    draw(d);
  }
  await load(true);
  state.timer = setInterval(() => { if (!document.hidden) load().catch(() => {}); }, 10000);
}

const ROLE_FROM = { default: 'Everyone signed in', user: 'The account itself', group: 'Group' };

async function viewAccess(username) {
  const avail = await api('GET', '/api/access');
  const input = h('input', { type: 'search', name: 'user', value: username || '', placeholder: 'Username, e.g. alice',
    'aria-label': 'Username', autocomplete: 'off', spellcheck: 'false' });
  const form = h('form', { class: 'toolbar', onsubmit: (ev) => {
    ev.preventDefault();
    const name = input.value.trim();
    if (!name) return;
    const target = '#/access/' + encodeURIComponent(name);
    if (location.hash === target) route(); else location.hash = target;
  } }, input, h('button', { type: 'submit', class: 'primary' }, 'Check'));
  const body = h('div');
  setMain(h('div', { class: 'pagehead' }, h('div', { class: 'grow' }, h('h1', {}, 'Access'),
    h('div', { class: 'muted' }, 'What one person can see in search: their groups, the roles Frogmouth gives them, ' +
      (state.me.super_admin ? 'and how many documents each source shows them.' : 'and how many documents each of your sources shows them.')))),
  avail.lookup ? form : null, body);

  if (!avail.lookup) {
    body.replaceChildren(h('div', { class: 'panel empty' },
      'The access check needs a directory account to read other people\'s groups: set LDAP_LOOKUP_USER and ',
      'LDAP_LOOKUP_PASSWORD for the portal (any ordinary domain account will do). See Help.'));
    return;
  }
  if (!username) {
    body.replaceChildren(h('p', { class: 'help' }, 'Enter a username to see what that person can find.'));
    input.focus();
    return;
  }
  body.replaceChildren(h('p', { class: 'muted' }, 'Checking…'));
  let d;
  try {
    d = await api('GET', '/api/access?user=' + encodeURIComponent(username));
  } catch (e) {
    body.replaceChildren(h('p', { class: 'error' }, e.message));
    return;
  }
  if (!d.found) {
    body.replaceChildren(h('div', { class: 'panel empty' }, `There's no account named "${d.username}" in the directory.`));
    return;
  }
  const parts = [];
  parts.push(h('div', { class: 'panel' },
    h('h2', {}, d.display_name, d.display_name !== d.username ? h('span', { class: 'muted' }, ` (${d.username})`) : null),
    d.disabled ? h('p', { class: 'warn' }, 'This account is disabled, so it can\'t sign in to search at all. ' +
      'The figures below are what it would see if it could.') : null,
    h('dl', { class: 'facts' },
      h('dt', {}, 'Groups'), h('dd', {}, d.groups.length
        ? d.groups.slice().sort((a, b) => a.localeCompare(b)).map(g => [h('span', { class: 'chip' }, g), ' '])
        : h('span', { class: 'muted' }, 'none')),
      d.nested_groups && d.nested_groups.length ? [h('dt', {}, 'Not counted'), h('dd', {},
        d.nested_groups.map(g => [h('span', { class: 'chip warn' }, g), ' ']),
        h('div', { class: 'muted small' }, 'Groups this account is in only through another group. ' +
          'Search counts direct memberships only, so documents shared with these groups stay hidden from it.'))] : null)));

  parts.push(h('h2', {}, 'Roles'));
  parts.push(h('div', { class: 'tablewrap' }, h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Role'), h('th', {}, 'Comes from'))),
    h('tbody', {}, d.roles.map(r => h('tr', {}, h('td', {}, h('code', {}, r.role)),
      h('td', {}, ROLE_FROM[r.from] || r.from, r.from === 'group' ? `: ${r.name}` : '')))))));

  parts.push(h('h2', {}, 'What they can see'));
  if (!d.counts) {
    parts.push(h('div', { class: 'panel empty' }, 'Document counts aren\'t set up: the portal needs OS_HOST and a read-only OpenSearch account.'));
  } else if (d.counts_error) {
    parts.push(h('p', { class: 'error' }, d.counts_error));
  } else {
    let visible = 0, total = 0;
    const rows = d.sources.map(r => {
      visible += r.visible; total += r.total;
      const through = Object.entries(r.by_role).sort((a, b) => b[1] - a[1]);
      return h('tr', { class: r.visible ? null : 'muted' },
        h('td', {}, h('a', { href: `#/source/${r.source_id}` }, r.name), ' ', h('span', { class: 'kind' }, KIND_SHORT[r.kind] || r.kind)),
        h('td', { class: 'num' }, h('b', {}, r.visible.toLocaleString())),
        h('td', { class: 'num' }, r.total.toLocaleString()),
        h('td', { class: 'num' }, r.total ? (100 * r.visible / r.total).toFixed(r.visible && r.visible < r.total ? 1 : 0) + '%' : '–'),
        h('td', {}, through.length ? through.map(([role, n]) => [h('code', {}, role), h('span', { class: 'muted' }, ` ${n.toLocaleString()}`), ' '])
          : h('span', { class: 'muted' }, r.total ? 'nothing' : 'no documents yet')));
    });
    parts.push(h('div', { class: 'tablewrap' }, h('table', { class: 'numbers' },
      h('thead', {}, h('tr', {}, ['Source', 'Can see', 'Documents', 'Share', 'Through'].map((t, i) =>
        h('th', { class: i && i < 4 ? 'num' : null }, t)))),
      h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 5, class: 'empty' }, 'No sources to show.'))),
      rows.length > 1 ? h('tfoot', {}, h('tr', {}, h('th', {}, 'All of these'),
        h('th', { class: 'num' }, visible.toLocaleString()), h('th', { class: 'num' }, total.toLocaleString()),
        h('th', { class: 'num' }, total ? (100 * visible / total).toFixed(1) + '%' : '–'), h('th', {}))) : null)));
    if (d.outside) {
      parts.push(h('p', { class: 'muted' }, `Also ${d.outside.visible.toLocaleString()} of ${d.outside.total.toLocaleString()} ` +
        `documents from ${d.outside.sources} source${d.outside.sources === 1 ? '' : 's'} the portal doesn't manage.`));
    }
    parts.push(h('p', { class: 'help' },
      'Counted from the index just now. A document can be open to several of the person\'s roles, so the Through ',
      'figures can add up to more than Can see. A folder\'s permissions reach the index at the source\'s next ACL sync, ',
      'and a change to someone\'s groups takes effect in search the next time they sign in.'));
  }
  body.replaceChildren(...parts);
}

// ------------------------------------------------------------------ scopes

const listText = (v) => (v || []).join('\n');
const listOf = (text) => text.split(/[\n,]/).map(s => s.trim()).filter(Boolean);

async function viewScopes() {
  const scopes = await api('GET', '/api/scopes');
  state.me.scopes = scopes;
  const creds = state.me.super_admin ? ['default', ...state.me.credentials] : [];
  const list = h('div');

  function scopeCard(sc) {
    const facts = h('dl', { class: 'facts' },
      h('dt', {}, 'Managed by'), h('dd', {}, sc.groups.join(', ')),
      h('dt', {}, 'Source types'), h('dd', {}, sc.kinds.map(k => state.me.kind_info[k].label).join(', ') || 'none'),
      h('dt', {}, 'SMB servers'), h('dd', {}, sc.smb_servers.join(', ') || 'none'),
      h('dt', {}, 'Crawl accounts'), h('dd', {}, sc.credentials.join(', ') || 'none'),
      h('dt', {}, 'May grant users'), h('dd', {}, sc.grant_users.join(', ') || 'none'),
      h('dt', {}, 'May grant groups'), h('dd', {}, sc.grant_groups.join(', ') || 'none'),
      h('dt', {}, 'May grant roles'), h('dd', {}, sc.grant_roles.join(', ') || 'none'),
      h('dt', {}, 'Shortest schedule'), h('dd', {}, every(sc.min_minutes)),
      sc.note ? [h('dt', {}, 'Note'), h('dd', {}, sc.note)] : null);
    return h('div', { class: 'panel' },
      h('div', { class: 'pagehead' }, h('div', { class: 'grow' }, h('h3', {}, sc.name)),
        state.me.super_admin ? h('button', { class: 'small', onclick: () => edit(sc) }, 'Edit') : null),
      facts);
  }

  function edit(sc) {
    const isNew = !sc;
    sc = sc || { name: '', groups: [], kinds: [], smb_servers: [], credentials: [], grant_users: [], grant_groups: [],
      grant_roles: [], min_minutes: 60, note: '' };
    const field = (name, label, value, help) => h('div', {},
      h('label', {}, label, h('textarea', { name, value: listText(value) })), h('div', { class: 'help' }, help));
    const form = h('form', { class: 'panel' },
      h('h3', {}, isNew ? 'New scope' : `Edit ${sc.name}`),
      h('div', { class: 'grid' },
        h('div', {}, h('label', {}, 'Name', h('input', { name: 'name', value: sc.name, required: true }))),
        field('groups', 'Managed by (AD groups)', sc.groups, 'Members of these groups manage this scope\'s sources.'),
        h('div', {}, h('div', { class: 'check' }, 'Source types'),
          Object.entries(state.me.kind_info).map(([k, v]) => h('label', { class: 'check' },
            h('input', { type: 'checkbox', name: 'kind', value: k, checked: sc.kinds.includes(k) }), v.label))),
        field('smb_servers', 'SMB servers', sc.smb_servers,
          'Servers its SMB sources may point at. The crawl account signs in to them, so list only your own.'),
        h('div', {}, h('div', { class: 'check' }, 'Crawl accounts'),
          creds.map(c => h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'cred', value: c,
            checked: sc.credentials.includes(c) }), c === 'default' ? 'Default crawl account' : c))),
        field('grant_users', 'May grant users', sc.grant_users, 'Extra access its mail and SharePoint sources may give.'),
        field('grant_groups', 'May grant groups', sc.grant_groups, 'AD group names.'),
        field('grant_roles', 'May grant roles', sc.grant_roles, 'Named roles; "guest" would make documents visible to everyone.'),
        h('div', {}, h('label', {}, 'Shortest schedule (minutes)',
          h('input', { type: 'number', name: 'min_minutes', min: 5, value: sc.min_minutes }))),
        h('div', { class: 'wide' }, h('label', {}, 'Note', h('input', { name: 'note', value: sc.note })))),
      h('p', { class: 'error', role: 'alert', hidden: true }),
      h('div', { class: 'formactions' },
        h('button', { type: 'submit', class: 'primary' }, isNew ? 'Create scope' : 'Save'),
        h('button', { type: 'button', onclick: () => viewScopes() }, 'Cancel'),
        isNew ? null : h('button', { type: 'button', class: 'danger', onclick: async () => {
          if (!confirm(`Delete the scope ${sc.name}? Its sources must be moved or removed first.`)) return;
          try { await api('DELETE', `/api/scopes/${sc.id}`); toast('Scope deleted.'); viewScopes(); }
          catch (e) { toast(e.message, true); }
        } }, 'Delete scope')));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = form.elements;
      const body = {
        name: f.name.value, groups: listOf(f.groups.value), smb_servers: listOf(f.smb_servers.value),
        kinds: [...form.querySelectorAll('input[name=kind]:checked')].map(i => i.value),
        credentials: [...form.querySelectorAll('input[name=cred]:checked')].map(i => i.value),
        grant_users: listOf(f.grant_users.value), grant_groups: listOf(f.grant_groups.value),
        grant_roles: listOf(f.grant_roles.value), min_minutes: parseInt(f.min_minutes.value, 10), note: f.note.value,
      };
      try {
        await api(isNew ? 'POST' : 'PUT', isNew ? '/api/scopes' : `/api/scopes/${sc.id}`, body);
        toast('Saved.');
        viewScopes();
      } catch (e) {
        const err = form.querySelector('.error');
        err.textContent = e.message;
        err.hidden = false;
      }
    });
    list.replaceChildren(form);
    form.elements.name.focus();
  }

  list.replaceChildren(...(scopes.length ? scopes.map(scopeCard)
    : [h('div', { class: 'panel empty' }, state.me.super_admin
      ? 'No scopes yet. A scope lets an AD group manage some sources without being a super admin.'
      : 'You manage no scopes.')]));
  setMain(h('div', { class: 'pagehead' }, h('div', { class: 'grow' }, h('h1', {}, 'Scopes'),
    h('div', { class: 'muted' }, 'Delegation: which groups manage which sources, and within what limits.')),
  state.me.super_admin ? h('button', { class: 'primary', onclick: () => edit(null) }, 'New scope') : null), list);
}

// ------------------------------------------------------------- credentials

async function viewCredentials() {
  const data = await api('GET', '/api/credentials');
  state.me.credentials = data.profiles.map(p => p.name);
  const holder = h('div');
  const def = data.default || {};
  function edit(p) {
    const isNew = !p;
    p = p || { name: '', user_env: '', pass_env: '', domain_env: '', note: '' };
    const form = h('form', { class: 'panel' },
      h('h3', {}, isNew ? 'New credential profile' : `Edit ${p.name}`),
      h('p', { class: 'muted' }, 'Only the names of environment variables are stored here. Set the variables on every worker.'),
      h('div', { class: 'grid' },
        h('label', {}, 'Name', h('input', { name: 'name', value: p.name, disabled: !isNew, required: true })),
        h('label', {}, 'Username variable', h('input', { name: 'user_env', value: p.user_env, placeholder: 'SMB_USER_ENG' })),
        h('label', {}, 'Password variable', h('input', { name: 'pass_env', value: p.pass_env, placeholder: 'SMB_PASS_ENG' })),
        h('label', {}, 'Domain variable', h('input', { name: 'domain_env', value: p.domain_env, placeholder: 'SMB_DOMAIN_ENG' })),
        h('label', { class: 'wide' }, 'Note', h('input', { name: 'note', value: p.note || '' }))),
      h('p', { class: 'error', role: 'alert', hidden: true }),
      h('div', { class: 'formactions' }, h('button', { type: 'submit', class: 'primary' }, 'Save'),
        h('button', { type: 'button', onclick: () => viewCredentials() }, 'Cancel')));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = form.elements;
      const body = { name: f.name.value, user_env: f.user_env.value, pass_env: f.pass_env.value,
        domain_env: f.domain_env.value, note: f.note.value };
      try {
        await api(isNew ? 'POST' : 'PUT', isNew ? '/api/credentials' : `/api/credentials/${p.id}`, body);
        toast('Saved.');
        viewCredentials();
      } catch (e) {
        const err = form.querySelector('.error');
        err.textContent = e.message;
        err.hidden = false;
      }
    });
    holder.replaceChildren(form);
  }
  holder.replaceChildren(h('div', { class: 'tablewrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['Profile', 'Username', 'Password', 'Domain', 'Used by', ''].map(t => h('th', {}, t)))),
    h('tbody', {},
      h('tr', {}, h('td', {}, 'default', h('div', { class: 'muted' }, 'default_credentials in the SMB settings')),
        h('td', { class: 'mono' }, def.user_env || ''), h('td', { class: 'mono' }, def.pass_env || ''),
        h('td', { class: 'mono' }, def.domain_env || ''), h('td', {}, String(data.default_sources)), h('td')),
      data.profiles.map(p => h('tr', {},
        h('td', {}, p.name, p.note ? h('div', { class: 'muted' }, p.note) : null),
        h('td', { class: 'mono' }, p.user_env), h('td', { class: 'mono' }, p.pass_env), h('td', { class: 'mono' }, p.domain_env),
        h('td', {}, String(p.sources)),
        h('td', { class: 'actions' },
          h('button', { class: 'small', onclick: () => edit(p) }, 'Edit'),
          h('button', { class: 'small danger', onclick: async () => {
            if (!confirm(`Delete the profile ${p.name}?`)) return;
            try { await api('DELETE', `/api/credentials/${p.id}`); toast('Deleted.'); viewCredentials(); }
            catch (e) { toast(e.message, true); }
          } }, 'Delete'))))))));
  setMain(h('div', { class: 'pagehead' }, h('div', { class: 'grow' }, h('h1', {}, 'Credentials'),
    h('div', { class: 'muted' }, 'SMB crawl accounts. The portal never sees a password: it names the variables workers read.')),
  h('button', { class: 'primary', onclick: () => edit(null) }, 'New profile')), holder);
}

// ---------------------------------------------------------------- settings

async function viewSettings() {
  const kind = viewSettings.kind || 'smb';
  const data = await api('GET', `/api/settings/${kind}`);
  const area = h('textarea', { class: 'tall', value: data.yaml, spellcheck: 'false', 'aria-label': 'Settings YAML' });
  const err = h('p', { class: 'error', role: 'alert', hidden: true });
  setMain(
    h('div', { class: 'pagehead' }, h('div', { class: 'grow' }, h('h1', {}, 'Settings'),
      h('div', { class: 'muted' }, 'Global defaults for each source type: everything in its YAML file except the source list.'))),
    h('div', { class: 'toolbar' }, Object.entries(state.me.kind_info).map(([k, v]) =>
      h('button', { class: k === kind ? 'primary' : '', onclick: () => { viewSettings.kind = k; viewSettings(); } }, v.label))),
    h('div', { class: 'panel' }, area, err,
      h('div', { class: 'formactions' }, h('button', { class: 'primary', onclick: async () => {
        err.hidden = true;
        try { await api('PUT', `/api/settings/${kind}`, { yaml: area.value }); toast('Saved.'); }
        catch (e) { err.textContent = e.message; err.hidden = false; }
      } }, 'Save'), h('span', { class: 'muted' }, 'Crawls started after saving use the new settings.'))));
}

// ------------------------------------------------------------------- audit

async function viewAudit() {
  const tbody = h('tbody');
  const more = h('button', {}, 'Older');
  let oldest = null;
  async function load() {
    const entries = await api('GET', '/api/audit' + (oldest ? `?before=${oldest}` : ''));
    for (const e of entries) {
      const detail = e.detail ? h('details', {}, h('summary', {}, 'details'), h('pre', {}, JSON.stringify(e.detail, null, 2))) : '';
      tbody.append(h('tr', {}, h('td', {}, timeEl(e.at)), h('td', {}, e.user), h('td', {}, e.action),
        h('td', {}, e.target || ''), h('td', {}, detail)));
      oldest = e.id;
    }
    more.hidden = entries.length < 200;
    if (!tbody.children.length) tbody.append(h('tr', {}, h('td', { colspan: 5, class: 'empty' }, 'Nothing yet.')));
  }
  more.addEventListener('click', () => load().catch(e => toast(e.message, true)));
  setMain(h('div', { class: 'pagehead' }, h('div', { class: 'grow' }, h('h1', {}, 'Audit log'),
    h('div', { class: 'muted' }, state.me.super_admin ? 'Every change, by whom.' : 'Changes in your scopes.'))),
  h('div', { class: 'tablewrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ['When', 'Who', 'What', 'Target', ''].map(t => h('th', {}, t)))), tbody)),
  h('div', { class: 'formactions' }, more));
  await load();
}

// -------------------------------------------------------------------- help

async function viewHelp() {
  // Our own static file, parsed rather than set as innerHTML.
  const res = await fetch('/static/help.html', { credentials: 'same-origin' });
  if (!res.ok) throw new Error('The help page could not be loaded.');
  const doc = new DOMParser().parseFromString(await res.text(), 'text/html');
  const page = document.importNode(doc.querySelector('.help-page'), true);
  // Buttons, not #links: the URL hash is the page route.
  page.querySelectorAll('.toc button').forEach(b => b.addEventListener('click', () => {
    const target = page.querySelector('#' + b.dataset.target);
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    target.setAttribute('tabindex', '-1');
    target.focus({ preventScroll: true });
  }));
  setMain(page);
}

// ------------------------------------------------------------------- start

(async function start() {
  try {
    state.me = await api('GET', '/api/me');
    showApp();
  } catch (e) {
    showSignIn();
  }
})();
