const PHASES = [
  ['blocked', 'Queued / blocked', '--ph-blocked'],
  ['dns', 'DNS lookup', '--ph-dns'],
  ['connect', 'Connecting', '--ph-connect'],
  ['ssl', 'TLS handshake', '--ph-ssl'],
  ['send', 'Sending', '--ph-send'],
  ['wait', 'Waiting (server)', '--ph-wait'],
  ['receive', 'Downloading', '--ph-receive'],
];

const els = {
  summary: document.getElementById('summary'),
  list: document.getElementById('list'),
  detail: document.getElementById('detail'),
  search: document.getElementById('search'),
  host: document.getElementById('host'),
  count: document.getElementById('count'),
  type: document.getElementById('type'),
  threshold: document.getElementById('threshold'),
  onlySlow: document.getElementById('onlySlow'),
  onlyDupes: document.getElementById('onlyDupes'),
  preserve: document.getElementById('preserve'),
  sort: document.getElementById('sort'),
  copyList: document.getElementById('copyList'),
  clear: document.getElementById('clear'),
};

const ROW_HEIGHT = 30;
const OVERSCAN = 10;
const SETTINGS_KEY = 'slowpoke:settings';
const persisted = [els.type, els.threshold, els.onlySlow, els.onlyDupes, els.preserve, els.sort];

let requests = [];
let nextId = 1;
let selectedId = null;
let renderQueued = false;
let rowsQueued = false;
let hostSignature = '';
let current = { rows: [], counts: new Map(), minStart: 0, span: 1 };

const listHead = h('div', { class: 'head' },
  h('span', {}, 'Status'), h('span', {}, 'Method'), h('span', {}, 'Request'),
  h('span', { class: 'num' }, 'Size'), h('span', { class: 'num' }, 'Time'), h('span', {}, 'Waterfall'),
);
const listRows = h('div', { class: 'rows' });
els.list.append(listHead, listRows);

/** Builds a DOM element without ever interpreting strings as HTML. */
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') el.className = value;
    else if (key === 'style') Object.assign(el.style, value);
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child);
  }
  return el;
}

/** Replaces an element's children, flattening nested arrays and skipping empty values. */
function setChildren(el, ...children) {
  el.replaceChildren(...children.flat(Infinity).filter((child) => child !== null && child !== undefined && child !== false));
}

function formatMs(ms) {
  if (ms < 0) return '-';
  if (ms >= 10000) return `${(ms / 1000).toFixed(1)} s`;
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${Math.round(ms)} ms`;
}

function formatBytes(bytes) {
  if (!bytes || bytes < 0) return '-';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function resourceType(entry) {
  const raw = (entry._resourceType || '').toLowerCase();
  if (raw === 'fetch' || raw === 'xhr') return 'xhr';
  if (['document', 'script', 'stylesheet', 'image', 'font'].includes(raw)) return raw;
  return 'other';
}

function toRequest(entry) {
  const url = new URL(entry.request.url, 'http://invalid');
  const key = `${entry.request.method} ${entry.request.url.split('#')[0]}`;
  return {
    id: nextId++,
    key,
    url: entry.request.url,
    host: url.host,
    path: `${url.pathname}${url.search}` || '/',
    method: entry.request.method,
    status: entry.response.status,
    type: resourceType(entry),
    start: new Date(entry.startedDateTime).getTime(),
    time: Math.max(entry.time, 0),
    size: entry.response._transferSize > 0 ? entry.response._transferSize : entry.response.content.size,
    timings: entry.timings,
    cached: entry.response._transferSize === 0 && entry.response.status !== 0,
    mime: entry.response.content.mimeType,
  };
}

function isSlow(req) {
  return req.time >= Number(els.threshold.value || 500);
}

function groupCounts() {
  const counts = new Map();
  for (const req of requests) counts.set(req.key, (counts.get(req.key) || 0) + 1);
  return counts;
}

function visibleRequests(counts) {
  const term = els.search.value.trim().toLowerCase();
  let rows = requests.filter((req) => {
    if (term && !req.url.toLowerCase().includes(term)) return false;
    if (els.host.value && req.host !== els.host.value) return false;
    if (els.type.value && req.type !== els.type.value) return false;
    if (els.onlySlow.checked && !isSlow(req)) return false;
    if (els.onlyDupes.checked && counts.get(req.key) < 2) return false;
    return true;
  });

  if (els.sort.value === 'time') {
    rows = rows.sort((a, b) => b.time - a.time);
  } else if (els.sort.value === 'count') {
    rows = rows.sort((a, b) => counts.get(b.key) - counts.get(a.key) || a.key.localeCompare(b.key) || a.start - b.start);
  } else {
    rows = rows.sort((a, b) => a.start - b.start);
  }
  return rows;
}

/** Rebuilds the host dropdown with request counts, keeping the current selection. */
function renderHosts() {
  const hosts = new Map();
  for (const req of requests) hosts.set(req.host, (hosts.get(req.host) || 0) + 1);
  const sorted = [...hosts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

  const signature = sorted.map(([host, n]) => `${host}:${n}`).join('|');
  if (signature === hostSignature) return;
  hostSignature = signature;

  const selected = hosts.has(els.host.value) ? els.host.value : '';
  els.host.replaceChildren(
    h('option', { value: '' }, `All hosts (${hosts.size})`),
    ...sorted.map(([host, n]) => h('option', { value: host }, `${host} (${n})`)),
  );
  els.host.value = selected;
}

function renderSummary(counts) {
  const slow = requests.filter(isSlow).length;
  const repeatedGroups = [...counts.values()].filter((n) => n > 1);
  const extraCalls = repeatedGroups.reduce((sum, n) => sum + n - 1, 0);
  const total = requests.reduce((sum, req) => sum + req.time, 0);
  const slowest = requests.reduce((max, req) => (req.time > max ? req.time : max), 0);

  const card = (label, value, cls = '') =>
    h('div', { class: `card ${cls}` }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value));

  els.summary.replaceChildren(
    card('Requests', String(requests.length)),
    card('Slow', String(slow), slow ? 'bad' : ''),
    card('Repeated URLs', `${repeatedGroups.length} (+${extraCalls})`, extraCalls ? 'dupe' : ''),
    card('Slowest', formatMs(slowest)),
    card('Sum of time', formatMs(total)),
  );
}

function renderRow(req, counts, minStart, span) {
  const count = counts.get(req.key);
  const slow = isSlow(req);
  const barClass = slow ? 'slow' : count > 1 ? 'dupe' : '';
  const timeClass = slow ? 'slow' : req.time >= Number(els.threshold.value || 500) / 2 ? 'mid' : '';

  return h(
    'div',
    {
      class: `row${req.id === selectedId ? ' selected' : ''}`,
      title: req.url,
      onclick: () => {
        selectedId = req.id;
        queueRender();
      },
    },
    h('span', { class: `status s${String(req.status)[0]}` }, req.status || 'ERR'),
    h('span', { class: 'method' }, req.method),
    h(
      'span',
      { class: 'name' },
      h('span', { class: 'path' }, req.path, ' ', h('span', { class: 'host' }, req.host)),
      count > 1 && h('span', { class: 'badge dupe' }, `x${count}`),
      slow && h('span', { class: 'badge slow' }, 'slow'),
    ),
    h('span', { class: 'num' }, req.cached ? 'cache' : formatBytes(req.size)),
    h('span', { class: `num time ${timeClass}` }, formatMs(req.time)),
    h(
      'span',
      { class: 'waterfall' },
      h('span', {
        class: `bar ${barClass}`,
        style: {
          left: `${((req.start - minStart) / span) * 100}%`,
          width: `${(req.time / span) * 100}%`,
        },
      }),
    ),
  );
}

/** Builds a plain-text summary of a request, including its timing phases and repeated calls. */
function buildSummary(req) {
  const threshold = Number(els.threshold.value || 500);
  const runs = requests.filter((r) => r.key === req.key).sort((a, b) => a.start - b.start);
  const lines = [
    `Request: ${req.method} ${req.url}`,
    `Status: ${req.status}`,
    `Type: ${req.mime || req.type}`,
    `Size: ${req.cached ? 'from cache' : formatBytes(req.size)}`,
    `Started: ${new Date(req.start).toISOString()}`,
    `Total time: ${formatMs(req.time)}${isSlow(req) ? ` (slow, threshold ${threshold} ms)` : ''}`,
    '',
    'Timing breakdown:',
    ...PHASES.map(([key, label]) => `- ${label}: ${req.timings[key] > 0 ? formatMs(req.timings[key]) : '-'}`),
  ];

  if (runs.length > 1) {
    const combined = runs.reduce((sum, r) => sum + r.time, 0);
    lines.push('', `Called ${runs.length} times, combined time ${formatMs(combined)}:`);
    runs.forEach((r, i) => lines.push(`- Call ${i + 1}: ${r.status}, ${formatMs(r.time)}, at +${formatMs(r.start - runs[0].start)}`));
  }

  return lines.join('\n');
}

/** Copies text to the clipboard, using a hidden textarea when the Clipboard API is unavailable. */
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = h('textarea', { style: { position: 'fixed', opacity: '0' } });
    area.value = text;
    document.body.append(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    return ok;
  }
}

/** Copies text and briefly shows the result on the button. */
async function copyWithFeedback(button, text) {
  button.dataset.label ||= button.textContent;
  button.textContent = (await copyText(text)) ? 'Copied' : 'Copy failed';
  setTimeout(() => { button.textContent = button.dataset.label; }, 1500);
}

/** Builds a plain-text list of the given requests, with the active filters and sort order. */
function buildListSummary(rows, counts) {
  const sortLabels = { start: 'start time', time: 'slowest first', count: 'most repeated' };
  const filters = [
    els.host.value && `host=${els.host.value}`,
    els.type.value && `type=${els.type.value}`,
    els.search.value.trim() && `search="${els.search.value.trim()}"`,
    els.onlySlow.checked && 'only slow',
    els.onlyDupes.checked && 'only repeated',
  ].filter(Boolean);
  const total = rows.reduce((sum, req) => sum + req.time, 0);

  const lines = [
    `Network requests (showing ${rows.length} of ${requests.length}, ${formatMs(total)} total)`,
    `Filters: ${filters.length ? filters.join(', ') : 'none'}`,
    `Slow threshold: ${Number(els.threshold.value || 500)} ms`,
    `Sorted by: ${sortLabels[els.sort.value]}`,
    '',
  ];

  for (const req of rows) {
    const count = counts.get(req.key);
    const flags = [isSlow(req) && 'slow', count > 1 && `repeated x${count}`].filter(Boolean);
    lines.push(`- ${req.status} ${req.method} ${formatMs(req.time)} ${req.cached ? 'cache' : formatBytes(req.size)} ${req.url}${flags.length ? ` (${flags.join(', ')})` : ''}`);
  }

  return lines.join('\n');
}

function renderDetail(counts) {
  const req = requests.find((r) => r.id === selectedId);
  if (!req) {
    els.detail.hidden = true;
    return;
  }
  els.detail.hidden = false;

  const phases = PHASES.map(([key, label, color]) => ({ label, color, value: Math.max(req.timings[key] ?? -1, 0) }));
  const phaseTotal = phases.reduce((sum, p) => sum + p.value, 0) || 1;
  const runs = requests.filter((r) => r.key === req.key).sort((a, b) => a.start - b.start);
  const firstStart = runs[0].start;

  setChildren(
    els.detail,
    h(
      'div',
      { class: 'actions' },
      h('button', {
        type: 'button',
        onclick: (event) => copyWithFeedback(event.currentTarget, buildSummary(req)),
      }, 'Copy for LLM'),
      h('button', { type: 'button', onclick: () => { selectedId = null; queueRender(); } }, 'Close'),
    ),
    h('h3', {}, req.path),
    h('div', { class: 'host' }, `${req.method} ${req.host}`),

    h('h4', {}, 'Where the time went'),
    h(
      'div',
      { class: 'phases' },
      phases.filter((p) => p.value > 0).map((p) =>
        h('span', { title: `${p.label}: ${formatMs(p.value)}`, style: { width: `${(p.value / phaseTotal) * 100}%`, background: `var(${p.color})` } }),
      ),
    ),
    phases.map((p) =>
      h('div', { class: 'phase-row' },
        h('span', { class: 'dot', style: { background: `var(${p.color})` } }),
        h('span', { class: 'k' }, p.label),
        h('span', { class: 'v' }, p.value > 0 ? formatMs(p.value) : '-'),
      ),
    ),
    h('div', { class: 'phase-row' },
      h('span', { class: 'dot' }),
      h('strong', { class: 'k' }, 'Total'),
      h('strong', { class: 'v' }, formatMs(req.time)),
    ),

    runs.length > 1 && [
      h('h4', {}, `Called ${runs.length} times`),
      runs.map((r, i) =>
        h('div', { class: 'run' },
          h('span', {}, i === 0 ? 'First call' : `+${formatMs(r.start - firstStart)}`),
          h('span', {}, `${r.status} / ${formatMs(r.time)}`),
        ),
      ),
      h('div', { class: 'run' },
        h('strong', {}, 'Combined time'),
        h('strong', {}, formatMs(runs.reduce((sum, r) => sum + r.time, 0))),
      ),
    ],

    h('h4', {}, 'Details'),
    h('div', { class: 'kv' },
      h('span', { class: 'k' }, 'URL'), h('span', {}, req.url),
      h('span', { class: 'k' }, 'Status'), h('span', {}, String(req.status)),
      h('span', { class: 'k' }, 'Type'), h('span', {}, req.mime || req.type),
      h('span', { class: 'k' }, 'Size'), h('span', {}, req.cached ? 'from cache' : formatBytes(req.size)),
    ),
  );
}

function render() {
  renderQueued = false;
  const counts = groupCounts();
  renderSummary(counts);
  renderHosts();

  const rows = visibleRequests(counts);
  const shownTime = rows.reduce((sum, req) => sum + req.time, 0);
  els.count.textContent = `Showing ${rows.length} of ${requests.length} requests, ${formatMs(shownTime)} total`;
  const minStart = requests.reduce((min, r) => Math.min(min, r.start), Infinity);
  const maxEnd = requests.reduce((max, r) => Math.max(max, r.start + r.time), 0);
  const span = Math.max(maxEnd - minStart, 1);

  current = { rows, counts, minStart, span };
  renderRows();
  renderDetail(counts);
}

/** Renders the rows inside the scrolled viewport, plus a small overscan. */
function renderRows() {
  rowsQueued = false;
  const { rows, counts, minStart, span } = current;

  if (!rows.length) {
    listRows.style.height = '';
    setChildren(listRows, h('div', { class: 'empty' }, requests.length ? 'No requests match the current filters.' : 'Waiting for requests. Reload the page to capture everything.'));
    return;
  }

  listRows.style.height = `${rows.length * ROW_HEIGHT}px`;
  const offset = Math.max(els.list.scrollTop - listRows.offsetTop, 0);
  const first = Math.max(Math.floor(offset / ROW_HEIGHT) - OVERSCAN, 0);
  const last = Math.min(Math.ceil((offset + els.list.clientHeight) / ROW_HEIGHT) + OVERSCAN, rows.length);

  setChildren(listRows, rows.slice(first, last).map((req, i) => {
    const row = renderRow(req, counts, minStart, span);
    row.style.top = `${(first + i) * ROW_HEIGHT}px`;
    return row;
  }));
}

function queueRender() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(render);
}

function queueRows() {
  if (rowsQueued) return;
  rowsQueued = true;
  requestAnimationFrame(renderRows);
}

/** Restores the persisted toolbar settings from localStorage. */
function loadSettings() {
  let saved;
  try {
    saved = JSON.parse(localStorage.getItem(SETTINGS_KEY)) || {};
  } catch {
    return;
  }
  for (const el of persisted) {
    if (!(el.id in saved)) continue;
    if (el.type === 'checkbox') el.checked = Boolean(saved[el.id]);
    else el.value = saved[el.id];
  }
}

/** Writes the persisted toolbar settings to localStorage. */
function saveSettings() {
  const values = Object.fromEntries(persisted.map((el) => [el.id, el.type === 'checkbox' ? el.checked : el.value]));
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(values));
  } catch {
    // Storage unavailable, settings only last for this session.
  }
}

chrome.devtools.network.onRequestFinished.addListener((entry) => {
  requests.push(toRequest(entry));
  queueRender();
});

chrome.devtools.network.onNavigated.addListener(() => {
  if (els.preserve.checked) return;
  requests = [];
  selectedId = null;
  queueRender();
});

chrome.devtools.network.getHAR((har) => {
  requests = har.entries.map(toRequest);
  queueRender();
});

els.copyList.addEventListener('click', (event) => {
  const counts = groupCounts();
  copyWithFeedback(event.currentTarget, buildListSummary(visibleRequests(counts), counts));
});

els.clear.addEventListener('click', () => {
  requests = [];
  selectedId = null;
  queueRender();
});

for (const el of [els.search, els.host, els.type, els.threshold, els.onlySlow, els.onlyDupes, els.sort]) {
  el.addEventListener('input', queueRender);
}

els.list.addEventListener('scroll', queueRows);
new ResizeObserver(queueRows).observe(els.list);

for (const el of persisted) {
  el.addEventListener('input', saveSettings);
}

loadSettings();
queueRender();
