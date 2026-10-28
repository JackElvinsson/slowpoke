const PHASES = [
  ['blocked', 'Queued / blocked', '--ph-blocked'],
  ['dns', 'DNS lookup', '--ph-dns'],
  ['connect', 'Connecting', '--ph-connect'],
  ['ssl', 'TLS handshake', '--ph-ssl'],
  ['send', 'Sending', '--ph-send'],
  ['wait', 'Waiting (server)', '--ph-wait'],
  ['receive', 'Downloading', '--ph-receive'],
];

const TYPES = ['xhr', 'document', 'script', 'stylesheet', 'image', 'font', 'other'];

const els = {
  summary: document.getElementById('summary'),
  list: document.getElementById('list'),
  detail: document.getElementById('detail'),
  search: document.getElementById('search'),
  host: document.getElementById('host'),
  count: document.getElementById('count'),
  type: document.getElementById('type'),
  threshold: document.getElementById('threshold'),
  typeThresholds: document.getElementById('typeThresholds'),
  thresholds: Object.fromEntries(TYPES.map((type) => [type, document.getElementById(`threshold-${type}`)])),
  ignoreParams: document.getElementById('ignoreParams'),
  onlySlow: document.getElementById('onlySlow'),
  onlyDupes: document.getElementById('onlyDupes'),
  preserve: document.getElementById('preserve'),
  sort: document.getElementById('sort'),
  sortCustom: document.getElementById('sortCustom'),
  view: document.getElementById('view'),
  saveBaseline: document.getElementById('saveBaseline'),
  clearBaseline: document.getElementById('clearBaseline'),
  copyList: document.getElementById('copyList'),
  clear: document.getElementById('clear'),
};

const ROW_HEIGHT = 30;
const OVERSCAN = 10;
const BURST_MS = 1000;
const MAX_FRAMES = 30;
const SHOWN_FRAMES = 10;
const TEXT_MIME = /json|javascript|css|html|xml|svg|text\//;
const STATIC_TYPES = ['script', 'stylesheet', 'image', 'font'];
const CACHE_HEADERS = ['cf-cache-status', 'x-cache', 'x-cache-status', 'x-proxy-cache', 'x-litespeed-cache', 'x-vercel-cache'];
const SETTINGS_KEY = 'slowpoke:settings';
const BASELINE_KEY = 'slowpoke:baseline';
const BASELINE_MIN_MS = 50;
const persisted = [els.type, els.threshold, ...Object.values(els.thresholds), els.ignoreParams, els.onlySlow, els.onlyDupes, els.preserve, els.sort, els.view];

const SORT_PRESETS = {
  start: { by: 'start', desc: false },
  latest: { by: 'start', desc: true },
  time: { by: 'time', desc: true },
  count: { by: 'count', desc: true },
};
const SORT_LABELS = { start: 'start time', status: 'status', method: 'method', path: 'request', size: 'size', time: 'time', count: 'calls', avg: 'average time', p95: 'p95 time', max: 'max time' };
const ASCENDING_FIRST = ['start', 'method', 'path'];
const GROUP_STATS = ['count', 'avg', 'p95', 'max'];
const REQUEST_SORT = {
  start: (req) => req.start,
  status: (req) => req.status,
  method: (req) => req.method,
  path: (req) => req.path,
  size: (req) => req.size,
  time: (req) => req.time,
  count: (req, groups) => groups.get(req.key).count,
  avg: (req, groups) => groups.get(req.key).avg,
  p95: (req, groups) => groups.get(req.key).p95,
  max: (req, groups) => groups.get(req.key).max,
};
const GROUP_SORT = {
  start: (group) => group.runs[0].start,
  status: (group) => group.runs.at(-1).status,
  method: (group) => group.runs.at(-1).method,
  path: (group) => group.runs.at(-1).path,
  size: (group) => group.runs.at(-1).size,
  time: (group) => group.total,
  count: (group) => group.count,
  avg: (group) => group.avg,
  p95: (group) => group.p95,
  max: (group) => group.max,
};

let requests = [];
let nextId = 1;
let selectedId = null;
let renderQueued = false;
let rowsQueued = false;
let hostSignature = '';
let headSignature = '';
let baseline = null;
let current = { rows: [], grouped: false, groups: new Map(), minStart: 0, span: 1 };

const listHead = h('div', { class: 'head' });
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

/** Copies HAR timings with the TLS time taken out of connect, since HAR counts it in both. */
function exclusiveTimings(timings) {
  const result = { ...timings };
  if (result.ssl > 0 && result.connect > 0) result.connect = Math.max(result.connect - result.ssl, 0);
  return result;
}

/** Returns a short FNV-1a hash of a string. */
function hashText(text) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16);
}

/** Reads GraphQL operation names from the URL or a JSON request body, including batched operations. */
function graphqlOperation(url, body) {
  const fromUrl = url.searchParams.get('operationName');
  if (fromUrl) return fromUrl;
  if (!body) return '';

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return '';
  }
  return (Array.isArray(parsed) ? parsed : [parsed])
    .map((op) => op?.operationName || /^\s*(?:query|mutation|subscription)\s+(\w+)/.exec(op?.query ?? '')?.[1])
    .filter(Boolean)
    .join(', ');
}

/** Parses the "Ignore params" setting into a set of query param names. */
function ignoredParams() {
  return new Set(els.ignoreParams.value.split(',').map((name) => name.trim()).filter(Boolean));
}

/** Builds the key that marks requests as repeats: method, URL without fragment and ignored params, and body hash. */
function requestKey(req, ignored) {
  const url = new URL(req.url, 'http://invalid');
  url.hash = '';
  if (ignored.has('*')) url.search = '';
  else for (const name of ignored) url.searchParams.delete(name);
  return `${req.method} ${url.href}${req.body ? ` #${hashText(req.body)}` : ''}`;
}

function recomputeKeys() {
  const ignored = ignoredParams();
  for (const req of requests) req.key = requestKey(req, ignored);
}

/** Collects the initiator's call frames, including async parent stacks, as file locations. */
function parseInitiator(initiator) {
  if (!initiator) return null;
  const frames = [];
  for (let stack = initiator.stack; stack; stack = stack.parent) {
    for (const frame of stack.callFrames || []) {
      if (frame.url) frames.push({ fn: frame.functionName, url: frame.url, line: frame.lineNumber ?? 0 });
    }
  }
  if (!frames.length && initiator.url) frames.push({ fn: '', url: initiator.url, line: initiator.lineNumber ?? 0 });
  return { type: initiator.type, frames: frames.slice(0, MAX_FRAMES) };
}

function frameId(frame) {
  return `${frame.url}:${frame.line}:${frame.fn}`;
}

function frameLabel(frame) {
  const url = new URL(frame.url, 'http://invalid');
  const file = url.pathname.split('/').pop() || url.host;
  return `${frame.fn ? `${frame.fn} @ ` : ''}${file}:${frame.line + 1}`;
}

/** Returns each run's caller: the first frame below the stack prefix that all runs in the group share. */
function findCallers(runs) {
  const stacks = runs.map((r) => r.initiator?.frames ?? []);
  const withFrames = stacks.filter((frames) => frames.length);
  if (!withFrames.length) return [];

  let shared = 0;
  while (withFrames.every((frames) => frames[shared] && frameId(frames[shared]) === frameId(withFrames[0][shared]))) shared++;

  const callers = new Map();
  for (const frames of withFrames) {
    const frame = frames[shared] ?? frames[0];
    const id = frameId(frame);
    if (!callers.has(id)) callers.set(id, { frame, count: 0 });
    callers.get(id).count++;
  }
  return [...callers.values()].sort((a, b) => b.count - a.count);
}

function openFrame(frame) {
  chrome.devtools.panels.openResource(frame.url, frame.line);
}

function frameLink(frame) {
  return h('button', { type: 'button', class: 'link', title: `${frame.url}:${frame.line + 1}`, onclick: () => openFrame(frame) }, frameLabel(frame));
}

function headerValues(headers, name) {
  return headers.filter((header) => header.name === name).map((header) => header.value);
}

/** Parses Server-Timing header values into metrics with name, duration and description. */
function parseServerTiming(values) {
  const metrics = [];
  for (const part of values.join(',').match(/(?:[^,"]|"[^"]*")+/g) ?? []) {
    const name = part.split(';')[0].trim();
    if (!name) continue;
    const params = Object.fromEntries(
      [...part.matchAll(/;\s*(\w+)\s*=\s*(?:"([^"]*)"|([^;\s]*))/g)].map(([, key, quoted, plain]) => [key.toLowerCase(), quoted ?? plain]),
    );
    metrics.push({ name, dur: params.dur ? Number(params.dur) : null, desc: params.desc ?? '' });
  }
  return metrics;
}

/** Reads the cache result from known CDN and proxy headers, or from a positive Age header. */
function parseCacheStatus(headers) {
  for (const name of CACHE_HEADERS) {
    const value = headerValues(headers, name)[0];
    if (!value) continue;
    const last = value.split(',').pop().trim().toLowerCase();
    const status = /hit|stale|revalidated|updating/.test(last) ? 'hit' : /miss|expired|bypass|dynamic|pass/.test(last) ? 'miss' : 'other';
    return { status, source: `${name}: ${value}` };
  }
  const age = Number(headerValues(headers, 'age')[0]);
  return age > 0 ? { status: 'hit', source: `age: ${age}` } : null;
}

function cacheLabel(cache) {
  return cache.status === 'other' ? cache.source : `${cache.status.toUpperCase()} (${cache.source})`;
}

/** Checks a request's timings and headers against common causes of slowness and lists the ones that match. */
function buildHints(req) {
  const hints = [];
  const phase = (key) => Math.max(req.timings[key] ?? 0, 0);
  const header = (name) => headerValues(req.responseHeaders, name)[0] ?? '';

  const wait = phase('wait');
  if (wait >= 200 && wait >= req.time * 0.6) {
    hints.push(`Server wait is ${formatMs(wait)} (${Math.round((wait / req.time) * 100)}% of the total), so the backend is the bottleneck${req.cache?.status === 'miss' ? ' and the response was not served from cache' : ''}.`);
  }

  const blocked = phase('blocked');
  if (blocked >= 100) {
    hints.push(/^http\/1/i.test(req.httpVersion)
      ? `Queued ${formatMs(blocked)} before sending. HTTP/1.1 allows 6 connections per host, so requests wait for a free one.`
      : `Queued ${formatMs(blocked)} before sending, usually behind higher-priority requests or a busy main thread.`);
  }

  const setup = phase('dns') + phase('connect') + phase('ssl');
  if (setup >= 100) hints.push(`Connection setup took ${formatMs(setup)}. A preconnect hint for ${req.host} starts it earlier.`);

  if (req.status >= 300 && req.status < 400 && header('location')) hints.push(`Redirects to ${header('location')}, which costs an extra round trip.`);

  if (!req.cached && req.size >= 10 * 1024 && TEXT_MIME.test(req.mime) && !header('content-encoding')) {
    hints.push(`Text response of ${formatBytes(req.size)} is not compressed. Enable gzip or brotli.`);
  }

  if (req.size >= 1024 * 1024) hints.push(`Large response, ${formatBytes(req.size)} transferred.`);

  if (STATIC_TYPES.includes(req.type) && req.status === 200 && !req.cached && !header('expires')) {
    const cacheControl = header('cache-control');
    if (!cacheControl || /no-store|no-cache|max-age=0\b/.test(cacheControl)) {
      hints.push('Static asset without long-lived cache headers, so the browser fetches it again on every visit.');
    }
  }

  return hints;
}

function toRequest(entry) {
  const url = new URL(entry.request.url, 'http://invalid');
  const body = entry.request.postData?.text || '';
  const responseHeaders = entry.response.headers.map(({ name, value }) => ({ name: name.toLowerCase(), value }));
  const req = {
    id: nextId++,
    url: entry.request.url,
    host: url.host,
    path: `${url.pathname}${url.search}` || '/',
    body,
    operation: graphqlOperation(url, body),
    method: entry.request.method,
    status: entry.response.status,
    httpVersion: entry.response.httpVersion,
    type: resourceType(entry),
    start: new Date(entry.startedDateTime).getTime(),
    time: Math.max(entry.time, 0),
    size: entry.response._transferSize > 0 ? entry.response._transferSize : entry.response.content.size,
    timings: exclusiveTimings(entry.timings),
    cached: entry.response._transferSize === 0 && entry.response.status !== 0,
    mime: entry.response.content.mimeType,
    initiator: parseInitiator(entry._initiator),
    requestHeaders: entry.request.headers,
    responseHeaders,
    serverTiming: parseServerTiming(headerValues(responseHeaders, 'server-timing')),
    cache: parseCacheStatus(responseHeaders),
  };
  req.key = requestKey(req, ignoredParams());
  return req;
}

function globalThreshold() {
  return Number(els.threshold.value || 500);
}

/** Returns the slow threshold for a request's type, or the global one when the type has none. */
function thresholdFor(req) {
  return Number(els.thresholds[req.type].value) || globalThreshold();
}

function isSlow(req) {
  return req.time >= thresholdFor(req);
}

/** Shows the global threshold as placeholder in the per-type inputs and marks the toggle when any override is set. */
function renderThresholds() {
  const inputs = Object.values(els.thresholds);
  for (const input of inputs) input.placeholder = String(globalThreshold());
  const overrides = inputs.filter((input) => input.value).length;
  const summary = els.typeThresholds.querySelector('summary');
  summary.textContent = overrides ? `Per type (${overrides})` : 'Per type';
  summary.classList.toggle('active', overrides > 0);
}

/** Finds the largest set of calls that started within BURST_MS of each other in a start-sorted run list. */
function findBurst(runs) {
  let best = null;
  for (let lo = 0, hi = 0; hi < runs.length; hi++) {
    while (runs[hi].start - runs[lo].start >= BURST_MS) lo++;
    const count = hi - lo + 1;
    if (count > 1 && (!best || count > best.count)) best = { count, span: runs[hi].start - runs[lo].start };
  }
  return best;
}

/** Groups requests by key with their start-sorted runs, combined time and burst. */
function buildGroups() {
  const groups = new Map();
  for (const req of requests) {
    if (!groups.has(req.key)) groups.set(req.key, { key: req.key, runs: [] });
    groups.get(req.key).runs.push(req);
  }
  for (const group of groups.values()) {
    group.runs.sort((a, b) => a.start - b.start);
    group.count = group.runs.length;
    group.total = group.runs.reduce((sum, r) => sum + r.time, 0);
    group.avg = group.total / group.count;
    const times = group.runs.map((r) => r.time).sort((a, b) => a - b);
    group.max = times.at(-1);
    group.p95 = times[Math.ceil(times.length * 0.95) - 1];
    group.burst = findBurst(group.runs);
  }
  return groups;
}

function burstLabel(burst) {
  return `${burst.count} calls within ${formatMs(burst.span)}`;
}

function visibleRequests(groups) {
  const term = els.search.value.trim().toLowerCase();
  let rows = requests.filter((req) => {
    if (term && !req.url.toLowerCase().includes(term) && !req.operation.toLowerCase().includes(term)) return false;
    if (els.host.value && req.host !== els.host.value) return false;
    if (els.type.value && req.type !== els.type.value) return false;
    if (els.onlySlow.checked && !isSlow(req)) return false;
    if (els.onlyDupes.checked && groups.get(req.key).count < 2) return false;
    return true;
  });

  const byKey = GROUP_STATS.includes(currentSort().by) ? (a, b) => a.key.localeCompare(b.key) : undefined;
  return sortItems(rows, REQUEST_SORT, groups, byKey);
}

/** Returns the groups that have at least one visible request, in the current sort order. */
function visibleGroups(rows, groups) {
  const list = [...new Set(rows.map((req) => req.key))].map((key) => groups.get(key));
  return sortItems(list, GROUP_SORT, groups);
}

/** Parses a sort menu value into a column and direction. */
function parseSort(value) {
  if (SORT_PRESETS[value]) return SORT_PRESETS[value];
  const [by, dir] = String(value).split(':');
  return SORT_LABELS[by] ? { by, desc: dir === 'desc' } : SORT_PRESETS.start;
}

function currentSort() {
  return parseSort(els.sort.value);
}

/** Selects the sort menu preset for a column and direction, or the custom option when none matches. */
function setSort({ by, desc }) {
  const preset = Object.keys(SORT_PRESETS).find((name) => SORT_PRESETS[name].by === by && SORT_PRESETS[name].desc === desc);
  if (!preset) els.sortCustom.value = `${by}:${desc ? 'desc' : 'asc'}`;
  els.sort.value = preset || els.sortCustom.value;
}

/** Sorts on a column, reversing the direction when it is already the active column. */
function sortOnColumn(by) {
  const sort = currentSort();
  setSort({ by, desc: sort.by === by ? !sort.desc : !ASCENDING_FIRST.includes(by) });
  saveSettings();
  queueRender();
}

function compareValues(a, b) {
  return typeof a === 'string' ? a.localeCompare(b) : a - b;
}

/** Sorts items in place on the active sort column, then by the optional tie breaker and start time. */
function sortItems(items, accessors, groups, tie = () => 0) {
  const { by, desc } = currentSort();
  const value = accessors[by];
  const dir = desc ? -1 : 1;
  return items.sort((a, b) => dir * compareValues(value(a, groups), value(b, groups)) || tie(a, b) || accessors.start(a) - accessors.start(b));
}

function columnLabel(by, grouped) {
  return by === 'time' && grouped ? 'total time' : SORT_LABELS[by];
}

/** Describes the active sort in words. */
function sortLabel(grouped) {
  const presets = { start: 'start time', latest: 'latest first', time: grouped ? 'highest total time' : 'slowest first', count: 'most repeated' };
  if (presets[els.sort.value]) return presets[els.sort.value];
  const { by, desc } = currentSort();
  return `${columnLabel(by, grouped)}, ${desc ? 'descending' : 'ascending'}`;
}

function loadBaseline() {
  try {
    baseline = JSON.parse(localStorage.getItem(BASELINE_KEY));
  } catch {
    baseline = null;
  }
}

/** Stores each group's call count and average time as the baseline to compare later runs against. */
function saveBaseline() {
  const groups = [...buildGroups().values()];
  baseline = {
    savedAt: Date.now(),
    requests: requests.length,
    groups: Object.fromEntries(groups.map((group) => [group.key, { count: group.count, avg: group.avg }])),
  };
  try {
    localStorage.setItem(BASELINE_KEY, JSON.stringify(baseline));
  } catch {
    // Storage unavailable, the baseline only lasts for this session.
  }
}

function clearBaseline() {
  baseline = null;
  try {
    localStorage.removeItem(BASELINE_KEY);
  } catch {
    // Storage unavailable, nothing was stored.
  }
}

/** Compares a time and call count against the baseline entry for a key. */
function compareToBaseline(key, time, count) {
  if (!baseline) return null;
  const before = baseline.groups[key];
  if (!before) return { kind: 'new' };
  const diff = time - before.avg;
  const significant = Math.abs(diff) >= Math.max(BASELINE_MIN_MS, before.avg * 0.2);
  return { kind: significant ? (diff > 0 ? 'slower' : 'faster') : 'same', diff, before, nowRepeated: before.count < 2 && count > 1 };
}

function baselineText(delta) {
  if (delta.kind === 'new') return 'not in the baseline';
  return `average ${formatMs(delta.before.avg)} over ${delta.before.count} calls, now ${formatDiff(delta.diff)}${delta.nowRepeated ? ', now repeated' : ''}`;
}

function formatDiff(ms) {
  return `${ms >= 0 ? '+' : '-'}${formatMs(Math.abs(ms))}`;
}

function baselineBadges(delta) {
  if (!delta) return null;
  if (delta.kind === 'new') return h('span', { class: 'badge delta-new', title: 'Not in the baseline' }, 'new');
  return [
    delta.kind !== 'same' && h('span', { class: `badge delta-${delta.kind}`, title: `Baseline average ${formatMs(delta.before.avg)}` }, formatDiff(delta.diff)),
    delta.nowRepeated && h('span', { class: 'badge dupe', title: 'Called once in the baseline' }, 'now repeated'),
  ];
}

/** Lists a delta's changes against the baseline as short text flags. */
function baselineFlags(delta) {
  if (!delta) return [];
  if (delta.kind === 'new') return ['new since baseline'];
  return [delta.kind !== 'same' && `${formatDiff(delta.diff)} vs baseline`, delta.nowRepeated && 'now repeated'].filter(Boolean);
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

function renderSummary(groups) {
  const slow = requests.filter(isSlow).length;
  const repeatedGroups = [...groups.values()].filter((group) => group.count > 1);
  const extraCalls = repeatedGroups.reduce((sum, group) => sum + group.count - 1, 0);
  const bursts = repeatedGroups.filter((group) => group.burst).length;
  const total = requests.reduce((sum, req) => sum + req.time, 0);
  const slowest = requests.reduce((max, req) => (req.time > max ? req.time : max), 0);

  const card = (label, value, cls = '') =>
    h('div', { class: `card ${cls}` }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value));

  setChildren(
    els.summary,
    card('Requests', String(requests.length)),
    card('Slow', String(slow), slow ? 'bad' : ''),
    card('Repeated URLs', `${repeatedGroups.length} (+${extraCalls})`, extraCalls ? 'dupe' : ''),
    card('Bursts', String(bursts), bursts ? 'dupe' : ''),
    card('Slowest', formatMs(slowest)),
    card('Sum of time', formatMs(total)),
    baseline && renderBaselineCard(groups, card),
  );
  els.clearBaseline.hidden = !baseline;
}

/** Counts the groups that got slower, faster or are new since the baseline and builds their summary card. */
function renderBaselineCard(groups, card) {
  const deltas = [...groups.values()].map((group) => compareToBaseline(group.key, group.avg, group.count));
  const count = (kind) => deltas.filter((delta) => delta.kind === kind).length;
  const slower = count('slower');
  const saved = new Date(baseline.savedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const el = card(`Vs baseline (${saved})`, `${slower} slower, ${count('faster')} faster, ${count('new')} new`, slower ? 'bad' : '');
  el.title = `Baseline of ${baseline.requests} requests saved ${new Date(baseline.savedAt).toLocaleString()}`;
  return el;
}

function renderRow(req, groups, minStart, span) {
  const { count, burst } = groups.get(req.key);
  const slow = isSlow(req);
  const barClass = slow ? 'slow' : count > 1 ? 'dupe' : '';
  const timeClass = slow ? 'slow' : req.time >= thresholdFor(req) / 2 ? 'mid' : '';

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
      req.operation && h('span', { class: 'badge op' }, req.operation),
      slow && h('span', { class: 'badge slow' }, 'slow'),
      count > 1 && h('span', { class: 'badge dupe' }, `x${count}`),
      burst && h('span', { class: 'badge burst', title: burstLabel(burst) }, `${burst.count} in ${formatMs(burst.span)}`),
      baselineBadges(compareToBaseline(req.key, req.time, count)),
      req.cache && req.cache.status !== 'other' && h('span', { class: `badge cache-${req.cache.status}`, title: req.cache.source }, req.cache.status.toUpperCase()),
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

/** Renders one row per group with its call count and time statistics. */
function renderGroupRow(group) {
  const last = group.runs.at(-1);
  const slow = group.max >= thresholdFor(last);

  return h(
    'div',
    {
      class: `row${group.runs.some((r) => r.id === selectedId) ? ' selected' : ''}`,
      title: last.url,
      onclick: () => {
        selectedId = last.id;
        queueRender();
      },
    },
    h('span', { class: `num calls${group.count > 1 ? ' dupe' : ''}` }, `x${group.count}`),
    h('span', { class: 'method' }, last.method),
    h(
      'span',
      { class: 'name' },
      h('span', { class: 'path' }, last.path, ' ', h('span', { class: 'host' }, last.host)),
      last.operation && h('span', { class: 'badge op' }, last.operation),
      slow && h('span', { class: 'badge slow' }, 'slow'),
      group.burst && h('span', { class: 'badge burst', title: burstLabel(group.burst) }, `${group.burst.count} in ${formatMs(group.burst.span)}`),
      baselineBadges(compareToBaseline(group.key, group.avg, group.count)),
    ),
    h('span', { class: 'num' }, formatMs(group.avg)),
    h('span', { class: 'num' }, formatMs(group.p95)),
    h('span', { class: `num time ${slow ? 'slow' : ''}` }, formatMs(group.max)),
    h('span', { class: 'num' }, formatMs(group.total)),
  );
}

/** Builds a plain-text summary of a request, including its timing phases and repeated calls. */
function buildSummary(req, groups) {
  const threshold = thresholdFor(req);
  const hints = buildHints(req);
  const { runs, total, burst } = groups.get(req.key);
  const lines = [
    `Request: ${req.method} ${req.url}`,
    req.operation ? `GraphQL operation: ${req.operation}` : null,
    `Status: ${req.status}`,
    `Type: ${req.mime || req.type}`,
    `Size: ${req.cached ? 'from cache' : formatBytes(req.size)}`,
    req.cache ? `CDN/proxy cache: ${cacheLabel(req.cache)}` : null,
    `Started: ${new Date(req.start).toISOString()}`,
    `Total time: ${formatMs(req.time)}${isSlow(req) ? ` (slow, threshold ${threshold} ms)` : ''}`,
    baseline ? `Baseline: ${baselineText(compareToBaseline(req.key, req.time, runs.length))}` : null,
    ...(hints.length ? ['', 'Hints:', ...hints.map((hint) => `- ${hint}`)] : []),
    '',
    'Timing breakdown:',
    ...PHASES.map(([key, label]) => `- ${label}: ${req.timings[key] > 0 ? formatMs(req.timings[key]) : '-'}`),
  ];

  if (req.serverTiming.length) {
    lines.push('', 'Server-Timing:');
    req.serverTiming.forEach((m) => lines.push(`- ${m.name}${m.desc ? ` (${m.desc})` : ''}: ${m.dur !== null ? formatMs(m.dur) : '-'}`));
  }

  if (req.initiator) {
    lines.push('', `Initiator (${req.initiator.type}):`);
    if (!req.initiator.frames.length) lines.push('- no stack recorded');
    req.initiator.frames.slice(0, SHOWN_FRAMES).forEach((frame) => lines.push(`- ${frame.fn || '(anonymous)'} ${frame.url}:${frame.line + 1}`));
  }

  if (runs.length > 1) {
    lines.push('', `Called ${runs.length} times, combined time ${formatMs(total)}${burst ? `, burst of ${burstLabel(burst)}` : ''}:`);
    runs.forEach((r, i) => lines.push(`- Call ${i + 1}: ${r.status}, ${formatMs(r.time)}, at +${formatMs(r.start - runs[0].start)}`));
    const callers = findCallers(runs);
    if (callers.length) lines.push('Callers:', ...callers.map(({ frame, count }) => `- x${count} ${frame.fn || '(anonymous)'} ${frame.url}:${frame.line + 1}`));
  }

  return lines.filter((line) => line !== null).join('\n');
}

/** Builds a cURL command that repeats the request with its method, headers and body. */
function buildCurl(req) {
  const quote = (text) => `'${text.replace(/'/g, "'\\''")}'`;
  const parts = [`curl ${quote(req.url)}`];
  if (req.method !== 'GET' && !(req.method === 'POST' && req.body)) parts.push(`-X ${req.method}`);

  let compressed = false;
  for (const { name, value } of req.requestHeaders) {
    const lower = name.toLowerCase();
    if (lower.startsWith(':') || lower === 'content-length') continue;
    if (lower === 'accept-encoding') {
      compressed = true;
      continue;
    }
    parts.push(`-H ${quote(`${name}: ${value}`)}`);
  }

  if (req.body) parts.push(`--data-raw ${quote(req.body)}`);
  if (compressed) parts.push('--compressed');
  return parts.join(' \\\n  ');
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

/** Briefly replaces a button's label with a status message. */
function flashLabel(button, message) {
  button.dataset.label ||= button.textContent;
  button.textContent = message;
  setTimeout(() => { button.textContent = button.dataset.label; }, 1500);
}

/** Copies text and briefly shows the result on the button. */
async function copyWithFeedback(button, text) {
  flashLabel(button, (await copyText(text)) ? 'Copied' : 'Copy failed');
}

/** Builds a plain-text list of the given requests, or of their groups in grouped view, with the active filters and sort order. */
function buildListSummary(rows, groups) {
  const grouped = els.view.value === 'grouped';
  const filters = [
    els.host.value && `host=${els.host.value}`,
    els.type.value && `type=${els.type.value}`,
    els.search.value.trim() && `search="${els.search.value.trim()}"`,
    els.onlySlow.checked && 'only slow',
    els.onlyDupes.checked && 'only repeated',
  ].filter(Boolean);
  const total = rows.reduce((sum, req) => sum + req.time, 0);
  const overrides = TYPES.filter((type) => els.thresholds[type].value).map((type) => `${type} ${Number(els.thresholds[type].value)} ms`);

  const lines = [
    `Network requests (showing ${rows.length} of ${requests.length}, ${formatMs(total)} total)`,
    `Filters: ${filters.length ? filters.join(', ') : 'none'}`,
    `Slow threshold: ${globalThreshold()} ms${overrides.length ? ` (${overrides.join(', ')})` : ''}`,
    `Sorted by: ${sortLabel(grouped)}`,
    baseline ? `Compared to baseline of ${baseline.requests} requests saved ${new Date(baseline.savedAt).toISOString()}` : null,
    '',
  ].filter((line) => line !== null);

  if (grouped) {
    for (const group of visibleGroups(rows, groups)) {
      const last = group.runs.at(-1);
      const flags = [
        group.max >= thresholdFor(last) && 'slow',
        group.burst && `burst of ${burstLabel(group.burst)}`,
        ...baselineFlags(compareToBaseline(group.key, group.avg, group.count)),
      ].filter(Boolean);
      lines.push(`- x${group.count} ${last.method} avg ${formatMs(group.avg)}, p95 ${formatMs(group.p95)}, max ${formatMs(group.max)}, total ${formatMs(group.total)} ${last.url}${last.operation ? ` [${last.operation}]` : ''}${flags.length ? ` (${flags.join(', ')})` : ''}`);
    }
    return lines.join('\n');
  }

  for (const req of rows) {
    const { count, burst } = groups.get(req.key);
    const flags = [
      isSlow(req) && 'slow',
      req.cache && req.cache.status !== 'other' && `cache ${req.cache.status}`,
      count > 1 && `repeated x${count}`,
      burst && `burst of ${burstLabel(burst)}`,
      ...baselineFlags(compareToBaseline(req.key, req.time, count)),
    ].filter(Boolean);
    const caller = req.initiator?.frames[0];
    lines.push(`- ${req.status} ${req.method} ${formatMs(req.time)} ${req.cached ? 'cache' : formatBytes(req.size)} ${req.url}${req.operation ? ` [${req.operation}]` : ''}${caller ? ` from ${frameLabel(caller)}` : ''}${flags.length ? ` (${flags.join(', ')})` : ''}`);
  }

  return lines.join('\n');
}

function renderDetail(groups) {
  const req = requests.find((r) => r.id === selectedId);
  if (!req) {
    els.detail.hidden = true;
    return;
  }
  els.detail.hidden = false;

  const phases = PHASES.map(([key, label, color]) => ({ label, color, value: Math.max(req.timings[key] ?? -1, 0) }));
  const phaseTotal = phases.reduce((sum, p) => sum + p.value, 0) || 1;
  const { runs, total, burst } = groups.get(req.key);
  const callers = runs.length > 1 ? findCallers(runs) : [];
  const hints = buildHints(req);
  const firstStart = runs[0].start;

  setChildren(
    els.detail,
    h(
      'div',
      { class: 'actions' },
      h('button', {
        type: 'button',
        onclick: (event) => copyWithFeedback(event.currentTarget, buildSummary(req, groups)),
      }, 'Copy for LLM'),
      h('button', {
        type: 'button',
        onclick: (event) => copyWithFeedback(event.currentTarget, buildCurl(req)),
      }, 'Copy as cURL'),
      h('button', { type: 'button', onclick: () => { selectedId = null; queueRender(); } }, 'Close'),
    ),
    h('h3', {}, req.path),
    h('div', { class: 'host' }, `${req.method} ${req.host}`),

    hints.length > 0 && [
      h('h4', {}, 'Hints'),
      h('ul', { class: 'hints' }, hints.map((hint) => h('li', {}, hint))),
    ],

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

    req.serverTiming.length > 0 && [
      h('h4', {}, 'Server timing'),
      req.serverTiming.map((m) =>
        h('div', { class: 'phase-row' },
          h('span', { class: 'dot', style: { background: 'var(--ph-wait)' } }),
          h('span', { class: 'k' }, m.desc ? `${m.name} (${m.desc})` : m.name),
          h('span', { class: 'v' }, m.dur !== null ? formatMs(m.dur) : '-'),
        ),
      ),
    ],

    h('h4', {}, 'Initiated by'),
    req.initiator?.frames.length
      ? [
        h('div', { class: 'muted' }, req.initiator.type),
        req.initiator.frames.slice(0, SHOWN_FRAMES).map((frame) => h('div', { class: 'frame' }, frameLink(frame))),
        req.initiator.frames.length > SHOWN_FRAMES && h('div', { class: 'muted' }, `+${req.initiator.frames.length - SHOWN_FRAMES} more frames`),
      ]
      : h('div', { class: 'muted' }, req.initiator ? `${req.initiator.type}, no stack recorded` : 'Not recorded'),

    runs.length > 1 && [
      h('h4', {}, `Called ${runs.length} times`),
      burst && h('div', { class: 'note burst' }, `Burst: ${burstLabel(burst)}`),
      callers.length > 0 && h('div', { class: 'callers' },
        callers.map(({ frame, count }) => h('div', { class: 'run' }, frameLink(frame), h('span', {}, `x${count}`))),
      ),
      runs.map((r, i) =>
        h('div', { class: 'run' },
          h('span', {}, i === 0 ? 'First call' : `+${formatMs(r.start - firstStart)}`),
          h('span', {}, `${r.status} / ${formatMs(r.time)}`),
        ),
      ),
      h('div', { class: 'run' },
        h('strong', {}, 'Combined time'),
        h('strong', {}, formatMs(total)),
      ),
    ],

    h('h4', {}, 'Details'),
    h('div', { class: 'kv' },
      h('span', { class: 'k' }, 'URL'), h('span', {}, req.url),
      req.operation && [h('span', { class: 'k' }, 'Operation'), h('span', {}, req.operation)],
      h('span', { class: 'k' }, 'Status'), h('span', {}, String(req.status)),
      h('span', { class: 'k' }, 'Type'), h('span', {}, req.mime || req.type),
      h('span', { class: 'k' }, 'Size'), h('span', {}, req.cached ? 'from cache' : formatBytes(req.size)),
      req.cache && [h('span', { class: 'k' }, 'CDN cache'), h('span', {}, cacheLabel(req.cache))],
      baseline && [h('span', { class: 'k' }, 'Baseline'), h('span', {}, baselineText(compareToBaseline(req.key, req.time, runs.length)))],
    ),
  );
}

function render() {
  renderQueued = false;
  const groups = buildGroups();
  renderSummary(groups);
  renderHosts();
  renderThresholds();

  const grouped = els.view.value === 'grouped';
  const rows = visibleRequests(groups);
  const shownTime = rows.reduce((sum, req) => sum + req.time, 0);
  const shownGroups = grouped ? visibleGroups(rows, groups) : null;
  els.count.textContent = grouped
    ? `Showing ${shownGroups.length} groups from ${rows.length} of ${requests.length} requests, ${formatMs(shownTime)} total`
    : `Showing ${rows.length} of ${requests.length} requests, ${formatMs(shownTime)} total`;
  const minStart = requests.reduce((min, r) => Math.min(min, r.start), Infinity);
  const maxEnd = requests.reduce((max, r) => Math.max(max, r.start + r.time), 0);
  const span = Math.max(maxEnd - minStart, 1);

  renderHead(grouped);
  current = { rows: shownGroups || rows, grouped, groups, minStart, span };
  renderRows();
  renderDetail(groups);
}

/** Renders the sortable column headings for the request or grouped view and the custom sort option label. */
function renderHead(grouped) {
  els.sortCustom.textContent = `Sort: ${sortLabel(grouped)}`;
  const signature = `${grouped}|${els.sort.value}`;
  if (signature === headSignature) return;
  headSignature = signature;
  els.list.classList.toggle('grouped', grouped);

  const columns = grouped
    ? [['count', 'Calls', 'num'], ['method', 'Method'], ['path', 'Request'], ['avg', 'Avg', 'num'], ['p95', 'p95', 'num'], ['max', 'Max', 'num'], ['time', 'Total', 'num']]
    : [['status', 'Status'], ['method', 'Method'], ['path', 'Request'], ['size', 'Size', 'num'], ['time', 'Time', 'num'], ['start', 'Waterfall']];
  const { by, desc } = currentSort();
  setChildren(listHead, columns.map(([key, label, align = '']) => {
    const direction = key === by ? (desc ? ' desc' : ' asc') : '';
    return h('button', {
      type: 'button',
      class: `sort ${align}${direction}`,
      title: `Sort by ${columnLabel(key, grouped)}`,
      onclick: () => sortOnColumn(key),
    }, label);
  }));
}

/** Renders the rows inside the scrolled viewport, plus a small overscan. */
function renderRows() {
  rowsQueued = false;
  const { rows, grouped, groups, minStart, span } = current;

  if (!rows.length) {
    listRows.style.height = '';
    setChildren(listRows, h('div', { class: 'empty' }, requests.length ? 'No requests match the current filters.' : 'Waiting for requests. Reload the page to capture everything.'));
    return;
  }

  listRows.style.height = `${rows.length * ROW_HEIGHT}px`;
  const offset = Math.max(els.list.scrollTop - listRows.offsetTop, 0);
  const first = Math.max(Math.floor(offset / ROW_HEIGHT) - OVERSCAN, 0);
  const last = Math.min(Math.ceil((offset + els.list.clientHeight) / ROW_HEIGHT) + OVERSCAN, rows.length);

  setChildren(listRows, rows.slice(first, last).map((item, i) => {
    const row = grouped ? renderGroupRow(item) : renderRow(item, groups, minStart, span);
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
    else if (el === els.sort) setSort(parseSort(saved[el.id]));
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

els.saveBaseline.addEventListener('click', (event) => {
  saveBaseline();
  flashLabel(event.currentTarget, 'Saved');
  queueRender();
});

els.clearBaseline.addEventListener('click', () => {
  clearBaseline();
  queueRender();
});

els.copyList.addEventListener('click', (event) => {
  const groups = buildGroups();
  copyWithFeedback(event.currentTarget, buildListSummary(visibleRequests(groups), groups));
});

els.ignoreParams.addEventListener('input', () => {
  recomputeKeys();
  queueRender();
});

els.clear.addEventListener('click', () => {
  requests = [];
  selectedId = null;
  queueRender();
});

for (const el of [els.search, els.host, els.type, els.threshold, ...Object.values(els.thresholds), els.onlySlow, els.onlyDupes, els.sort, els.view]) {
  el.addEventListener('input', queueRender);
}

document.addEventListener('click', (event) => {
  if (!els.typeThresholds.contains(event.target)) els.typeThresholds.open = false;
});

els.list.addEventListener('scroll', queueRows);
new ResizeObserver(queueRows).observe(els.list);

for (const el of persisted) {
  el.addEventListener('input', saveSettings);
}

loadSettings();
loadBaseline();
queueRender();
