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
  view: document.getElementById('view'),
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
const persisted = [els.type, els.threshold, ...Object.values(els.thresholds), els.ignoreParams, els.onlySlow, els.onlyDupes, els.preserve, els.sort, els.view];

let requests = [];
let nextId = 1;
let selectedId = null;
let renderQueued = false;
let rowsQueued = false;
let hostSignature = '';
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

  const setup = phase('dns') + phase('connect');
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
    timings: entry.timings,
    cached: entry.response._transferSize === 0 && entry.response.status !== 0,
    mime: entry.response.content.mimeType,
    initiator: parseInitiator(entry._initiator),
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

  if (els.sort.value === 'time') {
    rows = rows.sort((a, b) => b.time - a.time);
  } else if (els.sort.value === 'count') {
    rows = rows.sort((a, b) => groups.get(b.key).count - groups.get(a.key).count || a.key.localeCompare(b.key) || a.start - b.start);
  } else {
    rows = rows.sort((a, b) => a.start - b.start);
  }
  return rows;
}

/** Returns the groups that have at least one visible request, in the current sort order. */
function visibleGroups(rows, groups) {
  const list = [...new Set(rows.map((req) => req.key))].map((key) => groups.get(key));
  const byStart = (a, b) => a.runs[0].start - b.runs[0].start;
  if (els.sort.value === 'time') return list.sort((a, b) => b.total - a.total);
  if (els.sort.value === 'count') return list.sort((a, b) => b.count - a.count || byStart(a, b));
  return list.sort(byStart);
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

  els.summary.replaceChildren(
    card('Requests', String(requests.length)),
    card('Slow', String(slow), slow ? 'bad' : ''),
    card('Repeated URLs', `${repeatedGroups.length} (+${extraCalls})`, extraCalls ? 'dupe' : ''),
    card('Bursts', String(bursts), bursts ? 'dupe' : ''),
    card('Slowest', formatMs(slowest)),
    card('Sum of time', formatMs(total)),
  );
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
      req.cache && req.cache.status !== 'other' && h('span', { class: `badge cache-${req.cache.status}`, title: req.cache.source }, req.cache.status.toUpperCase()),
      count > 1 && h('span', { class: 'badge dupe' }, `x${count}`),
      burst && h('span', { class: 'badge burst', title: burstLabel(burst) }, `${burst.count} in ${formatMs(burst.span)}`),
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
      group.burst && h('span', { class: 'badge burst', title: burstLabel(group.burst) }, `${group.burst.count} in ${formatMs(group.burst.span)}`),
      slow && h('span', { class: 'badge slow' }, 'slow'),
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

/** Builds a plain-text list of the given requests, or of their groups in grouped view, with the active filters and sort order. */
function buildListSummary(rows, groups) {
  const grouped = els.view.value === 'grouped';
  const sortLabels = { start: 'start time', time: grouped ? 'highest total time' : 'slowest first', count: 'most repeated' };
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
    `Sorted by: ${sortLabels[els.sort.value]}`,
    '',
  ];

  if (grouped) {
    for (const group of visibleGroups(rows, groups)) {
      const last = group.runs.at(-1);
      const flags = [group.max >= thresholdFor(last) && 'slow', group.burst && `burst of ${burstLabel(group.burst)}`].filter(Boolean);
      lines.push(`- x${group.count} ${last.method} avg ${formatMs(group.avg)}, p95 ${formatMs(group.p95)}, max ${formatMs(group.max)}, total ${formatMs(group.total)} ${last.url}${last.operation ? ` [${last.operation}]` : ''}${flags.length ? ` (${flags.join(', ')})` : ''}`);
    }
    return lines.join('\n');
  }

  for (const req of rows) {
    const { count, burst } = groups.get(req.key);
    const flags = [isSlow(req) && 'slow', req.cache && req.cache.status !== 'other' && `cache ${req.cache.status}`, count > 1 && `repeated x${count}`, burst && `burst of ${burstLabel(burst)}`].filter(Boolean);
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

/** Swaps the column headings between the request and grouped views. */
function renderHead(grouped) {
  if (els.list.classList.contains('grouped') === grouped && listHead.childElementCount) return;
  els.list.classList.toggle('grouped', grouped);
  setChildren(listHead, grouped
    ? [h('span', { class: 'num' }, 'Calls'), h('span', {}, 'Method'), h('span', {}, 'Request'),
      h('span', { class: 'num' }, 'Avg'), h('span', { class: 'num' }, 'p95'), h('span', { class: 'num' }, 'Max'), h('span', { class: 'num' }, 'Total')]
    : [h('span', {}, 'Status'), h('span', {}, 'Method'), h('span', {}, 'Request'),
      h('span', { class: 'num' }, 'Size'), h('span', { class: 'num' }, 'Time'), h('span', {}, 'Waterfall')]);
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
queueRender();
