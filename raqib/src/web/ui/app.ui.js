// Raqib console — the interface is a thin client over the local API.
// No framework, no build step, no network beyond this origin.

const $ = (id) => document.getElementById(id);

const state = {
  kind: 'auto',
  regex: false,
  caseSensitive: false,
  busy: false,
};

function setStatus(text, tone = 'idle') {
  $('status-text').textContent = text;
  const dot = $('status-dot');
  dot.classList.toggle('is-busy', tone === 'busy');
  dot.classList.toggle('is-error', tone === 'error');
}

function formatBytes(bytes) {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path, body) {
  const response = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await response.json().catch(() => ({ error: 'the server returned a non-JSON response' }));
  if (!response.ok) throw new Error(payload.error || `request failed (${response.status})`);
  return payload;
}

function renderEvidence(evidence, elapsed) {
  $('evidence-kind').textContent = evidence.kind;
  $('evidence-subject').textContent = evidence.subject;
  $('evidence-summary').textContent = evidence.summary;

  const idBlock = $('evidence-id');
  idBlock.hidden = false;
  $('evidence-code').textContent = evidence.id;
  const stamp = $('evidence-stamp');
  const unknownCount = (evidence.limitations || []).length;
  stamp.textContent = unknownCount === 0 ? 'no gaps' : `${unknownCount} gap${unknownCount === 1 ? '' : 's'}`;
  stamp.classList.toggle('is-verified', unknownCount === 0);

  const facts = $('facts');
  facts.replaceChildren();
  for (const item of evidence.facts || []) {
    const row = el('div', 'fact');
    row.append(el('span', 'fact__label', item.label));
    const value = el('span', 'fact__value', item.value);
    if (item.source && item.source.file) {
      value.title = `${item.source.file}${item.source.line ? `:${item.source.line}` : ''}`;
    }
    row.append(value);
    facts.append(row);
  }
  $('facts-block').hidden = !(evidence.facts || []).length;

  const locations = $('locations');
  locations.replaceChildren();
  for (const item of (evidence.locations || []).slice(0, 300)) {
    const row = el('li', 'location');
    const position = `${item.file}${item.line ? `:${item.line}` : ''}${item.column ? `:${item.column}` : ''}`;
    const body = el('span');
    body.append(el('span', 'location__file', position));
    if (item.note) body.append(el('span', 'location__note', item.note));
    row.append(body);
    locations.append(row);
  }
  $('locations-block').hidden = !(evidence.locations || []).length;

  const limits = $('limits');
  limits.replaceChildren();
  for (const item of evidence.limitations || []) {
    limits.append(el('li', null, item));
  }
  $('limits-block').hidden = !(evidence.limitations || []).length;

  $('empty-block').hidden = true;

  $('stat-facts').textContent = (evidence.facts || []).length;
  $('stat-locations').textContent = (evidence.locations || []).length;
  $('stat-unknowns').textContent = unknownCount;
  $('stat-elapsed').textContent = `${Math.round(elapsed)} ms`;
  const files = (evidence.metrics || []).find((m) => m.label === 'tree.files');
  $('stat-files').textContent = files ? String(files.value) : '—';
}

async function runAnalysis() {
  const target = $('target').value.trim();
  if (!target) {
    setStatus('a target path is required', 'error');
    $('target').focus();
    return;
  }
  state.busy = true;
  setStatus(`reading ${target}`, 'busy');
  const started = performance.now();
  try {
    const kind = state.kind === 'map' ? 'sourcemap' : state.kind;
    const { evidence } = await api('/api/analyze', { path: target, kind });
    renderEvidence(evidence, performance.now() - started);
    setStatus(`analysed ${evidence.kind} in ${Math.round(performance.now() - started)} ms`);
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    state.busy = false;
  }
}

async function runSearch() {
  const target = $('target').value.trim();
  const pattern = $('pattern').value.trim();
  if (!target || !pattern) {
    setStatus('search needs a target path and a pattern', 'error');
    return;
  }
  setStatus(`searching for "${pattern}"`, 'busy');
  const started = performance.now();
  try {
    const { result } = await api('/api/search', {
      path: target,
      pattern,
      regex: state.regex,
      caseSensitive: state.caseSensitive,
      maxResults: 200,
    });
    const box = $('results');
    box.replaceChildren();
    for (const match of result.matches.slice(0, 120)) {
      const row = el('div', 'result');
      row.append(el('span', 'result__where', `${match.file}:${match.line}`));
      row.append(el('span', 'result__text', match.text));
      box.append(row);
    }
    if (!result.matches.length) {
      box.append(el('div', 'result', 'no matches'));
    }
    $('stat-files').textContent = String(result.filesScanned);
    $('stat-elapsed').textContent = `${Math.round(performance.now() - started)} ms`;
    setStatus(`${result.matches.length} match(es) in ${result.filesScanned} file(s) — ${result.elapsedMs.toFixed(0)} ms`);
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

// --- wiring ---------------------------------------------------------

for (const chip of document.querySelectorAll('.chip[data-kind]')) {
  chip.addEventListener('click', () => {
    for (const other of document.querySelectorAll('.chip[data-kind]')) other.classList.remove('is-active');
    chip.classList.add('is-active');
    state.kind = chip.dataset.kind;
  });
}

$('regex-toggle').addEventListener('click', (event) => {
  state.regex = !state.regex;
  event.currentTarget.classList.toggle('is-active', state.regex);
});

$('case-toggle').addEventListener('click', (event) => {
  state.caseSensitive = !state.caseSensitive;
  event.currentTarget.classList.toggle('is-active', state.caseSensitive);
});

$('analyze').addEventListener('click', runAnalysis);
$('search').addEventListener('click', runSearch);

$('target').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') runAnalysis();
});
$('pattern').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') runSearch();
});

document.addEventListener('keydown', (event) => {
  if (event.key === '/' && document.activeElement?.tagName !== 'INPUT') {
    event.preventDefault();
    $('pattern').focus();
  }
  if (event.key === 'Escape') {
    $('results').replaceChildren();
    setStatus('idle');
  }
});

api('/api/health')
  .then((health) => {
    $('build').textContent = health.version;
    $('runtime').textContent = 'node ' + (health.runtime || 'local');
    setStatus('ready — no network in use');
  })
  .catch(() => setStatus('console is not answering', 'error'));
