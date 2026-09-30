const $ = id => document.getElementById(id);
const form = $('query-form');
let report;
let selected = 0;
let tab = 'answers';
let history = [];
let running = false;
const api = window.dnsLocal;
function element(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function status(text, error = false) { $('status').textContent = text; $('status').className = error ? 'error' : ''; }
function modeChanged() {
  const mode = $('mode').value;
  $('resolver').hidden = mode !== 'public'; $('server').hidden = mode !== 'custom'; $('port-label').hidden = mode !== 'custom';
  $('mode-note').textContent = {
    system: 'Uses DNS servers configured on this device. OS per-domain routing and hosts-file overrides are not applied.',
    public: 'Queries a public recursive resolver directly. Its answer may come from cache.',
    custom: 'Connects directly to this IP. Internal nameservers require your network or VPN connection.',
    authoritative: 'Walks referrals from root servers, then shows the first responding authoritative server. Does not follow CNAME targets.',
    trace: 'Walks from the root with recursion disabled. Each referral, address lookup, and failed attempt is shown.',
    compare: 'Compares one responding authority with four public caches. Differences can reflect caching, DNS views, or geographic answers.'
  }[mode];
}
$('mode').addEventListener('change', modeChanged);
function valueText(value) {
  if (value?.type === 'Buffer') return new TextDecoder().decode(new Uint8Array(value.data));
  if (Array.isArray(value)) return value.map(valueText).join('');
  if (value && typeof value === 'object') return Object.entries(value).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join('  ');
  return String(value ?? '');
}
function showTable(records) {
  if (!records?.length) { $('content').append(element('p', tab === 'answers' && report?.request.type === 'SPF' ? 'No SPF records in this response. Check the response code, authority section, and raw packet for details.' : 'No records in this section. Check the response code and authority section for negative answers.', 'note')); return; }
  const table = element('table'); const head = element('thead'); const row = element('tr');
  for (const name of ['NAME', 'TTL', 'TYPE', 'VALUE']) row.append(element('th', name));
  head.append(row); table.append(head); const body = element('tbody');
  for (const record of records) { const tr = element('tr'); for (const value of [record.name || '.', record.ttl ?? '—', record.type, valueText(record.data ?? record)]) tr.append(element('td', String(value))); body.append(tr); }
  table.append(body); $('content').append(table);
}
function render() {
  if (!report) return;
  const current = report.results[selected];
  $('result-title').textContent = `${report.name} · ${report.request.type}`;
  $('trace-count').textContent = report.trace.length;
  $('copy').disabled = !current?.dig;
  $('export-text').disabled = false; $('export-json').disabled = false;
  $('server-cards').replaceChildren();
  report.results.forEach((result, index) => {
    const card = element('button', undefined, `server-card ${result.authoritative ? '' : 'recursive'} ${index === selected ? 'selected' : ''}`);
    card.append(element('span', result.error ? 'QUERY FAILED' : result.authoritative ? 'AUTHORITATIVE · AA=1' : 'NON-AUTHORITATIVE · AA=0', 'badge'));
    card.append(element('strong', `${result.label} · ${result.server}`));
    card.append(element('small', result.error ?? `${result.elapsedMs} ms · ${result.protocol.toUpperCase()} · ${result.packet.rcode}`));
    card.addEventListener('click', () => { selected = index; render(); }); $('server-cards').append(card);
  });
  document.querySelectorAll('[data-tab]').forEach(button => { button.classList.toggle('selected', button.dataset.tab === tab); button.setAttribute('aria-pressed', String(button.dataset.tab === tab)); });
  $('content').replaceChildren();
  if (tab === 'trace') {
    if (!report.trace.length) $('content').append(element('p', 'Choose Delegation trace, Authoritative servers, or Authority vs. public to walk from the root.', 'note'));
    report.trace.forEach((step, i) => {
      const row = element('div', undefined, 'trace-step');
      row.append(element('strong', `${String(i + 1).padStart(2, '0')}  ${step.zone}  →  ${step.server}`));
      row.append(element('div', step.purpose ?? 'Resolve original question', 'muted'));
      row.append(element('code', step.error ?? `${step.packet.rcode} · ${step.elapsedMs} ms · ${step.authoritative ? 'Authoritative answer' : 'Referral / non-authoritative'} · ${(step.packet.authorities ?? []).filter(r => r.type === 'NS').map(r => r.data).join(', ')}`));
      if (step.error) row.classList.add('failed'); $('content').append(row);
    });
    if (report.error) $('content').append(element('p', report.error, 'note failed'));
  } else if (tab === 'compare') {
    if (report.request.mode !== 'compare') $('content').append(element('p', 'Choose Authority vs. public to compare directly against the zone’s answer.', 'note'));
    else {
      $('content').append(element('p', 'TTL differences are ignored. A mismatch is evidence of different answers, not proof of propagation lag. Split DNS, geolocation, load balancing, and filtering can also differ.', 'note'));
      for (const result of report.results) { const row = element('div', undefined, 'compare-row'); row.append(element('h3', `${result.label} · ${result.server} — ${result.error ?? result.comparison ?? 'Authoritative baseline'}`)); row.append(element('pre', (result.answerRecords ?? []).map(r => `${r.name}  ${r.type}  ${valueText(r.data)}`).join('\n') || (report.request.type === 'SPF' ? 'No SPF records in this response' : 'No answer records'))); $('content').append(row); }
    }
  } else if (tab === 'raw') $('content').append(element('pre', JSON.stringify(current ?? { error: report.error, trace: report.trace }, null, 2)));
  else if (current?.error) $('content').append(element('p', current.error, 'note failed'));
  else {
    if (current?.packet) $('content').append(element('p', `Response: ${current.packet.rcode} · Flags: ${['aa', 'tc', 'rd', 'ra', 'ad', 'cd'].filter(flag => current.packet['flag_' + flag]).join(' ').toUpperCase() || 'none'} · AD is the responder’s claim, not local DNSSEC validation.`, 'note'));
    showTable(tab === 'answers' ? current?.answerRecords : current?.packet?.[tab]);
  }
}
document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click', () => { tab = button.dataset.tab; render(); }));
async function loadHistory() {
  try { history = await api.history(); drawHistory(); } catch (error) { status(error.message, true); }
}
function drawHistory() {
  $('history').replaceChildren(); const filter = $('history-search').value.toLowerCase();
  history.filter(item => `${item.request.name} ${item.request.type}`.toLowerCase().includes(filter)).forEach(item => {
    const button = element('button', undefined, 'history-item'); button.append(element('strong', item.request.name)); button.append(element('small', `${item.request.type} · ${item.request.mode} · ${new Date(item.createdAt).toLocaleDateString()}`));
    button.addEventListener('click', () => { if (running) return; for (const [key, value] of Object.entries(item.request)) { const control = form.elements.namedItem(key); if (!control) continue; if (control.type === 'checkbox') control.checked = value; else control.value = value; } modeChanged(); $('name').focus(); status('History loaded. Press Enter to run a fresh query.'); }); $('history').append(button);
  });
}
$('history-search').addEventListener('input', drawHistory);
$('clear').addEventListener('click', async () => { try { await api.clearHistory(); await loadHistory(); status('Local history cleared.'); } catch (error) { status(error.message, true); } });
form.addEventListener('submit', async event => {
  event.preventDefault(); if (running || !api) return;
  const input = Object.fromEntries(new FormData(form)); for (const key of ['rd', 'cd', 'do']) input[key] = form.elements.namedItem(key).checked;
  running = true; $('run').disabled = true; $('cancel').hidden = false;
  status('Querying DNS servers… A trace can take up to 60 seconds.');
  try {
    report = await api.query(input); selected = 0; tab = input.mode === 'trace' ? 'trace' : input.mode === 'compare' ? 'compare' : 'answers'; render();
    await loadHistory();
    const failures = report.results.filter(r => r.error).length;
    status(report.error ?? report.historyWarning ?? `Completed · ${report.results.length - failures} responses${failures ? ` · ${failures} failed` : ''} · ${new Date(report.createdAt).toLocaleTimeString()}`, Boolean(report.error || report.historyWarning || failures));
  } catch (error) { status(error.message, true); }
  finally { running = false; $('run').disabled = false; $('cancel').hidden = true; }
});
$('cancel').addEventListener('click', () => { api.cancel().catch(error => status(error.message, true)); });
$('copy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(report.results[selected].dig); status('dig command copied.'); } catch (error) { status(`Could not copy: ${error.message}`, true); } });
for (const format of ['text', 'json']) $('export-' + format).addEventListener('click', async () => { try { if (await api.export(format === 'text' ? 'txt' : 'json')) status('Report saved.'); } catch (error) { status(error.message, true); } });
document.addEventListener('keydown', event => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'l') { event.preventDefault(); $('name').focus(); $('name').select(); } if (event.key === 'Escape' && running) api.cancel(); });
modeChanged();
if (api) loadHistory(); else status('Open DNS Local with its desktop launcher to connect the local engine.');
