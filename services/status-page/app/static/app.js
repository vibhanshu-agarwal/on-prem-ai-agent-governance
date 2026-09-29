"use strict";
/* Agent Control Room. Vanilla JS. All data comes from this origin's /api/* (a thin proxy of the
   control-plane API); no tokens exist in the browser. Text is always inserted with textContent. */

const $ = (s, r = document) => r.querySelector(s);
const state = {
  cfg: null, persona: null, agents: [], live: {}, filter: 'all', q: '', showAll: false, shown: 24,
  disc: { pending: [], pending_total: 0 }, quar: [], audit: [], lastSeq: 0, alerts: 0, up: null,
};

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) el.append(k.nodeType ? k : document.createTextNode(String(k)));
  return el;
}

async function api(path, opts = {}) {
  const init = { method: opts.method || 'GET', headers: { 'X-Persona': state.persona || '' } };
  if (init.method !== 'GET') {
    init.headers['X-Requested-With'] = 'status-page';
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body || {});
  }
  const r = await fetch(path, init);
  let j = null; try { j = await r.json(); } catch (e) { /* empty */ }
  if (!r.ok) throw new Error((j && j.detail) || `HTTP ${r.status}`);
  return j;
}

function toast(msg, kind) {
  const t = h('div', { class: 'toast ' + (kind || '') }, msg);
  $('#toasts').append(t); setTimeout(() => t.remove(), kind === 'bad' ? 7000 : 4500);
}

const usd = n => '$' + (n || 0).toFixed((n || 0) < 1 ? 3 : 2);
const ago = ts => {
  const s = Math.max(0, Date.now() / 1000 - (typeof ts === 'string' ? Date.parse(ts) / 1000 : ts));
  if (s < 60) return Math.round(s) + 's'; if (s < 3600) return Math.round(s / 60) + 'm';
  if (s < 86400) return Math.round(s / 3600) + 'h'; return Math.round(s / 86400) + 'd';
};
const hhmmss = ts => new Date(ts).toLocaleTimeString([], { hour12: false });
const me = () => (state.cfg?.personas || []).find(p => p.name === state.persona) || { roles: [], teams: [] };
const can = role => me().roles.includes(role) || me().roles.includes('admin');

/* ---------- dialog ---------- */
function dialog(content) {
  const d = $('#dlg'), f = $('#dlgForm');
  f.replaceChildren(h('div', { class: 'dlg' }, content));
  if (!d.open) d.showModal();
  return d;
}
const closeDialog = () => $('#dlg').open && $('#dlg').close();
$('#dlg').addEventListener('click', e => { if (e.target === $('#dlg')) closeDialog(); });

/* ---------- KPIs ---------- */
function renderKpis() {
  const roots = state.agents.filter(a => !a.parent_agent_id);
  const count = s => roots.filter(a => a.status === s).length;
  const spend = Object.values(state.live).reduce((s, v) => s + (v.live?.spend_usd || 0), 0);
  const kp = (v, l, cls) => h('div', { class: 'kpi ' + (cls || '') }, h('div', { class: 'v' }, v), h('div', { class: 'l' }, l));
  $('#kpis').replaceChildren(
    kp(count('active'), 'agents running'),
    kp(count('stopped') + count('quarantined'), 'stopped or quarantined', count('quarantined') + count('stopped') ? 'warn' : ''),
    kp(usd(spend), 'spend on screen (30 d)'),
    kp(state.disc.pending_total, 'awaiting approval', state.disc.pending_total ? 'warn' : ''),
    kp(state.alerts, 'alerts in audit log', state.alerts ? 'bad' : ''),
  );
}

/* ---------- agents ---------- */
function visibleAgents() {
  const q = state.q.toLowerCase();
  let list = state.agents.filter(a => state.showAll || !a.parent_agent_id);
  if (state.filter !== 'all') list = list.filter(a => a.status === state.filter);
  if (q) list = list.filter(a => [a.agent_id, a.team, a.owner, a.display_name].some(x => (x || '').toLowerCase().includes(q)));
  return list.sort((a, b) => a.created_at - b.created_at);
}

function agentCard(a) {
  const lv = state.live[a.agent_id];
  const l = lv?.live;
  const spend = l?.spend_usd ?? null, budget = l?.max_budget_usd ?? a.max_budget_usd;
  const pct = spend != null && budget ? Math.min(100, spend / budget * 100) : 0;
  const cls = pct >= 100 ? 'bad' : pct >= 80 ? 'warn' : '';
  const running = l ? (l.workloads || []).filter(w => w.running).length : null;
  const stopped = a.status !== 'active';
  const events = lv?.events || [];
  return h('article', { class: 'card ' + a.status, dataset: { id: a.agent_id } },
    h('div', { class: 'card-top' },
      h('div', {}, h('div', { class: 'name' }, a.agent_id), h('div', { class: 'sub' }, a.display_name || '')),
      h('span', { class: 'status ' + a.status }, a.status)),
    h('div', { class: 'tags' },
      h('span', { class: 'tag' }, 'owner ', a.owner), h('span', { class: 'tag' }, 'team ', a.team),
      h('span', { class: 'tag tier-' + a.sandbox_tier, title: 'Sandbox isolation tier' }, a.sandbox_tier),
      h('span', { class: 'tag' }, a.auth === 'sso' ? 'SSO token' : 'API key'),
      a.delegation_depth ? h('span', { class: 'tag' }, 'delegate d' + a.delegation_depth) : null),
    h('div', { class: 'spend' },
      h('div', { class: 'spend-row' }, h('span', { class: 'muted' }, 'Spend vs budget'),
        h('span', {}, h('b', {}, spend == null ? '...' : usd(spend)), h('span', { class: 'muted' }, ' / ' + usd(budget)))),
      h('div', { class: 'bar', role: 'progressbar', 'aria-valuenow': Math.round(pct), 'aria-valuemin': 0, 'aria-valuemax': 100 },
        h('i', { class: cls, style: `width:${pct}%` }))),
    h('div', { class: 'wl' },
      running == null ? 'loading workloads' : `${running} workload${running === 1 ? '' : 's'} running`,
      l && l.keys ? h('span', {}, `${l.keys.filter(k => k.blocked).length}/${l.keys.length} keys blocked`) : null,
      l?.delegates?.length ? h('span', {}, `${l.delegates.length} delegates`) : null),
    h('div', {}, h('div', { class: 'ev-title' }, 'Recent activity'),
      h('ul', { class: 'ev' }, events.length ? events.slice(0, 4).map(e =>
        h('li', { class: e.severity === 'alert' ? 'alert' : '' }, h('span', {}, e.action), h('span', {}, ago(e.ts)))) :
        h('li', { class: 'none' }, lv ? 'no audit events' : '...'))),
    h('div', { class: 'card-actions' },
      stopped
        ? h('button', { class: 'btn', disabled: !can('operator'), onclick: () => resumeDialog(a) }, 'Resume')
        : h('button', { class: 'btn danger', disabled: !can('operator'), title: can('operator') ? '' : 'operator role required',
          onclick: () => stopDialog(a) }, 'Stop agent')));
}

function renderAgents() {
  const list = visibleAgents(), page = list.slice(0, state.shown);
  const grid = $('#grid');
  if (!state.agents.length) { grid.replaceChildren(...[1, 2, 3].map(() => h('div', { class: 'skeleton' }))); return; }
  grid.replaceChildren(...page.map(agentCard));
  if (!page.length) grid.replaceChildren(h('p', { class: 'muted' }, 'No agents match this filter.'));
  $('#moreBtn').hidden = list.length <= state.shown;
  $('#count').textContent = `${Math.min(list.length, state.shown)} of ${list.length}`;
  const chips = [['active', 'Running'], ['stopped', 'Stopped'], ['quarantined', 'Quarantined'], ['all', 'All']];
  $('#statusChips').replaceChildren(...chips.map(([k, lbl]) => h('button', {
    class: 'chip', 'aria-pressed': state.filter === k, onclick: () => { state.filter = k; state.shown = 24; renderAgents(); refreshLive(); },
  }, lbl)));
}

async function refreshAgents() {
  const d = await api('/api/agents'); state.agents = d.agents; renderAgents(); renderKpis();
}
async function refreshLive() {
  const ids = visibleAgents().slice(0, state.shown).map(a => a.agent_id);
  if (!ids.length) return;
  const d = await api('/api/live?ids=' + encodeURIComponent(ids.join(',')));
  Object.assign(state.live, d); renderAgents(); renderKpis();
}

/* ---------- stop / resume ---------- */
function stopDialog(a) {
  const reason = h('input', { type: 'text', placeholder: 'e.g. runaway spend, suspicious tool calls', maxlength: 200, autofocus: true });
  const go = h('button', { class: 'btn danger', type: 'button' }, 'Stop agent now');
  go.onclick = async () => {
    if (!reason.value.trim()) { reason.focus(); return; }
    go.disabled = true; go.textContent = 'Stopping...';
    try {
      const r = await api(`/api/agents/${encodeURIComponent(a.agent_id)}/stop`, { method: 'POST', body: { reason: reason.value.trim() } });
      const t = r.timings_ms || r.report?.timings_ms || {};
      closeDialog();
      const secs = t.total ? (t.total / 1000).toFixed(1) + ' s' : 'done';
      toast(`${a.agent_id} stopped and verified (${secs}).`, 'ok');
    } catch (e) { toast('Stop failed: ' + e.message, 'bad'); go.disabled = false; go.textContent = 'Stop agent now'; }
    refreshAll();
  };
  dialog([
    h('h3', {}, `Stop ${a.agent_id}?`),
    h('div', { class: 'note bad' }, 'This blocks the agent\'s gateway keys, resets its live connections, detaches it from the network, stops the workload and revokes its credentials. New requests are refused within about a second; the full, verified sequence takes about five.'),
    h('div', { class: 'tags' }, h('span', { class: 'tag' }, 'owner ', a.owner), h('span', { class: 'tag' }, 'team ', a.team), h('span', { class: 'tag' }, a.sandbox_tier)),
    h('label', {}, 'Reason (recorded in the audit log)', reason),
    h('div', { class: 'btns' }, h('button', { class: 'btn', type: 'button', onclick: closeDialog }, 'Cancel'), go),
  ]);
}
function resumeDialog(a) {
  const reason = h('input', { type: 'text', placeholder: 'why is it safe to resume?', maxlength: 200 });
  const go = h('button', { class: 'btn primary', type: 'button' }, 'Resume agent');
  go.onclick = async () => {
    if (!reason.value.trim()) { reason.focus(); return; }
    go.disabled = true;
    try { await api(`/api/agents/${encodeURIComponent(a.agent_id)}/resume`, { method: 'POST', body: { reason: reason.value.trim() } });
      closeDialog(); toast(`${a.agent_id} resumed (revoked credentials stay revoked).`, 'ok'); }
    catch (e) { toast('Resume failed: ' + e.message, 'bad'); go.disabled = false; }
    refreshAll();
  };
  dialog([h('h3', {}, `Resume ${a.agent_id}?`),
    h('div', { class: 'note warn' }, 'Keys are unblocked and the workload restarts. Credentials revoked by the stop are not restored.'),
    h('label', {}, 'Reason', reason),
    h('div', { class: 'btns' }, h('button', { class: 'btn', type: 'button', onclick: closeDialog }, 'Cancel'), go)]);
}

/* ---------- bulk quarantine ---------- */
function bulkDialog() {
  const teams = [...new Set(state.agents.map(a => a.team))].sort();
  const mode = h('select', {}, h('option', { value: 'team' }, 'By team'), h('option', { value: 'image' }, 'By container image'),
    h('option', { value: 'all' }, 'Entire fleet'));
  const team = h('select', {}, teams.map(t => h('option', { value: t }, t)));
  const image = h('input', { type: 'text', placeholder: 'govpilot/agents:1' });
  const target = h('div', {}, team);
  const out = h('div', { class: 'stack' });
  const reason = h('input', { type: 'text', placeholder: 'incident reference / why', maxlength: 200 });
  const fire = h('button', { class: 'btn danger', type: 'button', disabled: true }, 'Request quarantine');
  let prev = null;
  mode.onchange = () => { target.replaceChildren(mode.value === 'team' ? team : mode.value === 'image' ? image : h('div', { class: 'note warn' }, 'Every registered agent.')); reset(); };
  const reset = () => { prev = null; fire.disabled = true; out.replaceChildren(); };
  team.onchange = image.oninput = reset;
  const selector = () => mode.value === 'team' ? { team: team.value } : mode.value === 'image' ? { image: image.value.trim() } : { all: true };
  const previewBtn = h('button', { class: 'btn', type: 'button' }, 'Preview blast radius');
  previewBtn.onclick = async () => {
    previewBtn.disabled = true;
    try {
      prev = await api('/api/quarantine/preview', { method: 'POST', body: selector() });
      const c = prev.counts;
      const stat = (n, l) => h('div', {}, h('b', {}, n), h('span', {}, l));
      out.replaceChildren(...[
        h('div', { class: 'stats' }, stat(c.agents, 'agents'), stat(c.running_workloads, 'running workloads'), stat(c.gateway_keys, 'gateway keys'), stat(c.credentials + c.oidc_subjects, 'credentials')),
        c.unmanaged_workloads ? h('div', { class: 'note warn' }, `${c.unmanaged_workloads} unregistered workload(s) match the image and would be stopped too.`) : null,
        h('div', { class: 'chipl' }, prev.agent_ids.map(i => h('span', { class: 'tag' }, i))),
        prev.fleet_wide
          ? h('div', { class: 'note bad' }, h('b', {}, 'Fleet-wide action: two-person rule. '), `It needs ${prev.approvals_required} approvals from ${prev.approvals_required} different humans, neither of them you (${state.persona}). Nothing is stopped until both approve.`)
          : h('div', { class: 'note ok' }, 'Small blast radius: runs immediately when requested.')].filter(Boolean));
      fire.disabled = !c.agents && !c.unmanaged_workloads;
    } catch (e) { out.replaceChildren(h('div', { class: 'note bad' }, e.message)); }
    previewBtn.disabled = false;
  };
  fire.onclick = async () => {
    if (!reason.value.trim()) { reason.focus(); return; }
    fire.disabled = true;
    try {
      const a = await api('/api/quarantine/actions', { method: 'POST', body: { preview_id: prev.preview_id, reason: reason.value.trim() } });
      closeDialog();
      toast(a.status === 'pending_approval' ? `Requested. Waiting for ${a.approvals_required} approvals.` : 'Quarantine executed.', 'ok');
    } catch (e) { toast('Failed: ' + e.message, 'bad'); fire.disabled = false; }
    refreshAll();
  };
  dialog([
    h('h3', {}, 'Bulk quarantine'),
    h('p', { class: 'muted', style: 'margin:0' }, 'Choose who to isolate, preview exactly what would be stopped, then request it. Acting as ', h('b', {}, state.persona), '.'),
    h('div', { class: 'two' }, h('label', {}, 'Selector', mode), h('label', {}, 'Value', target)),
    previewBtn, out,
    h('label', {}, 'Reason', reason),
    h('div', { class: 'btns' }, h('button', { class: 'btn', type: 'button', onclick: closeDialog }, 'Close'), fire),
  ]);
}

function renderQuar() {
  const box = $('#qList');
  if (!state.quar.length) { box.replaceChildren(h('p', { class: 'muted' }, 'No quarantine actions yet.')); return; }
  box.replaceChildren(...state.quar.slice(0, 4).map(a => {
    const sel = Object.entries(a.selector).flatMap(([k, v]) => {
      if (!v || (Array.isArray(v) && !v.length)) return [];
      if (typeof v === 'object' && !Array.isArray(v)) return Object.entries(v).map(([lk, lv]) => `${lk}=${lv}`);
      return [`${k}: ${v}`];
    }).join(', ') || '-';
    const pend = a.status === 'pending_approval';
    const need = a.approvals_required || 0;
    return h('div', { class: 'item' },
      h('div', { class: 'row' }, h('b', {}, sel), h('span', { class: 'status ' + (pend ? 'pending' : a.status === 'executed' ? 'quarantined' : 'active') }, pend ? 'awaiting approval' : a.status)),
      h('div', { class: 'muted' }, `${a.reason} - by ${a.requested_by}, ${ago(a.requested_at)} ago`),
      need ? h('div', { class: 'steps' }, [...Array(need)].map((_, i) => h('i', { class: i < a.approvals.length ? 'done' : '' })),
        `${a.approvals.length}/${need} approvals`, a.approvals.length ? ` (${a.approvals.map(x => x.by).join(', ')})` : '') : null,
      h('div', { class: 'acts' },
        pend ? h('button', { class: 'btn sm primary', disabled: !can('approver'), onclick: () => approveQ(a) }, `Approve as ${state.persona}`) : null,
        a.status === 'executed' ? h('button', { class: 'btn sm', disabled: !can('operator'), onclick: () => liftQ(a) }, 'Lift') : null));
  }));
}
async function approveQ(a) {
  try { const r = await api(`/api/quarantine/actions/${a.action_id}/approve`, { method: 'POST' });
    toast(r.status === 'executed' || r.status === 'executing' ? 'Second approval recorded: quarantine executing.' : 'Approval recorded.', 'ok'); }
  catch (e) { toast(e.message, 'bad'); }
  refreshAll();
}
async function liftQ(a) {
  if (!confirm('Lift this quarantine and resume its agents?')) return;
  try { await api(`/api/quarantine/actions/${a.action_id}/lift`, { method: 'POST', body: { resume_agents: true } }); toast('Quarantine lifted.', 'ok'); }
  catch (e) { toast(e.message, 'bad'); }
  refreshAll();
}

/* ---------- discovery ---------- */
function renderDisc() {
  const d = state.disc;
  $('#discBadge').textContent = d.pending_total ? d.pending_total + ' pending' : '';
  const box = $('#discList');
  if (!d.pending.length) { box.replaceChildren(h('p', { class: 'muted' }, 'Queue is empty. Nothing unregistered has been seen.')); return; }
  box.replaceChildren(...d.pending.slice(0, 5).map(p => {
    const o = p.observation, ev = o.evidence || {};
    const spoof = ev.spoof_of || (p.reason || '').toLowerCase().includes('spoof');
    return h('div', { class: 'item' },
      h('div', { class: 'row' }, h('b', {}, o.name), h('span', { class: 'tag' }, p.feed)),
      h('div', { class: 'muted' }, `${o.kind}${o.image ? ' - ' + o.image : ''} - seen ${ago(p.created_at)} ago - budget ${usd(p.budget_usd)}, no key`),
      spoof ? h('div', { class: 'note bad' }, 'Possible spoof of a registered agent.') : null,
      h('div', { class: 'acts' },
        h('button', { class: 'btn sm primary', onclick: () => approveDisc(p) }, 'Approve'),
        h('button', { class: 'btn sm', onclick: () => rejectDisc(p) }, 'Reject')));
  }));
  if (d.pending_total > 5) box.append(h('p', { class: 'muted' }, `+ ${d.pending_total - 5} more in the queue`));
}
function approveDisc(p) {
  const o = p.observation;
  const teams = [...new Set(state.agents.map(a => a.team))].sort();
  const team = h('select', {}, teams.map(t => h('option', { value: t, selected: t === o.suggested_team }, t)));
  const budget = h('input', { type: 'number', min: 0, step: '0.5', value: '1' });
  const models = h('input', { type: 'text', value: 'mock-local' });
  const tier = h('select', {}, ['container', 'gvisor', 'microvm'].map(t => h('option', { value: t }, t)));
  const go = h('button', { class: 'btn primary', type: 'button' }, 'Approve and create key');
  go.onclick = async () => {
    go.disabled = true;
    try {
      const r = await api(`/api/discovery/${p.proposal_id}/approve`, { method: 'POST', body: { team: team.value, max_budget_usd: parseFloat(budget.value) || 0,
        models: models.value.split(',').map(s => s.trim()).filter(Boolean), sandbox_tier: tier.value } });
      closeDialog(); toast(`Registered ${r.agent_id || o.name} with a key and a ${usd(parseFloat(budget.value))} budget.`, 'ok');
    } catch (e) { toast(e.message, 'bad'); go.disabled = false; }
    refreshAll();
  };
  dialog([h('h3', {}, `Approve ${o.name}?`),
    h('div', { class: 'note' }, `Only a human owner of the chosen team can approve. You are ${state.persona} (${me().roles.join(', ') || 'no roles'}${me().teams.length ? '; owns ' + me().teams.join(', ') : ''}).`),
    h('div', { class: 'two' }, h('label', {}, 'Team', team), h('label', {}, 'Budget (USD / 30 d)', budget)),
    h('div', { class: 'two' }, h('label', {}, 'Allowed models', models), h('label', {}, 'Sandbox tier', tier)),
    h('div', { class: 'btns' }, h('button', { class: 'btn', type: 'button', onclick: closeDialog }, 'Cancel'), go)]);
}
function rejectDisc(p) {
  const reason = h('input', { type: 'text', placeholder: 'reason', value: 'not an approved agent' });
  const go = h('button', { class: 'btn danger', type: 'button' }, 'Reject');
  go.onclick = async () => {
    go.disabled = true;
    try { await api(`/api/discovery/${p.proposal_id}/reject`, { method: 'POST', body: { reason: reason.value.trim() || 'rejected' } }); closeDialog(); toast('Rejected.', 'ok'); }
    catch (e) { toast(e.message, 'bad'); go.disabled = false; }
    refreshAll();
  };
  dialog([h('h3', {}, `Reject ${p.observation.name}?`), h('label', {}, 'Reason', reason),
    h('div', { class: 'btns' }, h('button', { class: 'btn', type: 'button', onclick: closeDialog }, 'Cancel'), go)]);
}

/* ---------- audit feed ---------- */
function auditLine(r, isNew) {
  return h('div', { class: 'fl' + (isNew ? ' new' : '') },
    h('span', { class: 't' }, hhmmss(r.ts)),
    h('div', {}, h('div', { class: 'a ' + r.severity }, r.action),
      h('div', { class: 'm' }, `${r.target || '-'} by ${r.actor} #${r.seq}`)));
}
async function refreshAudit(first) {
  const d = await api(`/api/audit?limit=${first ? 40 : 100}&since_seq=${first ? 0 : state.lastSeq}`);
  const recs = d.records.filter(r => r.seq > state.lastSeq);
  if (!recs.length) return;
  state.lastSeq = Math.max(...recs.map(r => r.seq));
  const feed = $('#audit');
  const lines = recs.sort((a, b) => b.seq - a.seq).map(r => auditLine(r, !first));
  feed.prepend(...lines);
  while (feed.children.length > 80) feed.lastChild.remove();
}

/* ---------- misc ---------- */
async function refreshSide() {
  const [d, q, al] = await Promise.all([api('/api/discovery'), api('/api/quarantine/actions'), api('/api/alerts')]);
  state.disc = d; state.quar = q.actions; state.alerts = al.count; renderDisc(); renderQuar(); renderKpis();
}
async function refreshHealth() {
  try { const r = await (await fetch('/api/health')).json(); state.up = r.control_plane; } catch (e) { state.up = false; }
  const p = $('#health'); p.className = 'pill ' + (state.up ? 'ok' : 'bad');
  p.lastChild.textContent = state.up ? 'control plane healthy' : 'control plane unreachable';
}
const guard = fn => async (...a) => { try { await fn(...a); } catch (e) { if (state.up !== false) console.warn(e.message); } };
const refreshAll = guard(async () => { await Promise.all([refreshAgents().then(refreshLive), refreshSide(), refreshAudit(false)]); });

async function init() {
  state.cfg = await (await fetch('/api/config')).json();
  $('#grafana').href = state.cfg.grafana; $('#docs').href = state.cfg.api_docs; $('#openlit').href = state.cfg.openlit;
  let saved = null; try { saved = localStorage.getItem('persona'); } catch (e) { /* ignore */ }
  state.persona = state.cfg.personas.some(p => p.name === saved) ? saved : state.cfg.default;
  const sel = $('#persona');
  sel.replaceChildren(...state.cfg.personas.map(p => h('option', { value: p.name, selected: p.name === state.persona }, `${p.name} (${p.roles.filter(r => r !== 'admin').join(', ') || 'no roles'})`)));
  sel.onchange = () => { state.persona = sel.value; try { localStorage.setItem('persona', sel.value); } catch (e) { /* ignore */ }
    state.live = {}; $('#audit').replaceChildren(); state.lastSeq = 0; refreshAll(); refreshAudit(true); };
  $('#search').oninput = e => { state.q = e.target.value; state.shown = 24; renderAgents(); };
  $('#showAll').onchange = e => { state.showAll = e.target.checked; state.shown = 24; renderAgents(); refreshLive(); };
  $('#moreBtn').onclick = () => { state.shown += 24; renderAgents(); refreshLive(); };
  $('#bulkBtn').onclick = bulkDialog;
  $('#theme').onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = next;
    try { localStorage.setItem('theme', next); } catch (e) { /* ignore */ }
  };
  $('#verify').onclick = async e => {
    e.preventDefault();
    try { const r = await api('/api/audit/verify'); $('#chain').textContent = r.ok ? `Chain verified: ${r.count} records intact.` : 'CHAIN BROKEN at seq ' + r.first_bad_seq; }
    catch (err) { toast(err.message, 'bad'); }
  };
  renderAgents(); renderQuar(); renderDisc();
  await refreshHealth();
  await refreshAll(); await guard(refreshAudit)(true);
  setInterval(guard(refreshHealth), 5000);
  setInterval(guard(refreshAgents), 6000);
  setInterval(guard(refreshLive), 3000);
  setInterval(guard(refreshSide), 4000);
  setInterval(guard(() => refreshAudit(false)), 2500);
}
init().catch(e => toast('Failed to start: ' + e.message, 'bad'));
