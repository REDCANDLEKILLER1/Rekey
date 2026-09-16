/**
 * XRPMAN REKEY V8 — ui.js
 * HUD rendering. Presentation only: no ledger calls, no key handling, no decisions.
 *
 * Everything the ledger or the operator supplies is written with textContent and
 * never with innerHTML, so an account that carries a hostile-looking domain or
 * memo cannot inject markup into the wizard.
 */

export const $ = (id) => document.getElementById(id);

export function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

export function clear(node) {
  while (node && node.firstChild) node.removeChild(node.firstChild);
}

/* ---------- Terminal ---------- */

const MAX_LOG_LINES = 400;

export function log(message, type = 'info') {
  const terminal = $('terminal');
  if (!terminal) return;
  const line = el('div', `t-${type}`, `[${new Date().toLocaleTimeString()}] ${message}`);
  terminal.prepend(line);
  while (terminal.childElementCount > MAX_LOG_LINES) terminal.lastElementChild.remove();
}

export function logStep(title) {
  log(`── ${title} ──`, 'step');
}

/* ---------- Busy ---------- */

export function setBusy(busy) {
  const bar = $('busy');
  if (bar) bar.dataset.busy = busy ? 'true' : 'false';
  document.body.setAttribute('aria-busy', busy ? 'true' : 'false');
}

/* ---------- Chips ---------- */

export function setChip(id, value, state = 'ok') {
  const chip = $(id);
  if (!chip) return;
  chip.className = `chip ${state === 'ok' ? '' : state}`.trim();
  clear(chip);
  chip.append(el('b', null, chip.dataset.label || ''), document.createTextNode(` ${value}`));
}

/* ---------- Progress rail ---------- */

export const STEPS = Object.freeze([
  { id: 'p1', n: '01', label: 'Scan' },
  { id: 'p2', n: '02', label: 'Authority' },
  { id: 'p3', n: '03', label: 'New Key' },
  { id: 'p4', n: '04', label: 'Rekey' },
  { id: 'p5', n: '05', label: 'Verify Ledger' },
  { id: 'p6', n: '06', label: 'Prove Control' },
  { id: 'p7', n: '07', label: 'Disable Master' },
  { id: 'p8', n: '08', label: 'Final Audit' },
]);

export function renderRail(currentIndex, completed) {
  const rail = $('rail');
  if (!rail) return;
  clear(rail);
  STEPS.forEach((step, index) => {
    const node = el('div', 'rail-step');
    node.append(el('span', 'n', step.n), el('span', 'lbl', step.label.toUpperCase()));
    if (completed.has(index)) node.dataset.state = 'done';
    else if (index === currentIndex) node.dataset.state = 'active';
    else if (index < currentIndex) node.dataset.state = 'done';
    else node.dataset.state = 'locked';
    rail.append(node);
  });
}

export function setPanelState(panelId, state) {
  const panel = $(panelId);
  if (!panel) return;
  panel.dataset.locked = state === 'locked' ? 'true' : 'false';
  panel.dataset.state = state;
}

export function focusPanel(panelId) {
  const panel = $(panelId);
  if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ---------- Readouts ---------- */

/** rows: [[term, value, tone]] — tone is one of ok | warn | bad | none. */
export function renderReadout(containerId, rows) {
  const container = $(containerId);
  if (!container) return;
  clear(container);
  for (const [term, value, tone] of rows) {
    container.append(el('dt', null, term));
    container.append(el('dd', tone || '', value === null || value === undefined ? '—' : value));
  }
}

/* ---------- Checklists ---------- */

export function renderChecklist(containerId, checks) {
  const container = $(containerId);
  if (!container) return;
  clear(container);
  for (const check of checks) {
    const item = el('li', null, check.label);
    item.dataset.ok = check.ok ? 'true' : 'false';
    container.append(item);
  }
}

/* ---------- Notices ---------- */

export function renderNotices(containerId, notices) {
  const container = $(containerId);
  if (!container) return;
  clear(container);
  for (const notice of notices) {
    const level = notice.level === 'error' ? 'error' : notice.level === 'warn' ? 'warn' : '';
    container.append(el('div', `notice ${level}`.trim(), notice.text));
  }
}

export function notice(containerId, text, level = 'info') {
  renderNotices(containerId, [{ level, text }]);
}

/* ---------- Immutable confirmation block ---------- */

export function renderConfirm(containerId, rows, danger = false) {
  const container = $(containerId);
  if (!container) return;
  clear(container);
  container.className = `confirm${danger ? ' danger' : ''}`;
  for (const [key, value] of rows) {
    const row = el('div', 'row');
    row.append(el('span', 'k', key), el('span', 'v', value));
    container.append(row);
  }
}

/* ---------- Candidate picker ---------- */

export function renderCandidates(containerId, candidates, name, onSelect) {
  const container = $(containerId);
  if (!container) return;
  clear(container);

  candidates.forEach((candidate, index) => {
    const label = el('label', 'candidate');
    label.dataset.exists = candidate.exists ? 'true' : 'false';

    const radio = el('input');
    radio.type = 'radio';
    radio.name = name;
    radio.value = String(index);
    radio.checked = Boolean(candidate.selected);
    radio.addEventListener('change', () => onSelect(index));

    const meta = el('div', 'meta');
    meta.append(el('span', 'addr', candidate.address));
    meta.append(
      el(
        'span',
        'sub',
        `${candidate.algorithmLabel} · ${
          candidate.exists ? `FUNDED · ${candidate.balanceXrp} XRP` : 'NOT FOUND ON LEDGER'
        }`,
      ),
    );

    label.append(radio, meta);
    container.append(label);
  });
}

/* ---------- Secret rendering ---------- */

export function renderSecretBlock(containerId, entries) {
  const container = $(containerId);
  if (!container) return;
  clear(container);

  for (const entry of entries) {
    const block = el('div', 'secret-block');
    block.append(el('span', 'k', entry.label));

    if (entry.groups) {
      const grid = el('div', 'sn-grid');
      entry.groups.forEach((group, index) => {
        const cell = el('div', 'sn-item');
        cell.append(el('span', 'lbl', String.fromCharCode(65 + index)), document.createTextNode(group));
        grid.append(cell);
      });
      block.append(grid);
    } else {
      const value = el('span', `v${entry.masked ? ' masked' : ''}`, entry.value);
      block.append(value);
    }

    if (entry.hint) block.append(el('p', 'hint', entry.hint));
    container.append(block);
  }
}

/* ---------- Transaction receipts ---------- */

export function renderTransactions(containerId, records) {
  const container = $(containerId);
  if (!container) return;
  clear(container);

  for (const record of records) {
    const item = el('li');
    item.append(el('span', 'lbl', record.label));
    const link = el('a', null, record.hash);
    link.href = record.explorer;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    item.append(link);
    item.append(el('span', 'sub', ` · ${record.result} · ledger ${record.ledgerIndex ?? '—'}`));
    container.append(item);
  }
}

export function renderAudit(containerId, text) {
  const container = $(containerId);
  if (!container) return;
  container.textContent = text;
}

/* ---------- Misc ---------- */

export function setHidden(id, hidden) {
  const node = $(id);
  if (node) node.hidden = Boolean(hidden);
}

export function setDisabled(id, disabled) {
  const node = $(id);
  if (node) node.disabled = Boolean(disabled);
}

export function setText(id, text) {
  const node = $(id);
  if (node) node.textContent = text === null || text === undefined ? '—' : String(text);
}
