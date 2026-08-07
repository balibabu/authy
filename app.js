(() => {
  'use strict';

  const STORAGE_KEY = 'totp:accounts';
  const EXPIRY_DAYS = 7;

  // ---------- Base32 decoding ----------
  const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function base32ToBytes(secret) {
    const clean = String(secret).toUpperCase().replace(/\s+/g, '').replace(/=+$/, '');
    const lookup = {};
    for (let i = 0; i < BASE32_ALPHABET.length; i++) lookup[BASE32_ALPHABET[i]] = i;

    let bits = 0, value = 0;
    const output = [];
    for (const ch of clean) {
      if (!(ch in lookup)) throw new Error('Invalid Base32 character: ' + ch);
      value = (value << 5) | lookup[ch];
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        output.push((value >>> bits) & 0xff);
      }
    }
    return new Uint8Array(output);
  }

  // ---------- Crypto helpers ----------
  function bufToHex(arr) {
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function importHmacKey(secretBytes) {
    return crypto.subtle.importKey(
      'raw',
      secretBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );
  }

  async function hmacSha1(key, counterBytes) {
    const sig = await crypto.subtle.sign('HMAC', key, counterBytes);
    return new Uint8Array(sig);
  }

  // ---------- HOTP / TOTP (RFC 4226 / 6238) ----------
  async function hotp(secretBytes, counter) {
    const key = await importHmacKey(secretBytes);
    // 8-byte big-endian counter
    const counterBytes = new ArrayBuffer(8);
    const view = new DataView(counterBytes);
    // JS safe for 32-bit high/low; counters fit well within range
    view.setUint32(0, Math.floor(counter / 0x100000000));
    view.setUint32(4, counter & 0xffffffff);

    const hash = await hmacSha1(key, counterBytes);
    const offset = hash[hash.length - 1] & 0x0f;
    const binary =
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);
    return binary % 1000000;
  }

  async function totp(secret, period = 30) {
    const secretBytes = base32ToBytes(secret);
    const counter = Math.floor(Date.now() / 1000 / period);
    const code = await hotp(secretBytes, counter);
    return String(code).padStart(6, '0');
  }

  function secondsRemaining(period = 30) {
    return period - (Math.floor(Date.now() / 1000) % period);
  }

  // ---------- Storage ----------
  function loadAccounts() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const data = JSON.parse(raw);
      if (!Array.isArray(data)) return [];
      return data.filter(a => a && typeof a.id === 'string' && typeof a.secret === 'string');
    } catch {
      return [];
    }
  }

  function saveAccounts(accounts) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts));
  }

  // remove accounts older than EXPIRY_DAYS since lastAccessed
  function pruneExpired(accounts) {
    const now = Date.now();
    const limit = EXPIRY_DAYS * 24 * 60 * 60 * 1000;
    const kept = accounts.filter(a => (a.lastAccessed || a.createdAt || now) + limit > now);
    if (kept.length !== accounts.length) saveAccounts(kept);
    return kept;
  }

  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return 'id-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }

  // ---------- UI elements ----------
  const $ = (sel) => document.querySelector(sel);
  const listEl = $('#list');
  const emptyEl = $('#empty');
  const clearWrap = $('#clearWrap');
  const toastEl = $('#toast');

  let accounts = [];
  const codeCache = new Map(); // id -> { code, counter }
  let toastTimer = null;

  function showToast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.remove('opacity-0', 'translate-y-4');
    toastEl.classList.add('opacity-100', 'translate-y-0');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toastEl.classList.add('opacity-0', 'translate-y-4');
      toastEl.classList.remove('opacity-100', 'translate-y-0');
    }, 1600);
  }

  // Build HTML entities from char codes to avoid literal entity sequences.
  const AMP = String.fromCharCode(38);
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => {
      switch (c) {
        case AMP: return AMP + 'amp;';
        case '<': return AMP + 'lt;';
        case '>': return AMP + 'gt;';
        case '"': return AMP + 'quot;';
        default: return AMP + '#39;';
      }
    });
  }

  function renderSkeleton() {
    listEl.innerHTML = '';
    emptyEl.classList.add('hidden');
  }

  function renderEmpty() {
    listEl.innerHTML = '';
    emptyEl.classList.remove('hidden');
    clearWrap.classList.add('hidden');
  }

  function progressRingSVG(ratio, remaining) {
    const r = 14;
    const c = 2 * Math.PI * r;
    const offset = c * (1 - ratio);
    const danger = remaining <= 5;
    return `
      <svg width="36" height="36" viewBox="0 0 36 36" class="-rotate-90">
        <circle cx="18" cy="18" r="${r}" fill="none" stroke="currentColor" stroke-width="3" class="text-slate-800"></circle>
        <circle cx="18" cy="18" r="${r}" fill="none"
          stroke="currentColor" stroke-width="3" stroke-linecap="round"
          class="${danger ? 'text-rose-400' : 'text-brand-400'}"
          stroke-dasharray="${c}" stroke-dashoffset="${offset}"></circle>
      </svg>
      <span class="absolute inset-0 flex items-center justify-center text-[11px] font-mono ${danger ? 'text-rose-300' : 'text-slate-300'}">${remaining}</span>
    `;
  }

  function createCard(account) {
    const card = document.createElement('div');
    card.className = 'group bg-slate-900/60 ring-1 ring-slate-800 hover:ring-slate-700 rounded-2xl p-4 sm:p-5 transition';
    card.dataset.id = account.id;
    card.innerHTML = `
      <div class="flex items-center gap-4">
        <div class="flex-shrink-0 w-10 h-10 rounded-xl bg-slate-800 ring-1 ring-slate-700 flex items-center justify-center font-semibold text-sm text-brand-400 uppercase">
          ${escapeHtml((account.label || '?').slice(0, 1))}
        </div>
        <div class="min-w-0 flex-1">
          <div class="text-sm font-medium text-slate-200 truncate">${escapeHtml(account.label || 'Unnamed')}</div>
          <div class="text-[11px] text-slate-500 truncate font-mono">${escapeHtml(account.secret)}</div>
        </div>
        <button data-action="copy" title="Copy code"
          class="relative w-9 h-9 rounded-lg hover:bg-slate-800 flex items-center justify-center text-slate-300 transition">
          <svg data-copy class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 0 1-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 0 1 1.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.05 9.05 0 0 0-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 0 1-1.125-1.125v-9.25m10.625-1.125H4.875c-.621 0-1.125.504-1.125 1.125v9.5c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125v-9.5c0-.621-.504-1.125-1.125-1.125Z" />
          </svg>
          <svg data-check class="w-4 h-4 hidden text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2">
            <path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5" />
          </svg>
        </button>
        <button data-action="delete" title="Delete account"
          class="w-9 h-9 rounded-lg hover:bg-rose-500/10 hover:text-rose-400 flex items-center justify-center text-slate-400 transition">
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
            <path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
          </svg>
        </button>
      </div>

      <div class="mt-4 flex items-center justify-between gap-4">
        <div class="flex items-end gap-1.5">
          <span data-code class="otp-digit font-mono text-3xl sm:text-4xl font-semibold tracking-tight text-slate-100 select-all">······</span>
        </div>
        <div class="relative w-9 h-9 text-slate-500" data-ring>
          ${progressRingSVG(1, 30)}
        </div>
      </div>
    `;
    return card;
  }

  function renderAccounts() {
    if (accounts.length === 0) {
      renderEmpty();
      return;
    }
    emptyEl.classList.add('hidden');
    clearWrap.classList.remove('hidden');
    // diff: build only missing cards, remove orphan ones
    const existing = new Map();
    listEl.querySelectorAll('[data-id]').forEach(el => existing.set(el.dataset.id, el));
    const seen = new Set();

    for (const acc of accounts) {
      seen.add(acc.id);
      let card = existing.get(acc.id);
      if (!card) {
        card = createCard(acc);
        listEl.appendChild(card);
      }
    }
    // remove orphans
    existing.forEach((el, id) => { if (!seen.has(id)) el.remove(); });
  }

  async function refreshCodes() {
    if (accounts.length === 0) return;
    const counter = Math.floor(Date.now() / 1000 / 30);
    const remaining = secondsRemaining(30);
    const ratio = remaining / 30;

    for (const acc of accounts) {
      const card = listEl.querySelector(`[data-id="${CSS.escape(acc.id)}"]`);
      if (!card) continue;
      const cached = codeCache.get(acc.id);
      let code;
      if (cached && cached.counter === counter) {
        code = cached.code;
      } else {
        try {
          code = await totp(acc.secret);
          codeCache.set(acc.id, { code, counter });
        } catch {
          code = 'ERROR';
        }
      }
      const codeEl = card.querySelector('[data-code]');
      if (codeEl.textContent !== code) {
        codeEl.textContent = code;
        codeEl.classList.remove('pop'); void codeEl.offsetWidth; codeEl.classList.add('pop');
        codeEl.classList.toggle('text-rose-400', code === 'ERROR');
      }
      const ringWrap = card.querySelector('[data-ring]');
      ringWrap.innerHTML = progressRingSVG(ratio, remaining);
    }
  }

  function touchAccount(id) {
    const acc = accounts.find(a => a.id === id);
    if (!acc) return;
    acc.lastAccessed = Date.now();
    saveAccounts(accounts);
  }

  async function handleAdd(e) {
    e.preventDefault();
    const labelEl = $('#labelInput');
    const secretEl = $('#secretInput');
    let secret = secretEl.value.trim();
    const label = labelEl.value.trim() || 'Unnamed';

    if (!secret) {
      showToast('Enter a secret key');
      secretEl.focus();
      return;
    }
    // normalize spaces
    const normalized = secret.replace(/\s+/g, '').toUpperCase();
    try {
      base32ToBytes(normalized);
    } catch {
      showToast('Invalid Base32 secret');
      secretEl.focus();
      return;
    }

    const account = {
      id: uuid(),
      label,
      secret: normalized,
      createdAt: Date.now(),
      lastAccessed: Date.now(),
    };
    accounts.push(account);
    saveAccounts(accounts);
    labelEl.value = '';
    secretEl.value = '';
    renderAccounts();
    await refreshCodes();
    showToast('Account added');
    labelEl.focus();
  }

  function handleListClick(e) {
    const copyBtn = e.target.closest('[data-action="copy"]');
    const delBtn = e.target.closest('[data-action="delete"]');
    const card = e.target.closest('[data-id]');
    if (!card) return;
    const id = card.dataset.id;

    if (copyBtn) {
      const codeEl = card.querySelector('[data-code]');
      const text = codeEl.textContent.trim();
      navigator.clipboard?.writeText(text).then(
        () => {
          const copyIcon = copyBtn.querySelector('[data-copy]');
          const checkIcon = copyBtn.querySelector('[data-check]');
          copyIcon.classList.add('hidden');
          checkIcon.classList.remove('hidden');
          setTimeout(() => {
            copyIcon.classList.remove('hidden');
            checkIcon.classList.add('hidden');
          }, 1200);
          touchAccount(id);
          showToast('Copied ' + text);
        },
        () => showToast('Copy failed')
      );
      return;
    }

    if (delBtn) {
      accounts = accounts.filter(a => a.id !== id);
      codeCache.delete(id);
      saveAccounts(accounts);
      renderAccounts();
      showToast('Account deleted');
    }
  }

  function handleClearAll() {
    if (accounts.length === 0) return;
    if (!confirm('Delete all stored accounts? This cannot be undone.')) return;
    accounts = [];
    codeCache.clear();
    saveAccounts(accounts);
    renderAccounts();
    showToast('All accounts cleared');
  }

  // ---------- Init ----------
  function init() {
    accounts = pruneExpired(loadAccounts());
    renderAccounts();
    refreshCodes();
    // tick every second for the ring; codes recompute when counter changes
    setInterval(refreshCodes, 1000);

    $('#addForm').addEventListener('submit', handleAdd);
    listEl.addEventListener('click', handleListClick);
    $('#clearAll').addEventListener('click', handleClearAll);

    // prune on focus (e.g. returning to tab after days)
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        accounts = pruneExpired(loadAccounts());
        codeCache.clear();
        renderAccounts();
        refreshCodes();
      }
    });
  }

  init();
})();
