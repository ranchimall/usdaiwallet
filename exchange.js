/* ═══════════════════════════════════════════════════════════════
 * RanchiMall Exchange frontend (USDx ↔ USDAI)
 * Same design language as the wallet: .card, .form-*, .btn, .tx-item.
 * Depends on: floCrypto (lib.js + floCrypto.js), usdaiAPI
 * (usdaiBlockchainAPI.js) for the withdraw send step, and the
 * helpers showNotification / toggleVisibility / copyToClipboard
 * defined in index.html.
 * ═══════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  const AUTH_PREFIX = 'ranchimall-exchange';

  const TOKENS_BY_CHAIN = {
    tron: ['USDT'],
    ethereum: ['USDT', 'USDC'],
    bsc: ['USDT', 'USDC'],
  };

  const CHAIN_EXPLORER = {
    tron: (tx) => `https://tronscan.org/#/transaction/${tx}`,
    ethereum: (tx) => `https://etherscan.io/tx/${tx}`,
    bsc: (tx) => `https://bscscan.com/tx/${tx}`,
  };

  let depositPollTimer = null;
  let depositExpiresAt = null;
  let expiryTickTimer = null;
  let lastDepositAuth = null; // { privKey } for status polling

  // ─── Config: single source of truth is config.js ──────────────
  // (window.EXCHANGE_CONFIG, edited per deploy).
  const DEFAULT_BASE = 'http://localhost:3001/api/exchange';

  function fileBase() {
    const v = (window.EXCHANGE_CONFIG?.apiBase || '').trim();
    return v || DEFAULT_BASE;
  }

  function filePlatform() {
    return (window.EXCHANGE_CONFIG?.platformFloAddress || '').trim();
  }

  // Single source of truth: config.js. The platform address is
  // additionally cached in memory from backend GET /config.
  let cachedPlatform = '';

  function getBase() {
    return fileBase().replace(/\/$/, '');
  }

  function getPlatform() {
    return cachedPlatform || filePlatform();
  }

  function setPlatform(v) {
    cachedPlatform = (v || '').trim();
  }

  async function api(path, body) {
    const res = await fetch(getBase() + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.success === false) {
      throw new Error(data.error || `Request failed (HTTP ${res.status})`);
    }
    return data;
  }

  // ─── FLO auth signing (matches backend secure-endpoint.js) ─────
  function buildAuth(privKey, extra = {}, floIdField = 'floId') {
    if (typeof floCrypto === 'undefined') throw new Error('FLO library not loaded');
    const floId = floCrypto.getFloID(privKey);
    if (!floId) throw new Error('Invalid FLO private key');
    const pubKey = floCrypto.getPubKeyHex(privKey);
    if (!pubKey) throw new Error('Could not derive public key');
    const time = Date.now();
    const sign = floCrypto.signData(`${AUTH_PREFIX}:${floId}:${time}`, privKey);
    return { [floIdField]: floId, time, pubKey, sign, ...extra };
  }

  function requireKey(inputId) {
    const k = document.getElementById(inputId)?.value.trim();
    if (!k) {
      showNotification('⚠️ Enter your FLO private key first', 'warning');
      throw new Error('missing-key');
    }
    return k;
  }

  // ─── Settings / config ─────────────────────────────────────────
  // Config comes from config.js (window.EXCHANGE_CONFIG); the platform
  // address is auto-filled from backend GET /config when reachable.
  async function loadExchangeConfig() {
    try {
      const res = await fetch(getBase() + '/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const cfg = await res.json();
      if (cfg.success && cfg.platformFloAddress) {
        setPlatform(cfg.platformFloAddress);
      }
      if (cfg.success && cfg.minUsdaiWithdrawal) {
        const hint = document.getElementById('ex-min-hint');
        if (hint) hint.textContent = `Minimum withdrawal: ${cfg.minUsdaiWithdrawal} USDAI (sent to platform first)`;
      }
    } catch (e) {
      console.warn('exchange /config unreachable:', e.message);
    }
  }

  // ─── Deposit: chain/token selects ──────────────────────────────
  function refreshDepositTokens() {
    const chain = document.getElementById('ex-dep-chain')?.value || 'tron';
    const tokenSel = document.getElementById('ex-dep-token');
    if (!tokenSel) return;
    const tokens = TOKENS_BY_CHAIN[chain] || ['USDT'];
    tokenSel.innerHTML = tokens.map((t) => `<option value="${t}">${t}</option>`).join('');
  }

  function refreshWithdrawTokens() {
    const chain = document.getElementById('ex-wd-chain')?.value || 'tron';
    const tokenSel = document.getElementById('ex-wd-token');
    if (!tokenSel) return;
    const tokens = TOKENS_BY_CHAIN[chain] || ['USDT'];
    tokenSel.innerHTML = tokens.map((t) => `<option value="${t}">${t}</option>`).join('');
  }

  // ─── Deposit: create address ───────────────────────────────────
  async function createDepositAddress() {
    let privKey;
    try { privKey = requireKey('ex-dep-privkey'); } catch { return; }
    const chain = document.getElementById('ex-dep-chain').value;
    const token = document.getElementById('ex-dep-token').value;
    const btn = document.getElementById('ex-dep-btn');
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating…';

    try {
      const body = buildAuth(privKey, { chain, token });
      const data = await api('/deposit/create', body);
      lastDepositAuth = { privKey };
      renderDepositAddress(data);
      startDepositPolling();
      showNotification(data.reused ? 'Reusing your active address' : 'New deposit address created', 'success');
    } catch (err) {
      if (err.message !== 'missing-key') showNotification('❌ ' + err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = original;
    }
  }

  function renderDepositAddress(data) {
    document.getElementById('ex-dep-result').style.display = 'block';
    document.getElementById('ex-dep-address').textContent = data.address;
    depositExpiresAt = new Date(data.expiresAt).getTime();
    startExpiryCountdown();

    // QR (optional CDN lib; falls back to plain text)
    const qrBox = document.getElementById('ex-dep-qr');
    qrBox.innerHTML = '';
    try {
      if (typeof QRCode !== 'undefined') {
        new QRCode(qrBox, { text: data.address, width: 160, height: 160 });
      } else {
        qrBox.innerHTML = '<div class="tx-empty">QR unavailable offline — copy the address above</div>';
      }
    } catch {
      qrBox.innerHTML = '<div class="tx-empty">QR unavailable — copy the address above</div>';
    }
  }

  function startExpiryCountdown() {
    clearInterval(expiryTickTimer);
    const el = document.getElementById('ex-dep-expiry');
    const tick = () => {
      if (!depositExpiresAt) return;
      const ms = depositExpiresAt - Date.now();
      if (ms <= 0) {
        el.textContent = 'Expired — generate a new address';
        clearInterval(expiryTickTimer);
        return;
      }
      const m = Math.floor(ms / 60000);
      const s = Math.floor((ms % 60000) / 1000);
      el.textContent = `Expires in ${m}m ${String(s).padStart(2, '0')}s`;
    };
    tick();
    expiryTickTimer = setInterval(tick, 1000);
  }

  function statusBadge(status) {
    const map = {
      detected: 'badge-warn',
      confirmed: 'badge-info',
      swept: 'badge-accent',
      credited: 'badge-ok',
      failed: 'badge-err',
    };
    return `<span class="status-badge ${map[status] || 'badge-warn'}">${status}</span>`;
  }

  async function pollDepositStatus() {
    if (!lastDepositAuth) return;
    try {
      const body = buildAuth(lastDepositAuth.privKey);
      const data = await api('/deposit/status', body);
      renderDepositList(data.deposits || []);
    } catch (e) {
      console.warn('deposit status poll failed:', e.message);
    }
  }

  function startDepositPolling() {
    pollDepositStatus();
    clearInterval(depositPollTimer);
    depositPollTimer = setInterval(pollDepositStatus, 15000);
  }

  function renderDepositList(deposits) {
    const el = document.getElementById('ex-dep-history');
    if (!deposits.length) {
      el.innerHTML = '<div class="tx-empty">No deposits yet — send USDx to the address above</div>';
      return;
    }
    el.innerHTML = '';
    deposits.forEach((d) => {
      const div = document.createElement('div');
      div.className = 'tx-item';
      const amt = Number(d.usdx_amount).toFixed(6);
      const explorer = CHAIN_EXPLORER[d.chain]?.(d.txid) || '#';
      div.innerHTML = `
        <div class="tx-icon received"><i class="fa-solid fa-arrow-down"></i></div>
        <div class="tx-details">
          <div class="tx-type">+${amt} ${d.token} ${statusBadge(d.status)}</div>
          <div class="tx-address">${d.chain} · conf ${d.confirmations ?? 0}</div>
          <div class="tx-id" title="${d.txid}">TX: ${String(d.txid).slice(0, 10)}…</div>
          ${d.flo_txid ? `<div class="tx-date">USDAI paid: ${String(d.flo_txid).slice(0, 12)}…</div>` : ''}
        </div>
        <a class="explorer-link" target="_blank" rel="noopener" href="${explorer}">
          <i class="fa-solid fa-external-link-alt"></i>
        </a>`;
      el.appendChild(div);
    });
  }

  async function refreshDepositHistory() {
    let privKey;
    try { privKey = requireKey('ex-dep-privkey'); } catch { return; }
    lastDepositAuth = { privKey };
    startDepositPolling();
  }

  // ─── Withdraw: send USDAI → register request ───────────────────
  async function submitWithdraw() {
    let privKey;
    try { privKey = requireKey('ex-wd-privkey'); } catch { return; }
    const chain = document.getElementById('ex-wd-chain').value;
    const token = document.getElementById('ex-wd-token').value;
    const recipient = document.getElementById('ex-wd-recipient').value.trim();
    const amount = parseFloat(document.getElementById('ex-wd-amount').value);
    const platform = getPlatform();

    if (!recipient) { showNotification('⚠️ Enter the recipient USDx address', 'warning'); return; }
    if (!amount || amount <= 0) { showNotification('⚠️ Enter a valid USDAI amount', 'warning'); return; }
    if (!platform) { showNotification('⚠️ Platform address unknown — check Exchange settings / backend /config', 'error'); return; }
    if (typeof usdaiAPI === 'undefined') { showNotification('❌ USDAI library not loaded', 'error'); return; }

    const btn = document.getElementById('ex-wd-btn');
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Step 1/2: sending USDAI…';

    try {
      // Step 1 — on-chain USDAI transfer to the platform (signed locally)
      const sent = await usdaiAPI.send({ privateKey: privKey, receiver: platform, amount });
      btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Step 2/2: registering request…';

      // Step 2 — tell the backend; admin pays out USDx after review
      const body = buildAuth(privKey, {
        chain, token, recipientAddress: recipient, usdaiTxid: sent.hash || sent.txid,
      });
      const data = await api('/withdraw/request', body);
      showNotification(`Withdrawal #${data.request.id} registered — admin will pay ${amount} ${token} to ${recipient.slice(0, 10)}…`, 'success');
      document.getElementById('ex-wd-amount').value = '';
      refreshMyWithdrawals(privKey);
    } catch (err) {
      if (err.message !== 'missing-key') showNotification('❌ ' + err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = original;
    }
  }

  function wdStatusBadge(status) {
    const map = { pending: 'badge-warn', approved: 'badge-ok', rejected: 'badge-err' };
    return `<span class="status-badge ${map[status] || 'badge-warn'}">${status}</span>`;
  }

  async function refreshMyWithdrawals(knownKey) {
    let privKey = knownKey;
    if (!privKey) {
      try { privKey = requireKey('ex-wd-privkey'); } catch { return; }
    }
    try {
      const data = await api('/withdraw/my-requests', buildAuth(privKey));
      const el = document.getElementById('ex-wd-history');
      const rows = data.requests || [];
      if (!rows.length) {
        el.innerHTML = '<div class="tx-empty">No withdrawal requests yet</div>';
        return;
      }
      el.innerHTML = '';
      rows.forEach((r) => {
        const div = document.createElement('div');
        div.className = 'tx-item';
        div.innerHTML = `
          <div class="tx-icon sent"><i class="fa-solid fa-arrow-up"></i></div>
          <div class="tx-details">
            <div class="tx-type">#${r.id} · ${Number(r.usdx_amount).toFixed(6)} ${r.usdx_type} ${wdStatusBadge(r.status)}</div>
            <div class="tx-address">${r.chain} → ${r.payout_txid ? String(r.payout_txid).slice(0, 16) + '…' : 'awaiting payout'}</div>
            ${r.rejection_reason ? `<div class="tx-date">Reason: ${r.rejection_reason}</div>` : ''}
          </div>`;
        el.appendChild(div);
      });
    } catch (e) {
      showNotification('❌ ' + e.message, 'error');
    }
  }

  // ─── Admin ─────────────────────────────────────────────────────
  async function adminList() {
    let privKey;
    try { privKey = requireKey('ex-admin-privkey'); } catch { return; }
    const status = document.getElementById('ex-admin-filter')?.value || 'pending';
    try {
      const data = await api('/withdraw/admin/list', buildAuth(privKey, { status }, 'adminFloId'));
      renderAdminList(data.requests || [], privKey);
    } catch (e) {
      showNotification('❌ ' + e.message, 'error');
    }
  }

  function renderAdminList(rows, adminKey) {
    const el = document.getElementById('ex-admin-list');
    if (!rows.length) {
      el.innerHTML = '<div class="tx-empty">No requests with this status</div>';
      return;
    }
    el.innerHTML = '';
    rows.forEach((r) => {
      const div = document.createElement('div');
      div.className = 'tx-item admin-row';
      const pending = r.status === 'pending';
      div.innerHTML = `
        <div class="tx-details">
          <div class="tx-type">#${r.id} · ${Number(r.usdx_amount).toFixed(6)} ${r.usdx_type} on ${r.chain} ${wdStatusBadge(r.status)}</div>
          <div class="tx-address">User: ${r.flo_address}</div>
          <div class="tx-address">Pay to: ${r.recipient_address}</div>
          <div class="tx-id" title="${r.usdai_txid}">USDAI tx: ${String(r.usdai_txid).slice(0, 16)}…</div>
          ${r.payout_txid ? `<div class="tx-date">Paid: ${String(r.payout_txid).slice(0, 20)}…</div>` : ''}
        </div>
        ${pending ? `<div class="admin-actions">
          <button class="btn btn-sm btn-ok" data-act="approve">Approve</button>
          <button class="btn btn-sm btn-danger" data-act="reject">Reject</button>
        </div>` : ''}`;
      if (pending) {
        div.querySelector('[data-act="approve"]').onclick = () => adminApprove(r.id, adminKey);
        div.querySelector('[data-act="reject"]').onclick = () => adminReject(r.id, adminKey);
      }
      el.appendChild(div);
    });
  }

  async function adminApprove(requestId, adminKey) {
    const payoutTxid = prompt(`Approve request #${requestId}\n\nPaste the USDx payout transaction hash:`);
    if (!payoutTxid?.trim()) return;
    try {
      await api('/withdraw/admin/approve', buildAuth(adminKey, { requestId, payoutTxid: payoutTxid.trim() }, 'adminFloId'));
      showNotification(`Request #${requestId} approved`, 'success');
      adminList();
    } catch (e) {
      showNotification('❌ ' + e.message, 'error');
    }
  }

  async function adminReject(requestId, adminKey) {
    const reason = prompt(`Reject request #${requestId}\n\nReason (shown to user):`) || 'Rejected by admin';
    try {
      await api('/withdraw/admin/reject', buildAuth(adminKey, { requestId, reason }, 'adminFloId'));
      showNotification(`Request #${requestId} rejected`, 'success');
      adminList();
    } catch (e) {
      showNotification('❌ ' + e.message, 'error');
    }
  }

  // ─── Expose for onclick handlers ───────────────────────────────
  window.loadExchangeConfig = loadExchangeConfig;
  window.refreshDepositTokens = refreshDepositTokens;
  window.refreshWithdrawTokens = refreshWithdrawTokens;
  window.createDepositAddress = createDepositAddress;
  window.refreshDepositHistory = refreshDepositHistory;
  window.submitWithdraw = submitWithdraw;
  window.refreshMyWithdrawals = () => refreshMyWithdrawals();
  window.adminList = adminList;

  document.addEventListener('DOMContentLoaded', () => {
    refreshDepositTokens();
    refreshWithdrawTokens();
    loadExchangeConfig();
  });
})();
