(function (GLOBAL) {
  'use strict';

  const TOKEN_API_BASE = 'https://ranchimallflo.ranchimall.net/api/v2';
  const USDAI_TOKEN = 'usdai';
  const USDAI_DECIMALS = 10;
  const FLO_SEND_AMT = 0.0003;
  const EXPLORER_BASE = 'https://blockbook.ranchimall.net/tx';

  const usdaiAPI = {};

  // The address-transactions endpoint can return the same txid multiple
  // times (e.g. one row per matching vin/vout leg). Collapse exact
  // duplicates so the UI never shows — or sums — the same tx twice.
  function dedupeTxs(txs) {
    const seen = new Set();
    return txs.filter((tx) => {
      const id = tx.txid || tx.hash || tx.txID;
      const key = id ? `id:${id}` : `raw:${JSON.stringify(tx)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // The API returns `time` in Unix SECONDS, but `new Date()` needs
  // MILLISECONDS. Normalize everything to ms (or null) here so the
  // UI never renders 1970 dates again.
  function normalizeTimestamp(v) {
    if (v === null || v === undefined || v === '') return null;
    if (typeof v === 'number' && Number.isFinite(v)) {
      return v < 1e12 ? v * 1000 : v; // seconds → ms; ms passes through
    }
    const parsed = Date.parse(v);
    return Number.isNaN(parsed) ? null : parsed;
  }

  // ─── Validation ────────────────────────────────────────────────
  usdaiAPI.isValidAddress = function (addr) {
    try { return !!floCrypto.validateFloID(addr, true); } catch { return false; }
  };

  usdaiAPI.isValidPrivateKey = function (wif) {
    try { return !!floCrypto.getFloID(wif); } catch { return false; }
  };

  usdaiAPI.getAddressFromKey = function (wif) {
    try { return floCrypto.getFloID(wif); } catch { return null; }
  };

  // ─── Balance ───────────────────────────────────────────────────
  // NOTE: the old tokenHolders endpoint 404s — balance is summed
  // from the address transaction history (single source, always live).
  // Token semantics: the incorporation address MINTS on send (needs no prior balance), so its sends must not be subtracted — naive math reads negative there, which the token system forbids. Final clamp enforces the no-negative invariant for every address.
  usdaiAPI.getBalance = async function (floAddress) {
    if (!usdaiAPI.isValidAddress(floAddress)) {
      throw new Error('Invalid FLO address');
    }

    try {
      const res = await fetch(
        `${TOKEN_API_BASE}/floAddressTransactions/${floAddress}?token=${USDAI_TOKEN}`
      );
      if (res.ok) {
        const data = await res.json();
        const txs = dedupeTxs(Array.isArray(data)
          ? data
          : data.transactions || data.txs || data.data || []);
        const isIncorporation = txs.some(
          (tx) => (tx.transferType || tx.type) === 'infiniteTokenIncorporation'
        );
        let balance = 0;
        for (const tx of txs) {
          if ((tx.transferType || tx.type) === 'infiniteTokenIncorporation') continue;
          const amt = Number(tx.tokenAmount || tx.amount || 0);
          const dest = tx.receiverAddress || tx.to || tx.destAddress;
          const sender = tx.senderAddress || tx.from || tx.sender;
          if (dest === floAddress) balance += amt;
          if (sender === floAddress && !isIncorporation) balance -= amt;
        }
        return { address: floAddress, balance: Math.max(0, balance) };
      }
    } catch (e) {
      console.warn('fallback failed:', e);
    }

    return { address: floAddress, balance: 0 };
  };

  // ─── Send ──────────────────────────────────────────────────────
  usdaiAPI.send = async function ({ privateKey, receiver, amount }) {
    if (!usdaiAPI.isValidAddress(receiver))
      throw new Error('Invalid recipient FLO address');
    if (!usdaiAPI.isValidPrivateKey(privateKey))
      throw new Error('Invalid FLO private key');
    if (!amount || Number(amount) <= 0)
      throw new Error('Invalid amount');

    const senderFloID = floCrypto.getFloID(privateKey);
    if (senderFloID === receiver)
      throw new Error('Cannot send to your own address');

    // Check balance before broadcasting
    const { balance } = await usdaiAPI.getBalance(senderFloID);
    if (balance < Number(amount)) {
      throw new Error(
        `Insufficient USDAI. You have ${balance.toFixed(6)}, trying to send ${Number(amount).toFixed(6)}.`
      );
    }

    // Build the floData payload — this IS the USDAI transfer
    const tokenAmount = Number(amount).toFixed(USDAI_DECIMALS);
    const floData = `send ${tokenAmount} ${USDAI_TOKEN}#`;

    // Sign + broadcast
    const txid = await floBlockchainAPI.sendTx(
      senderFloID,
      receiver,
      FLO_SEND_AMT,
      privateKey,
      floData
    );

    return {
      hash: txid,
      from: senderFloID,
      to: receiver,
      amount: Number(amount),
      fee: FLO_SEND_AMT,
    };
  };

  // ─── Transaction history ───────────────────────────────────────
  usdaiAPI.getTransactions = async function (floAddress, options = {}) {
    const limit = options.limit || 10;

    try {
      const res = await fetch(
        `${TOKEN_API_BASE}/floAddressTransactions/${floAddress}?token=${USDAI_TOKEN}`
      );
      if (!res.ok) return { transactions: [], hasMore: false };

      const data = await res.json();
      const txs = dedupeTxs(Array.isArray(data)
        ? data
        : data.transactions || data.txs || data.data || []);

      const transactions = txs.slice(0, limit).map((tx) => {
        const amt = Number(tx.tokenAmount || tx.amount || 0);
        const dest = tx.receiverAddress || tx.to || tx.destAddress;
        const sender = tx.senderAddress || tx.from || tx.sender;
        const isMint = (tx.transferType || tx.type) === 'infiniteTokenIncorporation';
        const isSent = !isMint && sender === floAddress;

        return {
          id: tx.txid || tx.hash || tx.txID || '',
          hash: tx.txid || tx.hash || tx.txID || '',
          sender,
          receiver: dest,
          amount: amt,
          amountUsdai: amt,
          type: isMint ? 'mint' : (isSent ? 'sent' : 'received'),
          timestamp: normalizeTimestamp(tx.time ?? tx.timestamp ?? tx.createdAt),
          confirmations: tx.confirmations || 0,
        };
      });

      return {
        transactions,
        hasMore: txs.length > limit,
      };
    } catch (e) {
      console.error('getTransactions error:', e);
      return { transactions: [], hasMore: false };
    }
  };

  // ─── Single transaction ────────────────────────────────────────
  usdaiAPI.getTransaction = async function (txid) {
    try {
      const res = await fetch(`${TOKEN_API_BASE}/transactionDetails/${txid}`);
      if (!res.ok) throw new Error('Transaction not found');
      const tx = await res.json();

      const amt = Number(tx.tokenAmount || tx.amount || 0);
      const dest = tx.receiverAddress || tx.to || tx.destAddress;
      const sender = tx.senderAddress || tx.from || tx.sender;

      return {
        id: txid,
        hash: txid,
        sender,
        receiver: dest,
        amount: amt,
        amountUsdai: amt,
        confirmations: tx.confirmations || 0,
        tokenIdentification: tx.tokenIdentification || '',
        timestamp: normalizeTimestamp(tx.time ?? tx.timestamp ?? null),
      };
    } catch (e) {
      throw e;
    }
  };

  usdaiAPI.getExplorerUrl = function (txid) {
    return `${EXPLORER_BASE}/${txid}`;
  };

  GLOBAL.usdaiAPI = usdaiAPI;

})(typeof window !== 'undefined' ? window : global);