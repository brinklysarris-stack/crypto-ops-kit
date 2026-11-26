/**
 * Zero-dependency Multi-Chain, x402, BOLT-11 Lightning & UTXO Inspector Core.
 * Runs identically in Node.js (ESM) and modern browsers with zero external deps.
 */

// --- Keccak-256 (Ethereum / EIP-55 original padding 0x01) ---
const MASK64 = 0xffffffffffffffffn;
const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const RHO = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rotl64(x, n) {
  if (n === 0) return x;
  const bn = BigInt(n);
  return ((x << bn) | (x >> (64n - bn))) & MASK64;
}

function keccakF1600(state) {
  const C = new Array(5);
  const D = new Array(5);
  const B = Array.from({ length: 5 }, () => new Array(5));
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) {
      C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] ^= D[x];
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        B[y][(2 * x + 3 * y) % 5] = rotl64(state[x + 5 * y], RHO[x][y]);
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);
      }
    }
    state[0] ^= KECCAK_RC[round];
  }
}

export function keccak256Hex(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : Uint8Array.from(input);
  const rate = 136;
  const paddedLen = Math.ceil((bytes.length + 1) / rate) * rate;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;

  const state = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let lane = 0; lane < 17; lane++) {
      let val = 0n;
      const base = off + lane * 8;
      for (let b = 0; b < 8; b++) {
        val |= BigInt(padded[base + b]) << BigInt(8 * b);
      }
      state[lane] ^= val;
    }
    keccakF1600(state);
  }

  let hex = '';
  for (let lane = 0; lane < 4; lane++) {
    const v = state[lane];
    for (let b = 0; b < 8; b++) {
      hex += Number((v >> BigInt(8 * b)) & 0xffn).toString(16).padStart(2, '0');
    }
  }
  return hex;
}

// --- EVM & EIP-55 ---
export function toEip55Checksum(address) {
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address.trim())) {
    throw new Error('Invalid EVM address format (expected 0x + 40 hex chars)');
  }
  const lower = address.trim().slice(2).toLowerCase();
  const hash = keccak256Hex(lower);
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

export function inspectEvmAddress(address) {
  const trimmed = String(address || '').trim();
  const checksummed = toEip55Checksum(trimmed);
  const body = trimmed.slice(2);
  const isAllLower = body === body.toLowerCase();
  const isAllUpper = body === body.toUpperCase();
  const checksumMatches = trimmed === checksummed;
  return {
    type: 'evm_address',
    valid: true,
    input: trimmed,
    checksummed,
    mixedCaseChecked: !isAllLower && !isAllUpper,
    checksumValid: isAllLower || isAllUpper ? null : checksumMatches,
    warning: !isAllLower && !isAllUpper && !checksumMatches ? 'Mixed-case EIP-55 checksum mismatch' : null,
  };
}

export function formatTokenUnits(rawBigInt, decimals = 6) {
  const d = Number(decimals);
  const neg = rawBigInt < 0n ? '-' : '';
  const v = rawBigInt < 0n ? -rawBigInt : rawBigInt;
  if (d === 0) return neg + v.toString();
  const s = v.toString().padStart(d + 1, '0');
  const intPart = s.slice(0, s.length - d);
  const fracPart = s.slice(s.length - d).replace(/0+$/, '');
  return neg + (fracPart ? `${intPart}.${fracPart}` : intPart);
}

function wordAddress(hexWord) {
  return toEip55Checksum('0x' + hexWord.slice(24, 64));
}

function wordUint256(hexWord) {
  return BigInt('0x' + hexWord);
}

export function decodeEvmCalldata(hexInput, decimals = 6) {
  const clean = String(hexInput || '').trim().toLowerCase();
  if (!/^0x[0-9a-f]{8,}$/.test(clean) || (clean.length - 2) % 2 !== 0) {
    throw new Error('Invalid hex calldata (must start with 0x and have >=4 bytes)');
  }
  const selector = clean.slice(0, 10);
  const argsHex = clean.slice(10);
  const words = [];
  for (let i = 0; i + 64 <= argsHex.length; i += 64) {
    words.push(argsHex.slice(i, i + 64));
  }

  if (selector === '0xa9059cbb' && words.length >= 2) {
    const to = wordAddress(words[0]);
    const amountRaw = wordUint256(words[1]);
    return {
      type: 'evm_calldata',
      selector,
      method: 'transfer(address,uint256)',
      params: { to, amountRaw: amountRaw.toString(), amountFormatted: formatTokenUnits(amountRaw, decimals), decimals },
    };
  }
  if (selector === '0x095ea7b3' && words.length >= 2) {
    const spender = wordAddress(words[0]);
    const amountRaw = wordUint256(words[1]);
    const isUnlimited = amountRaw === (1n << 256n) - 1n;
    return {
      type: 'evm_calldata',
      selector,
      method: 'approve(address,uint256)',
      params: {
        spender,
        amountRaw: amountRaw.toString(),
        amountFormatted: isUnlimited ? 'UNLIMITED (uint256.max)' : formatTokenUnits(amountRaw, decimals),
        decimals,
      },
    };
  }
  if (selector === '0x23b872dd' && words.length >= 3) {
    const from = wordAddress(words[0]);
    const to = wordAddress(words[1]);
    const amountRaw = wordUint256(words[2]);
    return {
      type: 'evm_calldata',
      selector,
      method: 'transferFrom(address,address,uint256)',
      params: { from, to, amountRaw: amountRaw.toString(), amountFormatted: formatTokenUnits(amountRaw, decimals), decimals },
    };
  }
  if (selector === '0xe3ee160e' && words.length >= 9) {
    // EIP-3009 transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)
    const from = wordAddress(words[0]);
    const to = wordAddress(words[1]);
    const valueRaw = wordUint256(words[2]);
    const validAfter = Number(wordUint256(words[3]));
    const validBefore = Number(wordUint256(words[4]));
    const nonce = '0x' + words[5];
    return {
      type: 'evm_calldata',
      selector,
      method: 'transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)',
      params: {
        from,
        to,
        amountRaw: valueRaw.toString(),
        amountFormatted: formatTokenUnits(valueRaw, decimals),
        validAfter,
        validBefore,
        nonce,
        decimals,
      },
    };
  }
  return {
    type: 'evm_calldata',
    selector,
    method: 'unknown',
    wordCount: words.length,
    words,
  };
}

// --- Solana Base58 & Lamports ---
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_MAP = Object.fromEntries([...B58_ALPHABET].map((c, i) => [c, BigInt(i)]));

export function decodeBase58(str) {
  const s = String(str || '').trim();
  if (!s) throw new Error('Empty Base58 string');
  let num = 0n;
  for (const ch of s) {
    if (!(ch in B58_MAP)) throw new Error(`Invalid Base58 character: ${ch}`);
    num = num * 58n + B58_MAP[ch];
  }
  const bytes = [];
  while (num > 0n) {
    bytes.push(Number(num & 0xffn));
    num >>= 8n;
  }
  bytes.reverse();
  let leadingZeros = 0;
  for (const ch of s) {
    if (ch === '1') leadingZeros++;
    else break;
  }
  return Uint8Array.from([...new Array(leadingZeros).fill(0), ...bytes]);
}

export function inspectSolanaAddress(str) {
  const trimmed = String(str || '').trim();
  const decoded = decodeBase58(trimmed);
  if (decoded.length !== 32) {
    throw new Error(`Expected 32-byte Solana pubkey, got ${decoded.length} bytes`);
  }
  const hex = Array.from(decoded).map((b) => b.toString(16).padStart(2, '0')).join('');
  return {
    type: 'solana_address',
    valid: true,
    address: trimmed,
    byteLength: 32,
    hex: '0x' + hex,
  };
}

export function lamportsToSol(lamports) {
  const val = BigInt(String(lamports).trim());
  return formatTokenUnits(val, 9);
}

// --- Bech32 & Bitcoin Lightning BOLT-11 ---
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_MAP = Object.fromEntries([...BECH32_CHARSET].map((c, i) => [c, i]));
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= BECH32_GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

export function decodeBech32(str) {
  const s = String(str || '').trim().toLowerCase();
  const pos = s.lastIndexOf('1');
  if (pos < 1 || pos + 7 > s.length) throw new Error('Invalid Bech32 separator or length');
  const hrp = s.slice(0, pos);
  const data = [];
  for (let i = pos + 1; i < s.length; i++) {
    const v = BECH32_MAP[s[i]];
    if (v === undefined) throw new Error(`Invalid Bech32 character: ${s[i]}`);
    data.push(v);
  }
  const chk = bech32Polymod([...bech32HrpExpand(hrp), ...data]);
  if (chk !== 1) throw new Error('Bech32 checksum mismatch');
  return { hrp, words: data.slice(0, -6) };
}

export function encodeBech32(hrp, words) {
  const h = hrp.toLowerCase();
  const values = [...bech32HrpExpand(h), ...words, 0, 0, 0, 0, 0, 0];
  const mod = bech32Polymod(values) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >> (5 * (5 - i))) & 31);
  return `${h}1${[...words, ...checksum].map((w) => BECH32_CHARSET[w]).join('')}`;
}

function wordsToBytes(words) {
  let acc = 0;
  let bits = 0;
  const out = [];
  for (const w of words) {
    acc = (acc << 5) | w;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

function readInt5(words, start, len) {
  let val = 0n;
  for (let i = 0; i < len; i++) {
    val = (val << 5n) | BigInt(words[start + i]);
  }
  return val;
}

export function decodeBolt11(invoice) {
  const clean = String(invoice || '').trim().replace(/^lightning:/i, '');
  const { hrp, words } = decodeBech32(clean);
  const m = hrp.match(/^(lnbcrt|lntbs|lntb|lnbc)(?:(\d+)([munp]?))?$/);
  if (!m) throw new Error(`Unsupported BOLT-11 HRP: ${hrp}`);

  const networkMap = { lnbc: 'bitcoin-mainnet', lntb: 'bitcoin-testnet', lntbs: 'bitcoin-signet', lnbcrt: 'bitcoin-regtest' };
  const multMsat = { '': 100_000_000_000n, m: 100_000_000n, u: 100_000n, n: 100n, p: 1n }; // Note: p * 1e-12 BTC * 1e11 msat = 0.1 msat!
  let msat = null;
  let satoshis = null;
  if (m[2]) {
    const n = BigInt(m[2]);
    const unit = m[3] || '';
    if (unit === 'p') {
      msat = n / 10n;
      satoshis = Number(msat) / 1000;
    } else {
      msat = n * multMsat[unit];
      satoshis = Number(msat) / 1000;
    }
  }

  if (words.length < 7 + 104) throw new Error('BOLT-11 payload too short for timestamp + signature');
  const timestamp = Number(readInt5(words, 0, 7));
  const sigWordsStart = words.length - 104;
  let cursor = 7;

  const result = {
    type: 'bolt11_invoice',
    validChecksum: true,
    network: networkMap[m[1]],
    hrp,
    amountMsat: msat !== null ? msat.toString() : null,
    amountSats: satoshis,
    amountBtc: msat !== null ? formatTokenUnits(msat, 11) : null,
    timestamp,
    createdIso: new Date(timestamp * 1000).toISOString(),
    expirySeconds: 3600, // BOLT-11 default
    paymentHash: null,
    description: null,
    descriptionHash: null,
    payeePubkey: null,
    minFinalCltvExpiry: null,
    tagsParsed: [],
  };

  while (cursor + 3 <= sigWordsStart) {
    const tag = BECH32_CHARSET[words[cursor]];
    const dataLen = Number(readInt5(words, cursor + 1, 2));
    cursor += 3;
    if (cursor + dataLen > sigWordsStart) break;
    const fieldWords = words.slice(cursor, cursor + dataLen);
    cursor += dataLen;

    const hexOf = (arr) => Array.from(wordsToBytes(arr)).map((b) => b.toString(16).padStart(2, '0')).join('');
    if (tag === 'p' && fieldWords.length === 52) {
      result.paymentHash = hexOf(fieldWords).slice(0, 64);
    } else if (tag === 'd') {
      result.description = new TextDecoder().decode(wordsToBytes(fieldWords));
    } else if (tag === 'h' && fieldWords.length === 52) {
      result.descriptionHash = hexOf(fieldWords).slice(0, 64);
    } else if (tag === 'x') {
      result.expirySeconds = Number(readInt5(fieldWords, 0, fieldWords.length));
    } else if (tag === 'c') {
      result.minFinalCltvExpiry = Number(readInt5(fieldWords, 0, fieldWords.length));
    } else if (tag === 'n' && fieldWords.length === 53) {
      result.payeePubkey = hexOf(fieldWords).slice(0, 66);
    }
    result.tagsParsed.push(tag);
  }
  result.expiresIso = new Date((timestamp + result.expirySeconds) * 1000).toISOString();
  return result;
}

// --- x402 Base64/JSON Header Inspector ---
export function decodeX402Header(input) {
  const s = String(input || '').trim();
  let jsonText = s;
  if (!s.startsWith('{') && !s.startsWith('[')) {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
    let bin;
    if (typeof Buffer !== 'undefined') {
      bin = Buffer.from(b64, 'base64').toString('utf8');
    } else {
      bin = decodeURIComponent(escape(atob(b64)));
    }
    jsonText = bin;
  }
  const payload = JSON.parse(jsonText);
  const accepts = Array.isArray(payload.accepts) ? payload.accepts : (payload.scheme ? [payload] : []);
  const normalizedAccepts = accepts.map((a) => ({
    scheme: a.scheme,
    network: a.network,
    asset: a.asset,
    payTo: a.payTo,
    maxAmountRequiredRaw: a.maxAmountRequired || a.amount || null,
    usdcFormatted: (a.maxAmountRequired || a.amount) ? formatTokenUnits(BigInt(a.maxAmountRequired || a.amount), 6) : null,
  }));
  return { type: 'x402_payload', x402Version: payload.x402Version ?? null, normalizedAccepts, raw: payload };
}

// --- Bitcoin UTXO Consolidation & Fee Breakeven ---
export const INPUT_VBYTES = {
  p2tr: 57.5,
  p2wpkh: 68,
  'p2sh-p2wpkh': 91,
  p2pkh: 148,
};

export function calcUtxoConsolidation({
  utxoCount,
  totalInputSats,
  inputType = 'p2wpkh',
  feeRateSatVb = 5,
  outputCount = 1,
}) {
  const n = Number(utxoCount);
  const total = Number(totalInputSats);
  const rate = Number(feeRateSatVb);
  const perIn = INPUT_VBYTES[inputType];
  if (!perIn) throw new Error(`Unknown inputType: ${inputType}`);
  if (!Number.isFinite(n) || n < 1 || !Number.isFinite(total) || total < 0 || !Number.isFinite(rate) || rate < 0) {
    throw new Error('Invalid numeric parameters');
  }
  const perOut = 31; // P2WPKH output vBytes
  const overhead = 10.5;
  const txVbytes = Math.ceil(overhead + n * perIn + Number(outputCount) * perOut);
  const feeSats = Math.ceil(txVbytes * rate);
  const netSats = total - feeSats;
  const avgUtxoSats = total / n;
  const marginalCostPerInputSats = perIn * rate;
  const maxEconomicalFeeRate = avgUtxoSats / perIn;
  const dustThresholdSats = inputType === 'p2pkh' ? 546 : 294;
  return {
    inputType,
    utxoCount: n,
    txVbytes,
    feeRateSatVb: rate,
    feeSats,
    netSats,
    feePct: total > 0 ? Number(((feeSats / total) * 100).toFixed(2)) : 100,
    marginalCostPerInputSats: Number(marginalCostPerInputSats.toFixed(1)),
    maxEconomicalFeeRateSatVb: Number(maxEconomicalFeeRate.toFixed(2)),
    dustThresholdSats,
    profitable: netSats > dustThresholdSats && avgUtxoSats > marginalCostPerInputSats,
  };
}

// --- Auto-Detect & Batch Classifier ---
export function autoInspect(input, decimals = 6) {
  const s = String(input || '').trim();
  if (!s) throw new Error('Empty input');
  if (/^0x[0-9a-fA-F]{40}$/.test(s)) return inspectEvmAddress(s);
  if (/^0x[0-9a-fA-F]{8,}$/.test(s)) return decodeEvmCalldata(s, decimals);
  if (/^(lightning:)?(lnbcrt|lntbs|lntb|lnbc)/i.test(s)) return decodeBolt11(s);
  if (s.startsWith('{') || /^[A-Za-z0-9+/=_-]{24,}$/.test(s)) {
    try {
      const x = decodeX402Header(s);
      if (x && typeof x.raw === 'object') return x;
    } catch {}
  }
  return inspectSolanaAddress(s);
}

export function batchInspect(text, decimals = 6) {
  const lines = String(text || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  return lines.map((line, i) => {
    try {
      return { line: i + 1, ok: true, result: autoInspect(line, decimals) };
    } catch (e) {
      return { line: i + 1, ok: false, input: line, error: e.message };
    }
  });
}
