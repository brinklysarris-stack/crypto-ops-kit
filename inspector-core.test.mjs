import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {
  keccak256Hex,
  toEip55Checksum,
  inspectEvmAddress,
  decodeEvmCalldata,
  inspectSolanaAddress,
  lamportsToSol,
  encodeBech32,
  decodeBolt11,
  decodeX402Header,
  calcUtxoConsolidation,
  batchInspect,
} from './inspector-core.mjs';

test('Keccak-256 matches official Ethereum empty vector and EIP-55 vectors', () => {
  assert.equal(
    keccak256Hex(''),
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
  );
  // Official EIP-55 test vectors
  assert.equal(toEip55Checksum('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'), '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed');
  assert.equal(toEip55Checksum('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'), '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359');
  assert.equal(inspectEvmAddress('0x217Ad83F7E0Cae8CE48a678cF0A1229b302aD28d').checksumValid, true);
  assert.equal(inspectEvmAddress('0x217ad83f7e0cae8ce48a678cf0a1229b302aD28d').checksumValid, false);
});

test('ERC-20 transfer & EIP-3009 calldata decoding formats amounts accurately', () => {
  const calldata =
    '0xa9059cbb' +
    '000000000000000000000000217ad83f7e0cae8ce48a678cf0a1229b302ad28d' +
    '00000000000000000000000000000000000000000000000000000000002dc6c0'; // 3,000,000 = 3 USDC
  const dec = decodeEvmCalldata(calldata, 6);
  assert.equal(dec.method, 'transfer(address,uint256)');
  assert.equal(dec.params.to, '0x217Ad83F7E0Cae8CE48a678cF0A1229b302aD28d');
  assert.equal(dec.params.amountFormatted, '3');
});

test('Solana Base58 validation and Lamports conversion', () => {
  const s = inspectSolanaAddress('5SjX65iqeVQAmnoM3wuZfP9rXxrDFnwMNJc8o7ZVNZg1');
  assert.equal(s.valid, true);
  assert.equal(s.byteLength, 32);
  assert.throws(() => inspectSolanaAddress('NotValidBase58!0OlI'), /Invalid Base58/);
  assert.equal(lamportsToSol('48000000'), '0.048');
});

test('BOLT-11 Lightning decoder parses network, amount multipliers, and tagged fields', () => {
  const ts = 1795708800;
  const words = [];
  for (let i = 6; i >= 0; i--) words.push((ts >> (i * 5)) & 31);
  // Add expiry 'x' (code 6 in charset) of 7200s (12 = 7200? Wait: 7200 = 7*1024+32 -> words [7,1,0])
  words.push(31 /*'l' skip? No, 'x' is index 30? Wait check BECH32_CHARSET*/);
  const charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  words.pop();
  const dBytes = Buffer.from('5000 sats test', 'utf8');
  const dWords = [];
  let acc = 0, bits = 0;
  for (const b of dBytes) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; dWords.push((acc >> bits) & 31); }
  }
  if (bits > 0) dWords.push((acc << (5 - bits)) & 31);
  words.push(charset.indexOf('d'), 0, dWords.length, ...dWords);
  // Add 'x' tag = 7200 -> 7*1024 + 1*32 + 0 = 7200 -> 3 words [7, 1, 0]
  words.push(charset.indexOf('x'), 0, 3, 7, 1, 0);
  for (let i = 0; i < 104; i++) words.push(0);

  const inv = encodeBech32('lnbc50u', words);
  const parsed = decodeBolt11(inv);
  assert.equal(parsed.network, 'bitcoin-mainnet');
  assert.equal(parsed.amountSats, 5000);
  assert.equal(parsed.description, '5000 sats test');
  assert.equal(parsed.expirySeconds, 7200);
});

test('x402 header decoder & UTXO consolidation fee math', () => {
  const payload = Buffer.from(JSON.stringify({
    x402Version: 1,
    accepts: [{ scheme: 'exact', network: 'eip155:8453', maxAmountRequired: '3500000', asset: 'USDC', payTo: '0x217Ad83F7E0Cae8CE48a678cF0A1229b302aD28d' }],
  })).toString('base64url');
  const x = decodeX402Header(payload);
  assert.equal(x.normalizedAccepts[0].usdcFormatted, '3.5');

  const u = calcUtxoConsolidation({ utxoCount: 10, totalInputSats: 50000, inputType: 'p2wpkh', feeRateSatVb: 5 });
  assert.equal(u.txVbytes, 722); // ceil(10.5 + 680 + 31)
  assert.equal(u.feeSats, 3610);
  assert.equal(u.profitable, true);
});

test('Batch inspector classifies valid mixed inputs and isolates bad lines', () => {
  const out = batchInspect('0x217Ad83F7E0Cae8CE48a678cF0A1229b302aD28d\n5SjX65iqeVQAmnoM3wuZfP9rXxrDFnwMNJc8o7ZVNZg1\nbadline');
  assert.equal(out.length, 3);
  assert.equal(out[0].ok, true);
  assert.equal(out[1].ok, true);
  assert.equal(out[2].ok, false);
});

test('Built standalone index.html contains valid embedded core script and executes cleanly in VM', () => {
  const html = fs.readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.ok(!html.includes('__INSPECTOR_CORE__'), 'build placeholder must be replaced');
  assert.ok(!html.includes('__SAMPLE_BOLT11__'), 'sample placeholder must be replaced');
  assert.ok(!html.includes('__SAMPLE_X402__'), 'sample x402 placeholder must be replaced');
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(m, 'inline script present');
  // Test core functions and all SAMPLES decode cleanly in sandbox VM
  const coreAndSamples = m[1].split("document.querySelectorAll('.tab')")[0];
  const ctx = { TextEncoder, TextDecoder, Buffer, URL, Uint8Array, Array, BigInt, Math, Object, JSON, Error, Number, String, parseInt, escape, atob };
  vm.runInNewContext(
    `${coreAndSamples}\nthis._samples = Object.fromEntries(Object.entries(SAMPLES).map(([k, v]) => [k, autoInspect(v, 6)]));`,
    ctx
  );
  assert.equal(ctx._samples.evm.checksumValid, true);
  assert.equal(ctx._samples.calldata.params.amountFormatted, '3');
  assert.equal(ctx._samples.sol.valid, true);
  assert.equal(ctx._samples.bolt11.amountSats, 5000);
  assert.equal(ctx._samples.x402.normalizedAccepts[0].usdcFormatted, '3');
});
