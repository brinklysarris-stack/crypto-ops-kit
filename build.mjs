import fs from 'node:fs';
import { encodeBech32 } from './inspector-core.mjs';

function makeSampleBolt11() {
  const hrp = 'lnbc50u'; // 5,000 sats
  const ts = 1795708800; // 2026-11-26T16:00:00Z
  const words = [];
  for (let i = 6; i >= 0; i--) words.push((ts >> (i * 5)) & 31);
  // Add tagged description 'd': "aibox invoice"
  const desc = Buffer.from('aibox demo invoice', 'utf8');
  const dWords = [];
  let acc = 0, bits = 0;
  for (const b of desc) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      dWords.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) dWords.push((acc << (5 - bits)) & 31);
  // 'd' is index 13 in BECH32_CHARSET
  words.push(13, (dWords.length >> 5) & 31, dWords.length & 31, ...dWords);
  // Add 104 dummy signature words
  for (let i = 0; i < 104; i++) words.push(0);
  return encodeBech32(hrp, words);
}

const sampleX402 = Buffer.from(JSON.stringify({
  x402Version: 1,
  accepts: [{
    scheme: 'exact',
    network: 'eip155:8453',
    maxAmountRequired: '3000000',
    asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    payTo: '0x217Ad83F7E0Cae8CE48a678cF0A1229b302aD28d',
  }],
})).toString('base64');

const coreRaw = fs.readFileSync('d:/aibox/work/products/crypto-ops-kit/inspector-core.mjs', 'utf8');
const browserCore = coreRaw.replace(/^export /gm, '');
let tpl = fs.readFileSync('d:/aibox/work/products/crypto-ops-kit/ui-template.html', 'utf8');
tpl = tpl
  .replace('/* __INSPECTOR_CORE__ */', browserCore)
  .replace('__SAMPLE_BOLT11__', makeSampleBolt11())
  .replace('__SAMPLE_X402__', sampleX402);
fs.writeFileSync('d:/aibox/work/products/crypto-ops-kit/index.html', tpl, 'utf8');
console.log('Built d:/aibox/work/products/crypto-ops-kit/index.html bytes:', Buffer.byteLength(tpl, 'utf8'));
