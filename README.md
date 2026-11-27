# Crypto Ops Inspector (`crypto-ops-kit`)

100% offline, zero-dependency browser utility & Node.js core for verifying multi-chain payments, agent receipts, and Bitcoin UTXO consolidation fees.

## Capabilities
- **EVM / Base / Tempo Inspector**: Pure-JS Keccak-256 EIP-55 checksum validator & ERC-20 / EIP-3009 (`transfer`, `approve`, `transferFrom`, `transferWithAuthorization`) calldata decoder.
- **Solana Pubkey Validator**: Strict Base58 32-byte pubkey validation and exact BigInt Lamport-to-SOL formatting.
- **Bitcoin BOLT-11 Lightning Decoder**: Bech32 polymod verification, amount multiplier decoding (`m`, `u`, `n`, `p`), timestamp, expiry, payment hash, and description tags.
- **x402 Header Inspector**: Decodes `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` Base64/Base64URL JSON payloads.
- **UTXO Consolidation Fee Planner**: Calculates exact vBytes, fee sats, marginal input cost, dust threshold, and breakeven `sat/vB` across `P2WPKH`, `P2TR`, `P2SH-P2WPKH`, and `P2PKH`.
- **Batch Classifier**: Validates mixed multi-line payment addresses/payloads in one pass.

## Build & Verify
```bash
node build.mjs
node --test inspector-core.test.mjs
```
Open `index.html` directly in any browser (`file://`) or serve statically.

## Commercial Bundle & 24h Custom Services (RMB Instant Checkout)
Need commercial support, custom chain decoders, or 24-hour Node.js/Python automation scripts?
- **Live Interactive Utility**: <https://brinklysarris-stack.github.io/crypto-ops-kit/>
- **Afdian Storefront (Instant Auto-Delivery & 24h Custom Order)**: <https://afdian.com/a/daringotter> (`¥20.00 Commercial Pack + Tech Q&A` · `¥29.90 24h Custom Script`)
- **Direct Contact**: <mailto:brinklysarris@gmail.com>
