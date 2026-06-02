# Crinkl ZK Verifier

`@crnkl/zk-verifier` is the public package surface for independently checking
Crinkl ZK spend proof artifacts.

Current status: alpha scaffold.

What this package does now:

- validates `SpendZkStatementProofV1` artifact shape
- resolves a verifier registry manifest entry
- enforces the `H2_PROMO_OPEN_MIN_V1` public input order
- checks top-level `scopeId` and `nullifier` binding
- checks spend-token head and token-hash binding when a spend token is supplied
- rejects unknown circuits and verifier keys fail-closed
- rejects replayed `(scopeId, nullifier)` pairs when a replay store is supplied

What this package does not do yet:

- it does not bundle the Halo2 cryptographic verifier
- it does not prove CBSA inside ZK
- it does not prove store-set membership for `H2_PROMO_OPEN_MIN_V1`
- it does not replace `crinkl-protocol-spec` as the public spec authority

The cryptographic backend must be injected. If no backend is supplied, proof
verification fails closed with `unsupported_cryptographic_backend`.

## Usage

```js
import { verifySpendZkProof } from "@crnkl/zk-verifier";

const result = await verifySpendZkProof({
  spendToken,
  proof,
  manifest,
  hashStatement,
  backend
});

if (!result.ok) {
  console.error(result.reason);
}
```

`backend.verify()` receives the proof artifact, matched registry entry, and
public input order. It must return `{ ok: true }` only after cryptographic proof
verification succeeds.

## Test

```bash
npm test
```
