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
- verifies real Halo2 proof bytes through the Rust CLI backend when configured
- runs the full 18-case pre-production verifier gate from `crinkl-protocol-spec`
- ships reproducible `H2_PROMO_OPEN_MIN_V1` verifier fixture artifacts with a registry manifest and artifact hashes

What this package does not do yet:

- it does not prove CBSA inside ZK
- it does not prove store-set membership for `H2_PROMO_OPEN_MIN_V1`
- it does not replace `crinkl-protocol-spec` as the public spec authority

The cryptographic backend must be injected. If no backend is supplied, proof verification fails closed with `unsupported_cryptographic_backend`.

## Halo2 CLI backend

The current real backend calls the existing Rust verifier CLI. It does not trust
the Crinkl gateway or proof service.

```js
import { createHalo2CliBackend, verifySpendZkProof } from "@crnkl/zk-verifier";

const backend = createHalo2CliBackend({
  cargoManifestPath: "/path/to/crinkl-platform/scripts/zk-demo-rs/Cargo.toml"
});

const result = await verifySpendZkProof({
  spendToken,
  proof,
  manifest,
  hashStatement,
  backend
});
```

For a built binary instead of Cargo:

```js
const backend = createHalo2CliBackend({
  command: "/path/to/crnkl-zk-demo"
});
```

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

## Fixture artifacts

The public beta fixture set lives in `fixtures/h2-promo-open-min-v1/`:

- `valid-proof.json`
- `spend-token.json`
- `manifest.json`
- `fixture-metadata.json`

The manifest includes `artifactHash`, `sourceCommit`, `verifierParams`, and the
frozen public input order. `fixture-metadata.json` records the generator, source
commit, verifier artifact profile, artifact hash, and SHA-256 file hashes.

Regenerate the fixture set from the platform Rust Halo2 CLI:

```bash
CRNKL_ZK_DEMO_MANIFEST_PATH=/path/to/crinkl-platform/scripts/zk-demo-rs/Cargo.toml npm run generate:fixtures
```

## Test

```bash
npm run test:preproduction
```

Real Halo2 CLI backend test:

```bash
CRNKL_ZK_DEMO_MANIFEST_PATH=/path/to/crinkl-platform/scripts/zk-demo-rs/Cargo.toml npm run test:halo2
```

The pre-production gate covers:

- valid proof artifact and registry entry
- unknown `proofSystem`
- unknown `circuitId`
- unknown or mismatched `verifyingKeyId`
- missing `publicInputs`
- missing proof bytes
- changed `spendIdHash`
- changed `headEventHash`
- changed `spendTokenHash`
- changed `statementId`
- changed `scopeId`
- changed `nullifier`
- changed `expectedStoreHash`
- changed `minDayIndex`
- changed `thresholdCents`
- changed commitment public input
- changed proof bytes
- replayed nullifier in the same scope
