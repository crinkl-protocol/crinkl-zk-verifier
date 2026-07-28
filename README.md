# Crinkl ZK Verifier

`@crnkl/zk-verifier` is the public package surface for independently checking
Crinkl ZK spend proof artifacts.

Current status: alpha package with Linux x64 release-binary backend.

What this package does now:

- validates `SpendZkStatementProofV1` artifact shape
- resolves a verifier registry manifest entry
- enforces the `H2_PROMO_OPEN_MIN_V1` public input order
- checks top-level `scopeId` and `nullifier` binding
- checks spend-token head and token-hash binding when a spend token is supplied
- rejects unknown circuits and verifier keys fail-closed
- rejects replayed `(scopeId, nullifier)` pairs when a replay store is supplied
- verifies real Halo2 proof bytes through the Rust CLI backend when configured
- independently admits signed Spend Token v1/v2 artifacts and verifies
  per-Spend v2 holder control
- composes exact Campaign request context, authorized input manifest, signed
  v2 token, accepted head, atomic proof, holder challenge, and Campaign
  nullifier with explicit partial-failure reporting
- runs the full 18-case pre-production verifier gate from `crinkl-protocol-spec`
- ships reproducible `H2_PROMO_OPEN_MIN_V1` verifier fixture artifacts with a registry manifest and artifact hashes

What this package does not do yet:

- it does not prove CBSA inside ZK
- it does not prove store-set membership for `H2_PROMO_OPEN_MIN_V1`
- it does not replace `crinkl-protocol-spec` as the public spec authority
- it does not generate proofs, hold private Spend witnesses, issue holder
  keys, or provide a Campaign challenge service

The cryptographic backend must be injected. If no backend is supplied, proof verification fails closed with `unsupported_cryptographic_backend`.

## Halo2 CLI backend

The current real backend calls the Rust verifier CLI. It does not trust
the Crinkl gateway or proof service. On Linux x64, the package uses the bundled
`bin/crnkl-zk-demo-linux-x64` release binary by default when no explicit command
or Cargo manifest is supplied.

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

## Release binary backend

The package includes a Linux x64 release binary at `bin/crnkl-zk-demo-linux-x64`.
The pinned checksum is in `bin/checksums.sha256`. Verify it with:

```bash
npm run verify:release-binary
```

Test the bundled binary against the published fixture with:

```bash
npm run test:release-binary
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

## Campaign proof authorization

`verifyCampaignProofAuthorizationV1()` implements the source-only composition
profile around the independently testable token, holder, head, proof, and
replay checks. The trusted Campaign consumer supplies the exact expected
`CampaignHolderProofAuthorizationRequestContextV1`; the verifier recomputes
its hash and refuses caller-selected substitutions.

State is consumed in this order:

1. the atomic proof and current nullifier state are checked without consuming
   either replay control;
2. the valid holder challenge is consumed;
3. the Campaign nullifier is consumed last.

An invalid proof or holder signature consumes nothing. If the nullifier
consume loses a race after holder consumption, the result is
`campaign_nullifier_consumption_failed` with `partialConsumption = true` and
`retryRule = NEW_HOLDER_CHALLENGE_REQUIRED`. This package does not claim
cross-store atomicity.

This is completed-package verification, not prover admission. A future
server-side prover must validate holder authorization before it reads private
witness material; if proving then fails, that earlier challenge remains
consumed and retry requires a new challenge. This package cannot prove when a
prover accessed a witness.

The consumed nullifier is the exact proof/qualification replay control carried
by the atomic proof. It is not conversion evidence, a settlement nullifier,
reward authority, or permission to release escrow.

The synthetic orchestration fixture is in
`fixtures/campaign-proof-authorization-v1/`. It contains no private witness or
holder private key. Its short proof bytes are accepted only by the injected
test stub; real candidate proof verification remains independently covered by
`fixtures/h2-atomic-purchase-v2-candidate/`.

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
