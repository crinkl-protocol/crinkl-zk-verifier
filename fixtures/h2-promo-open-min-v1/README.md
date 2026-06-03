# H2_PROMO_OPEN_MIN_V1 Fixture Set

This directory carries the public beta verifier fixture for the current
`H2_PROMO_OPEN_MIN_V1` Halo2 IPA proof profile.

Files:

- `valid-proof.json`: a valid `SpendZkStatementProofV1` proof artifact.
- `spend-token.json`: the minimal spend token fields needed for package-level binding checks.
- `manifest.json`: the verifier registry manifest entry, including artifact hash, source commit, verifier params, and public input order.
- `fixture-metadata.json`: generator, source commit, artifact hash, verifier artifact profile, and file hashes.

Regenerate with:

```bash
CRNKL_ZK_DEMO_MANIFEST_PATH=/path/to/crinkl-platform/scripts/zk-demo-rs/Cargo.toml npm run generate:fixtures
```
