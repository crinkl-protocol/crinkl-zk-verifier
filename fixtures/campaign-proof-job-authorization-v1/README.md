# Campaign proof-job authorization grant fixture

`grant-vector.json` is copied byte-for-byte from the adopted
`crinkl-protocol` conformance vector
`conformance/v2/vectors/campaign.proofJobAuthorizationGrant.v1.json` at merge
commit `827a68623a2f3ae298f7b8a669ccc7af8ac1374e`.

The fixture contains synthetic identifiers and hashes only. It contains no
production Campaign, Spend Token, holder key, signature, receipt, witness,
wallet, or user identifier.

The verifier tests require the adopted canonical grant bytes and `grantRef`,
strict unknown-field and duplicate rejection, expiry rejection, and atomic
claim-race rejection. The proof-job authorizer tests separately exercise real
Spend Token v2 and holder-control verification using the existing synthetic
Campaign authorization fixture.
