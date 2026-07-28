# Campaign composite proof-authorization fixture

This fixture is the exact valid request context and input manifest from the
adopted `CampaignHolderProofAuthorizationRequestContextV2` conformance vector
in `crinkl-protocol` PR #67.

It binds two sorted Condition requirements and two sorted source statements to
one compiled atomic-purchase statement, one admitted proof-profile binding,
one holder-selected Spend input, and the exact Halo2 circuit/key tuple.

All identifiers and hashes are synthetic. The fixture contains no receipt,
wallet, holder key, Spend witness, commitment opening, proof bytes, or user
identifier. It validates request and manifest binding only; it does not claim
runtime availability, proof generation, Campaign qualification, conversion,
reward, escrow, validator finality, or settlement.
