# Campaign server-proved completion verifier fixture

This fixture extracts the adopted grant, lifecycle, package, and canonical
references from:

`crinkl-protocol@fa86432a507a75d40b99c131eff3671c57e79d02:conformance/v2/vectors/campaign.serverProvedCompletion.v1.json`

The test combines it with the existing synthetic atomic-purchase proof and
Spend Token fixture, changing only the proof issuer and creation time to the
adopted completion vector values. No private witness or holder key is stored.

This is composition conformance evidence, not production ZK evidence. The
cryptographic backend is an injected acceptance stub and
`H2_ATOMIC_PURCHASE_V2_CANDIDATE` remains a lab candidate.
