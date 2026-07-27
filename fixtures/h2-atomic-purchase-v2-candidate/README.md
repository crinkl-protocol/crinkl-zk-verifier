# H2 atomic purchase v2 candidate fixture

This directory contains one deterministic real Halo2 IPA proof for
`H2_ATOMIC_PURCHASE_V2_CANDIDATE`, its public Campaign statement, the matching
minimal Spend Token projection, the verifier manifest, and shared rejection
cases.

The fixture proves one purchase witness satisfies store-set membership, lower
and upper day bounds, minimum amount, and exact ISO-4217 currency under one
pinned verifying key. The private witness and commitment blindings are not
persisted.

Both the direct `crnkl-zk-demo` verifier and the independent package verifier
must accept `valid-proof.json` and reject every case in
`verification-cases.json`.

This is lab candidate evidence. It does not admit the circuit, select it in the
Campaign compiler, verify the Spend Token issuer signature, or make it
production ZK.
