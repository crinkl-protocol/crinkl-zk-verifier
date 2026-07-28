# Campaign proof-authorization composition fixture

This fixture composes one synthetic signed `SpendAttestationTokenV2`, one
accepted canonical head, one exact Campaign holder request context, one
holder challenge and response, one structurally complete atomic-purchase proof
artifact, and one Campaign nullifier.

It freezes orchestration and failure semantics. It deliberately does not claim
that the short `atomicProof.proof` bytes are a real Halo2 proof:

- `cryptographicBackendEvidence = INJECTED_ACCEPTANCE_STUB`;
- `productionZk = false`;
- no private Spend witness or commitment opening is persisted; and
- no holder private key is persisted in this package.

The independent real-proof fixture continues to verify the candidate circuit
and pinned key separately. Combining holder binding with a newly generated
real proof is a later admitted proof-generation step; this source-only slice
does not generate a proof or run the GPU.

The test suite proves this ordering:

1. verify the exact expected Campaign request context and input-manifest
   binding;
2. verify the signed token, accepted head, atomic proof, and pre-existing
   nullifier state without consuming either replay control;
3. verify and atomically consume the holder challenge;
4. consume the Campaign nullifier last.

An invalid proof or holder signature consumes neither control. If nullifier
consumption loses a race after the holder challenge was consumed, the result
is an explicit partial-consumption failure with
`retryRule = NEW_HOLDER_CHALLENGE_REQUIRED`. No cross-store atomicity is
claimed.

This ordering applies to verification of a completed package. It does not
claim that the prover accessed private witness material only after holder
authorization; that is a later bounded server-prover responsibility. The
fixture's Campaign nullifier is proof/qualification replay control only. It
does not authorize conversion, reward, escrow, or settlement.
