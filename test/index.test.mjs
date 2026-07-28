import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER,
  H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER,
  verifySpendZkProof
} from "../src/index.mjs";

const acceptingBackend = { verify: () => ({ ok: true }) };

const preProductionVectors = [
  {
    name: "01 valid proof artifact and registry entry accepts",
    expectedOk: true
  },
  {
    name: "02 unknown proofSystem fails closed",
    mutate: ({ proof }) => {
      proof.proofSystem = "GROTH16";
    },
    expectedReason: "unknown_proof_system"
  },
  {
    name: "03 unknown circuitId fails closed",
    mutate: ({ proof }) => {
      proof.circuitId = "H2_UNKNOWN";
    },
    expectedReason: "unknown_circuit_id"
  },
  {
    name: "04 unknown or mismatched verifyingKeyId fails closed",
    mutate: ({ proof }) => {
      proof.verifyingKeyId = hash("unknown-vk");
    },
    expectedReason: "unknown_verifying_key_id"
  },
  {
    name: "05 missing publicInputs fails malformed",
    mutate: ({ proof }) => {
      delete proof.publicInputs;
    },
    expectedReason: "malformed_proof_artifact"
  },
  {
    name: "06 missing proof bytes fails malformed",
    mutate: ({ proof }) => {
      delete proof.proof;
    },
    expectedReason: "malformed_proof_artifact"
  },
  {
    name: "07 changed spendIdHash fails",
    mutate: ({ proof }) => {
      proof.publicInputs.spendIdHash = hash("changed-spend");
    },
    expectedReason: "public_input_mismatch"
  },
  {
    name: "08 changed headEventHash fails",
    mutate: ({ proof }) => {
      proof.publicInputs.headEventHash = hash("changed-head");
    },
    expectedReason: "public_input_mismatch"
  },
  {
    name: "09 changed spendTokenHash fails",
    mutate: ({ proof }) => {
      proof.publicInputs.spendTokenHash = hash("changed-token");
    },
    expectedReason: "public_input_mismatch"
  },
  {
    name: "10 changed statementId fails",
    mutate: ({ proof }) => {
      proof.statementId = hash("changed-statement");
    },
    expectedReason: "public_input_mismatch"
  },
  {
    name: "11 changed scopeId fails",
    mutate: ({ proof }) => {
      proof.publicInputs.scopeId = hash("changed-scope");
    },
    expectedReason: "public_input_mismatch"
  },
  {
    name: "12 changed nullifier fails",
    mutate: ({ proof }) => {
      proof.publicInputs.nullifier = hash("changed-nullifier");
    },
    expectedReason: "public_input_mismatch"
  },
  {
    name: "13 changed expectedStoreHash fails",
    mutate: ({ proof }) => {
      proof.publicInputs.expectedStoreHash = hash("changed-store");
    },
    expectedReason: "public_input_mismatch"
  },
  {
    name: "14 changed minDayIndex fails",
    mutate: ({ proof }) => {
      proof.publicInputs.minDayIndex = proof.publicInputs.minDayIndex + 1;
    },
    expectedReason: "public_input_mismatch"
  },
  {
    name: "15 changed thresholdCents fails",
    mutate: ({ proof }) => {
      proof.publicInputs.thresholdCents = proof.publicInputs.thresholdCents + 1;
    },
    expectedReason: "public_input_mismatch"
  },
  {
    name: "16 changed commitment public input fails",
    mutate: ({ proof }) => {
      proof.publicInputs.commitmentTotal = poseidon("changed-total-commitment");
    },
    backend: {
      verify: ({ proof }) =>
        proof.publicInputs.commitmentTotal === poseidon("total-commitment")
          ? { ok: true }
          : { ok: false }
    },
    expectedReason: "cryptographic_verification_failed"
  },
  {
    name: "17 changed proof bytes fails",
    mutate: ({ proof }) => {
      proof.proof = "Y2hhbmdlZA==";
    },
    backend: {
      verify: ({ proof }) => (proof.proof === "cHJvb2Y=" ? { ok: true } : { ok: false })
    },
    expectedReason: "cryptographic_verification_failed"
  },
  {
    name: "18 replayed nullifier in same scope fails",
    mutate: (fixture) => {
      fixture.seenNullifiers = new Set([`${fixture.proof.scopeId}\u0000${fixture.proof.nullifier}`]);
    },
    expectedReason: "replayed_nullifier",
    expectedReplayChecked: true
  }
];

for (const vector of preProductionVectors) {
  test(`pre-production vector ${vector.name}`, async () => {
    const fixture = makeFixture();
    vector.mutate?.(fixture);

    const result = await verifySpendZkProof({
      ...fixture,
      backend: vector.backend ?? acceptingBackend
    });

    if (vector.expectedOk) {
      assert.equal(result.ok, true);
      assert.equal(result.reason, "ok");
      assert.equal(result.circuitId, "H2_PROMO_OPEN_MIN_V1");
      return;
    }

    assert.equal(result.ok, false);
    assert.equal(result.reason, vector.expectedReason);
    if (vector.expectedReplayChecked !== undefined) {
      assert.equal(result.replayChecked, vector.expectedReplayChecked);
    }
  });
}

test("missing backend fails closed before production wiring", async () => {
  const fixture = makeFixture();
  const result = await verifySpendZkProof(fixture);

  assert.equal(result.ok, false);
  assert.equal(result.reason, "unsupported_cryptographic_backend");
});

test("prototype property circuit IDs fail closed as unknown", async () => {
  const fixture = makeFixture();
  fixture.proof.circuitId = "toString";

  const result = await verifySpendZkProof({
    ...fixture,
    backend: acceptingBackend
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "unknown_circuit_id");
});

test("registry publicInputOrder mismatch fails closed", async () => {
  const fixture = makeFixture();
  fixture.manifest.entries[0].publicInputOrder = [...H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER].reverse();

  const result = await verifySpendZkProof({
    ...fixture,
    backend: acceptingBackend
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "public_input_order_mismatch");
});

test("atomic purchase v2 candidate binds one token, one statement, and all four commitments", async () => {
  const fixture = makeAtomicPurchaseV2Fixture();
  let observedOrder;
  const result = await verifySpendZkProof({
    ...fixture,
    backend: {
      verify: ({ publicInputOrder }) => {
        observedOrder = publicInputOrder;
        return { ok: true };
      }
    }
  });

  assert.equal(result.ok, true);
  assert.equal(result.circuitId, "H2_ATOMIC_PURCHASE_V2_CANDIDATE");
  assert.deepEqual(observedOrder, H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER);
});

for (const [name, mutate, expectedReason] of [
  [
    "store-set root",
    ({ proof }) => {
      proof.publicInputs.storeSetRoot = poseidon("changed-store-set-root");
    },
    "public_input_mismatch"
  ],
  [
    "upper date bound",
    ({ proof }) => {
      proof.publicInputs.maxDayIndex += 1;
    },
    "public_input_mismatch"
  ],
  [
    "minimum amount",
    ({ proof }) => {
      proof.publicInputs.minimumAmountCents += 1;
    },
    "public_input_mismatch"
  ],
  [
    "currency code",
    ({ proof }) => {
      proof.publicInputs.expectedCurrencyCode = currencyCode("CAD");
    },
    "public_input_mismatch"
  ],
  [
    "signed currency commitment",
    ({ spendToken }) => {
      spendToken.zk.commitments.C_currency = poseidon("changed-currency-commitment");
    },
    "spend_token_commitment_mismatch"
  ]
]) {
  test(`atomic purchase v2 candidate rejects changed ${name}`, async () => {
    const fixture = makeAtomicPurchaseV2Fixture();
    mutate(fixture);

    const result = await verifySpendZkProof({
      ...fixture,
      backend: acceptingBackend
    });

    assert.equal(result.ok, false);
    assert.equal(result.reason, expectedReason);
  });
}

test("atomic purchase v2 candidate requires the signed Spend Token commitments", async () => {
  const fixture = makeAtomicPurchaseV2Fixture();
  delete fixture.spendToken;

  const result = await verifySpendZkProof({
    ...fixture,
    backend: acceptingBackend
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "spend_token_commitment_mismatch");
});

test("atomic purchase v2 candidate rejects normalized or malformed statement currency", async () => {
  const fixture = makeAtomicPurchaseV2Fixture();
  fixture.proof.statement.currency = "usd";
  fixture.proof.statementId = hash(JSON.stringify(fixture.proof.statement));
  fixture.proof.publicInputs.statementId = fixture.proof.statementId;

  const result = await verifySpendZkProof({
    ...fixture,
    backend: acceptingBackend
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "malformed_proof_artifact");
});

test("atomic purchase v2 candidate rejects a profile-specific public input order mismatch", async () => {
  const fixture = makeAtomicPurchaseV2Fixture();
  fixture.manifest.entries[0].publicInputOrder = [
    ...H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER
  ].reverse();

  const result = await verifySpendZkProof({
    ...fixture,
    backend: acceptingBackend
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "public_input_order_mismatch");
});

function makeFixture() {
  const spendId = "spend-alpha-1";
  const headEventHash = hash("head");
  const spendTokenHash = hash("token");
  const statement = {
    domain: "crinkl:statement:v1",
    schemaVersion: 1,
    type: "SPEND_STOREHASH_EQ_AND_DAYINDEX_GTE_AND_TOTAL_GTE",
    protocolVersion: "1.0.0-rc.2",
    expectedStoreHash: hash("store"),
    minDayIndex: 19888,
    thresholdCents: 1200,
    currency: "USD"
  };
  const statementId = hash(JSON.stringify(statement));
  const scopeId = hash("scope");
  const nullifier = hash("nullifier");
  const verifyingKeyId = hash("vk");

  const proof = {
    schemaVersion: 1,
    protocolVersion: "1.0.0-rc.2",
    spendId,
    spendTokenHash,
    binding: { headEventHash },
    statement,
    statementId,
    scopeId,
    nullifier,
    proofSystem: "HALO2_IPA",
    circuitId: "H2_PROMO_OPEN_MIN_V1",
    verifyingKeyId,
    publicInputs: {
      spendIdHash: hash(spendId),
      headEventHash,
      spendTokenHash,
      statementId,
      scopeId,
      nullifier,
      expectedStoreHash: statement.expectedStoreHash,
      minDayIndex: statement.minDayIndex,
      thresholdCents: statement.thresholdCents,
      commitmentStore: poseidon("store-commitment"),
      commitmentDayIndex: poseidon("day-commitment"),
      commitmentTotal: poseidon("total-commitment")
    },
    proof: "cHJvb2Y=",
    issuedBy: "crinkl-proof-service",
    createdAt: "2026-06-02T00:00:00.000Z"
  };

  return {
    proof,
    spendToken: {
      lineage: { headEventHash },
      protocol: { protocolVersion: "1.0.0-rc.2" },
      signatures: { tokenHash: spendTokenHash }
    },
    manifest: {
      schemaVersion: 1,
      protocolVersion: "1.0.0-rc.2",
      entries: [
        {
          schemaVersion: 1,
          protocolVersion: "1.0.0-rc.2",
          proofSystem: "HALO2_IPA",
          circuitId: "H2_PROMO_OPEN_MIN_V1",
          verifyingKeyId,
          publicInputOrder: [...H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER],
          verifierKeyIdProfile: "halo2_pinned_debug_v1",
          status: "alpha_current_business"
        }
      ]
    },
    hashStatement: (candidate) => hash(JSON.stringify(candidate))
  };
}

function makeAtomicPurchaseV2Fixture() {
  const spendId = "spend-atomic-purchase-v2";
  const headEventHash = hash("atomic-head");
  const spendTokenHash = hash("atomic-token");
  const statement = {
    domain: "crinkl:statement:v1",
    schemaVersion: 1,
    type: "PRIVATE_COMMERCE_ATOMIC_PURCHASE",
    protocolVersion: "1.0.0-rc.2",
    storeSetRoot: poseidon("eligible-store-set"),
    minDayIndex: 20_000,
    maxDayIndex: 20_200,
    minimumAmountCents: 1_000,
    currency: "USD"
  };
  const statementId = hash(JSON.stringify(statement));
  const scopeId = hash("atomic-scope");
  const nullifier = hash("atomic-nullifier");
  const commitments = {
    C_store: poseidon("atomic-store"),
    C_dayIndex: poseidon("atomic-day"),
    C_total: poseidon("atomic-total"),
    C_currency: poseidon("atomic-currency")
  };
  const verifyingKeyId =
    "sha256:b01da9b079abf9063d7b5b096c57dc715be2fa7323f8dc0df79ac7605ed65f74";

  return {
    proof: {
      schemaVersion: 1,
      protocolVersion: "1.0.0-rc.2",
      spendId,
      spendTokenHash,
      binding: { headEventHash },
      statement,
      statementId,
      scopeId,
      nullifier,
      proofSystem: "HALO2_IPA",
      circuitId: "H2_ATOMIC_PURCHASE_V2_CANDIDATE",
      verifyingKeyId,
      publicInputs: {
        spendIdHash: hash(spendId),
        headEventHash,
        spendTokenHash,
        statementId,
        scopeId,
        nullifier,
        storeSetRoot: statement.storeSetRoot,
        minDayIndex: statement.minDayIndex,
        minimumAmountCents: statement.minimumAmountCents,
        commitmentStore: commitments.C_store,
        commitmentDayIndex: commitments.C_dayIndex,
        commitmentTotal: commitments.C_total,
        maxDayIndex: statement.maxDayIndex,
        expectedCurrencyCode: currencyCode(statement.currency),
        commitmentCurrency: commitments.C_currency
      },
      proof: "cHJvb2Y=",
      issuedBy: "crinkl-zk-verifier-candidate-test",
      createdAt: "2026-07-27T00:00:00.000Z",
      k: 14
    },
    spendToken: {
      lineage: { headEventHash },
      protocol: { protocolVersion: "1.0.0-rc.2" },
      signatures: { tokenHash: spendTokenHash },
      zk: { commitments }
    },
    manifest: {
      schemaVersion: 1,
      protocolVersion: "1.0.0-rc.2",
      entries: [
        {
          schemaVersion: 1,
          protocolVersion: "1.0.0-rc.2",
          proofSystem: "HALO2_IPA",
          circuitId: "H2_ATOMIC_PURCHASE_V2_CANDIDATE",
          verifyingKeyId,
          publicInputOrder: [...H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER],
          verifierKeyIdProfile: "halo2_atomic_purchase_v2_candidate",
          verifierParams: { k: 14 },
          status: "LAB_CANDIDATE_NOT_ADOPTED"
        }
      ]
    },
    hashStatement: (candidate) => hash(JSON.stringify(candidate))
  };
}

function currencyCode(value) {
  return (
    (value.charCodeAt(0) << 16) |
    (value.charCodeAt(1) << 8) |
    value.charCodeAt(2)
  );
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function poseidon(value) {
  return `poseidon:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}
