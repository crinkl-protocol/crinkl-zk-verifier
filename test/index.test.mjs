import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER,
  verifySpendZkProof
} from "../src/index.mjs";

test("valid open-min proof passes when backend accepts", async () => {
  const fixture = makeFixture();
  const result = await verifySpendZkProof({
    ...fixture,
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, true);
  assert.equal(result.reason, "ok");
  assert.equal(result.circuitId, "H2_PROMO_OPEN_MIN_V1");
});

test("missing backend fails closed", async () => {
  const fixture = makeFixture();
  const result = await verifySpendZkProof(fixture);

  assert.equal(result.ok, false);
  assert.equal(result.reason, "unsupported_cryptographic_backend");
});

test("unknown circuit fails closed", async () => {
  const fixture = makeFixture();
  fixture.proof.circuitId = "H2_UNKNOWN";

  const result = await verifySpendZkProof({
    ...fixture,
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "unknown_circuit_id");
});

test("changed threshold public input fails before backend", async () => {
  const fixture = makeFixture();
  fixture.proof.publicInputs.thresholdCents = 9999;

  const result = await verifySpendZkProof({
    ...fixture,
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "public_input_mismatch");
});

test("replayed nullifier fails when replay store is supplied", async () => {
  const fixture = makeFixture();
  const seenNullifiers = new Set([`${fixture.proof.scopeId}\u0000${fixture.proof.nullifier}`]);

  const result = await verifySpendZkProof({
    ...fixture,
    seenNullifiers,
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "replayed_nullifier");
  assert.equal(result.replayChecked, true);
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

function hash(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function poseidon(value) {
  return `poseidon:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}
