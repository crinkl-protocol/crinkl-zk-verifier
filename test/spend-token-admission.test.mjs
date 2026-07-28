import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign
} from "node:crypto";
import { test } from "node:test";

import {
  canonicalize,
  H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER,
  verifySpendAttestationToken,
  verifySpendAttestationTokenV1,
  verifySpendAttestationTokenV2,
  verifySpendZkProof
} from "../src/index.mjs";

test("matches the adopted Spend Token canonical-hash vector", () => {
  const unsignedToken = JSON.parse(
    "{\"tokenType\":\"SPEND_ATTESTATION\",\"schemaVersion\":1,\"spendId\":\"spend-1\",\"wallet\":\"wallet-1\",\"canonical\":{\"status\":\"HARD_VERIFIED\",\"storeHash\":\"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"date\":\"2024-01-01\",\"totalCents\":\"1234\",\"currency\":\"USD\",\"timestamp\":\"2024-01-01T00:00:00.000Z\",\"verificationVersion\":\"1.0.0\"},\"lineage\":{\"headEventHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"eventCount\":3},\"protocol\":{\"protocolVersion\":\"1.0.0-rc.1\"}}"
  );
  const expectedCanonical =
    "{\"canonical\":{\"currency\":\"USD\",\"date\":\"2024-01-01\",\"status\":\"HARD_VERIFIED\",\"storeHash\":\"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"timestamp\":\"2024-01-01T00:00:00.000Z\",\"totalCents\":\"1234\",\"verificationVersion\":\"1.0.0\"},\"lineage\":{\"eventCount\":3,\"headEventHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"protocol\":{\"protocolVersion\":\"1.0.0-rc.1\"},\"schemaVersion\":1,\"spendId\":\"spend-1\",\"tokenType\":\"SPEND_ATTESTATION\",\"wallet\":\"wallet-1\"}";

  assert.equal(canonicalize(unsignedToken), expectedCanonical);
  assert.equal(
    createHash("sha256").update(expectedCanonical, "utf8").digest("hex"),
    "a8e643def40ef692899c0324c28df732503862d0f6c8ca8b0a600d9412c04e22"
  );
});

test("admits a canonical signed SpendAttestationTokenV1 from an authorized issuer", async () => {
  const fixture = makeSignedToken();
  const result = await verifySpendAttestationTokenV1({
    token: fixture.token,
    issuerRegistry: fixture.issuerRegistry
  });

  assert.equal(result.ok, true);
  assert.equal(result.spendId, fixture.token.spendId);
  assert.equal(result.spendTokenHash, `sha256:${fixture.token.signatures.tokenHash}`);
  assert.equal(result.headEventHash, fixture.token.lineage.headEventHash);
});

test("rejects a token whose signed canonical body changed", async () => {
  const fixture = makeSignedToken();
  fixture.token.canonical.totalCents = "9999";

  const result = await verifySpendAttestationTokenV1({
    token: fixture.token,
    issuerRegistry: fixture.issuerRegistry
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "spend_token_hash_mismatch");
});

test("rejects an invalid Ed25519 signature", async () => {
  const fixture = makeSignedToken();
  fixture.token.signatures.signature = Buffer.alloc(64, 7).toString("base64");

  const result = await verifySpendAttestationTokenV1({
    token: fixture.token,
    issuerRegistry: fixture.issuerRegistry
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "spend_token_signature_invalid");
});

test("rejects a cryptographically valid token from an unauthorized issuer", async () => {
  const fixture = makeSignedToken();

  const result = await verifySpendAttestationTokenV1({
    token: fixture.token,
    issuerRegistry: { isAuthorized: () => false }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "spend_token_issuer_unauthorized");
});

test("rejects a signed token outside the verifier's admitted protocol versions", async () => {
  const fixture = makeSignedToken();
  const result = await verifySpendAttestationTokenV1({
    token: fixture.token,
    issuerRegistry: fixture.issuerRegistry,
    supportedProtocolVersions: ["1.0.0-rc.2"]
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "unsupported_protocol_version");
});

test("strict proof policy requires token admission, accepted head, and replay storage", async () => {
  const fixture = makeStrictProofFixture();
  const consumed = [];
  const result = await verifySpendZkProof({
    ...fixture,
    verificationPolicy: strictPolicy(),
    issuerRegistry: fixture.issuerRegistry,
    headStore: {
      isAccepted: ({ spendId, eventCount }) =>
        spendId === fixture.spendToken.spendId && eventCount === 3
    },
    seenNullifiers: {
      has: () => false,
      consume: (scopeId, nullifier) => {
        consumed.push([scopeId, nullifier]);
        return true;
      }
    },
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, true);
  assert.equal(result.spendTokenAdmissionChecked, true);
  assert.equal(result.headAcceptanceChecked, true);
  assert.equal(result.replayChecked, true);
  assert.equal(result.replayRecorded, true);
  assert.deepEqual(consumed, [[fixture.proof.scopeId, fixture.proof.nullifier]]);
});

test("strict proof policy admits a signed SpendAttestationTokenV2", async () => {
  const fixture = makeStrictProofFixture({
    schemaVersion: 2,
    holderBinding: {
      scheme: "crinkl.holder.v2",
      commitment: hashId("holder-commitment")
    }
  });
  const result = await verifySpendZkProof({
    ...fixture,
    verificationPolicy: strictPolicy(),
    issuerRegistry: fixture.issuerRegistry,
    headStore: { isAccepted: () => true },
    seenNullifiers: {
      has: () => false,
      consume: () => true
    },
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, true);
  assert.equal(result.spendTokenAdmissionChecked, true);
});

test("generic token admission supports v1 and v2 while malformed v2 holder binding fails closed", async () => {
  const v1Fixture = makeSignedToken();
  const v2Fixture = makeSignedToken({
    schemaVersion: 2,
    holderBinding: {
      scheme: "crinkl.holder.v2",
      commitment: hashId("holder-commitment")
    }
  });

  const v1 = await verifySpendAttestationToken({
    token: v1Fixture.token,
    issuerRegistry: v1Fixture.issuerRegistry
  });
  const v2 = await verifySpendAttestationTokenV2({
    token: v2Fixture.token,
    issuerRegistry: v2Fixture.issuerRegistry
  });
  v2Fixture.token.holderBinding.scheme = "unrecognized";
  const malformed = await verifySpendAttestationTokenV2({
    token: v2Fixture.token,
    issuerRegistry: v2Fixture.issuerRegistry
  });

  assert.equal(v1.ok, true);
  assert.equal(v1.schemaVersion, 1);
  assert.equal(v2.ok, true);
  assert.equal(v2.schemaVersion, 2);
  assert.equal(malformed.ok, false);
  assert.equal(malformed.reason, "malformed_spend_token");
});

test("strict proof policy rejects a valid token at an unaccepted head", async () => {
  const fixture = makeStrictProofFixture();
  const result = await verifySpendZkProof({
    ...fixture,
    verificationPolicy: strictPolicy(),
    issuerRegistry: fixture.issuerRegistry,
    headStore: { isAccepted: () => false },
    seenNullifiers: {
      has: () => false,
      consume: () => true
    },
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "spend_token_head_not_accepted");
  assert.equal(result.spendTokenAdmissionChecked, true);
  assert.equal(result.headAcceptanceChecked, true);
});

test("strict proof policy rejects when no durable replay store is supplied", async () => {
  const fixture = makeStrictProofFixture();
  const result = await verifySpendZkProof({
    ...fixture,
    verificationPolicy: strictPolicy(),
    issuerRegistry: fixture.issuerRegistry,
    headStore: { isAccepted: () => true },
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "nullifier_replay_store_required");
  assert.equal(result.replayChecked, false);
});

test("strict proof policy rejects a non-atomic has-only replay adapter", async () => {
  const fixture = makeStrictProofFixture();
  const result = await verifySpendZkProof({
    ...fixture,
    verificationPolicy: strictPolicy(),
    issuerRegistry: fixture.issuerRegistry,
    headStore: { isAccepted: () => true },
    seenNullifiers: { has: () => false },
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "nullifier_replay_store_required");
});

test("strict proof policy rejects a replay race at atomic consumption", async () => {
  const fixture = makeStrictProofFixture();
  const result = await verifySpendZkProof({
    ...fixture,
    verificationPolicy: strictPolicy(),
    issuerRegistry: fixture.issuerRegistry,
    headStore: { isAccepted: () => true },
    seenNullifiers: {
      has: () => false,
      consume: () => false
    },
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "replayed_nullifier");
  assert.equal(result.replayChecked, true);
  assert.equal(result.replayRecorded, false);
});

test("invalid strict-policy spelling fails closed instead of selecting legacy behavior", async () => {
  const fixture = makeStrictProofFixture();
  const result = await verifySpendZkProof({
    ...fixture,
    verificationPolicy: {
      spendTokenAdmission: "require"
    },
    backend: { verify: () => ({ ok: true }) }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "invalid_verification_policy");
});

export function makeSignedToken({
  schemaVersion = 1,
  holderBinding
} = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const rawPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const unsignedToken = {
    tokenType: "SPEND_ATTESTATION",
    schemaVersion,
    spendId: "spend-signed-token-001",
    canonical: {
      status: "HARD_VERIFIED",
      storeHash: hashId("store"),
      date: "2026-07-27",
      totalCents: "1200",
      currency: "USD",
      timestamp: "2026-07-27T12:00:00.000Z",
      verificationVersion: "1.0.0"
    },
    lineage: {
      headEventHash: hashId("head"),
      eventCount: 3
    },
    protocol: {
      protocolVersion: "1.0.0-rc.1"
    },
    ...(holderBinding === undefined ? {} : { holderBinding })
  };
  const tokenHash = createHash("sha256")
    .update(canonicalize(unsignedToken), "utf8")
    .digest("hex");
  const signature = sign(null, Buffer.from(tokenHash, "hex"), privateKey)
    .toString("base64");
  const publicKeyBase64 = rawPublicKey.toString("base64");

  return {
    token: {
      ...unsignedToken,
      signatures: {
        issuedBy: "crinkl-authority-test",
        publicKey: publicKeyBase64,
        tokenHash,
        signature
      }
    },
    issuerRegistry: {
      isAuthorized: ({ issuedBy, publicKey: candidate }) =>
        issuedBy === "crinkl-authority-test" && candidate === publicKeyBase64
    }
  };
}

function makeStrictProofFixture(tokenOptions) {
  const signed = makeSignedToken(tokenOptions);
  const spendTokenHash = `sha256:${signed.token.signatures.tokenHash}`;
  const statement = {
    domain: "crinkl:statement:v1",
    schemaVersion: 1,
    type: "SPEND_STOREHASH_EQ_AND_DAYINDEX_GTE_AND_TOTAL_GTE",
    protocolVersion: "1.0.0-rc.1",
    expectedStoreHash: signed.token.canonical.storeHash,
    minDayIndex: 20_000,
    thresholdCents: 1_000,
    currency: "USD"
  };
  const statementId = hashId(canonicalize(statement));
  const scopeId = hashId("strict-scope");
  const nullifier = hashId("strict-nullifier");
  const verifyingKeyId = hashId("strict-verifying-key");
  const proof = {
    schemaVersion: 1,
    protocolVersion: "1.0.0-rc.1",
    spendId: signed.token.spendId,
    spendTokenHash,
    binding: { headEventHash: signed.token.lineage.headEventHash },
    statement,
    statementId,
    scopeId,
    nullifier,
    proofSystem: "HALO2_IPA",
    circuitId: "H2_PROMO_OPEN_MIN_V1",
    verifyingKeyId,
    publicInputs: {
      spendIdHash: hashId(signed.token.spendId),
      headEventHash: signed.token.lineage.headEventHash,
      spendTokenHash,
      statementId,
      scopeId,
      nullifier,
      expectedStoreHash: statement.expectedStoreHash,
      minDayIndex: statement.minDayIndex,
      thresholdCents: statement.thresholdCents,
      commitmentStore: poseidon("strict-store"),
      commitmentDayIndex: poseidon("strict-day"),
      commitmentTotal: poseidon("strict-total")
    },
    proof: "cHJvb2Y=",
    issuedBy: "strict-test-prover",
    createdAt: "2026-07-27T12:00:00.000Z"
  };

  return {
    proof,
    spendToken: signed.token,
    issuerRegistry: signed.issuerRegistry,
    manifest: {
      schemaVersion: 1,
      protocolVersion: "1.0.0-rc.1",
      entries: [
        {
          schemaVersion: 1,
          protocolVersion: "1.0.0-rc.1",
          proofSystem: "HALO2_IPA",
          circuitId: proof.circuitId,
          verifyingKeyId,
          publicInputOrder: [...H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER]
        }
      ]
    },
    hashStatement: (candidate) => hashId(canonicalize(candidate))
  };
}

function strictPolicy() {
  return {
    spendTokenAdmission: "required",
    headAcceptance: "required",
    nullifierReplay: "required"
  };
}

function hashId(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function poseidon(value) {
  return `poseidon:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}
