import assert from "node:assert/strict";
import {
  createHash,
  createPrivateKey,
  sign
} from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  canonicalize,
  verifySpendAttestationToken,
  verifySpendAttestationTokenV1,
  verifySpendAttestationTokenV2,
  verifySpendHolderControlV2
} from "../src/index.mjs";

const vector = JSON.parse(
  await readFile(
    new URL(
      "../fixtures/spend-token-v2-holder-binding/vector.json",
      import.meta.url
    ),
    "utf8"
  )
);
const valid = vector.valid;

test("admits the adopted holder-control vector and consumes its challenge once", async () => {
  const fixture = makeFixture();
  const result = await verifySpendHolderControlV2(fixture.input);

  assert.equal(result.ok, true);
  assert.equal(result.reason, "holder_control_verified");
  assert.equal(result.spendId, valid.spendId);
  assert.equal(result.spendTokenHash, valid.expectedSpendTokenHash);
  assert.equal(result.scopeId, valid.challenge.scopeId);
  assert.equal(result.requestContextHash, valid.challenge.requestContextHash);
  assert.equal(result.challengeId, valid.expectedChallengeId);
  assert.equal(result.tokenAdmissionChecked, true);
  assert.equal(result.challengeChecked, true);
  assert.equal(result.challengeConsumed, true);
  assert.deepEqual(fixture.challengeStore.outstandingCalls, [
    {
      verifierId: valid.challenge.verifierId,
      nonceBase64: valid.challenge.nonceBase64
    }
  ]);
  assert.equal(fixture.challengeStore.consumeCalls.length, 1);
});

test("generic admission accepts v2 while versioned wrappers remain exact", async () => {
  const fixture = makeFixture();
  const generic = await verifySpendAttestationToken({
    token: fixture.input.token,
    issuerRegistry: fixture.input.issuerRegistry
  });
  const v2 = await verifySpendAttestationTokenV2({
    token: fixture.input.token,
    issuerRegistry: fixture.input.issuerRegistry
  });
  const v1 = await verifySpendAttestationTokenV1({
    token: fixture.input.token,
    issuerRegistry: fixture.input.issuerRegistry
  });

  assert.equal(generic.ok, true);
  assert.equal(generic.schemaVersion, 2);
  assert.deepEqual(generic.holderBinding, valid.unsignedToken.holderBinding);
  assert.equal(v2.ok, true);
  assert.equal(v1.ok, false);
  assert.equal(v1.reason, "malformed_spend_token");
});

test("a valid v2 token without holderBinding is valid but cannot prove holder control", async () => {
  const fixture = makeFixture();
  const unsignedToken = structuredClone(valid.unsignedToken);
  delete unsignedToken.holderBinding;
  const token = signIssuerToken(unsignedToken);

  const admission = await verifySpendAttestationTokenV2({
    token,
    issuerRegistry: fixture.input.issuerRegistry
  });
  const holder = await verifySpendHolderControlV2({
    ...fixture.input,
    token
  });

  assert.equal(admission.ok, true);
  assert.equal(holder.ok, false);
  assert.equal(holder.reason, "holder_control_unavailable");
  assert.equal(fixture.challengeStore.consumeCalls.length, 0);
});

test("rejects a holder key that does not match the signed token commitment", async () => {
  const fixture = makeFixture();
  fixture.input.holderProof.holderPublicKeyBase64 =
    vector.keyMaterial.wrongPublicKeyBase64;

  const result = await verifySpendHolderControlV2(fixture.input);

  assert.equal(result.ok, false);
  assert.equal(result.reason, "holder_commitment_mismatch");
  assert.equal(fixture.challengeStore.consumeCalls.length, 0);
});

test("rejects an invalid holder signature without consuming the challenge", async () => {
  const fixture = makeFixture();
  const signature = Buffer.from(
    fixture.input.holderProof.signatureBase64,
    "base64"
  );
  signature[0] ^= 1;
  fixture.input.holderProof.signatureBase64 = signature.toString("base64");

  const result = await verifySpendHolderControlV2(fixture.input);

  assert.equal(result.ok, false);
  assert.equal(result.reason, "holder_signature_invalid");
  assert.equal(fixture.challengeStore.consumeCalls.length, 0);
});

test("changed scope is rejected by the complete challenge id", async () => {
  const fixture = makeFixture();
  fixture.input.challenge.scopeId =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  fixture.input.expectedContext.scopeId = fixture.input.challenge.scopeId;

  const result = await verifySpendHolderControlV2(fixture.input);

  assert.equal(result.ok, false);
  assert.equal(result.reason, "holder_challenge_id_mismatch");
  assert.equal(fixture.challengeStore.consumeCalls.length, 0);
});

test("changed request context is rejected by the complete challenge id", async () => {
  const fixture = makeFixture();
  fixture.input.challenge.requestContextHash =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  fixture.input.expectedContext.requestContextHash =
    fixture.input.challenge.requestContextHash;

  const result = await verifySpendHolderControlV2(fixture.input);

  assert.equal(result.ok, false);
  assert.equal(result.reason, "holder_challenge_id_mismatch");
  assert.equal(fixture.challengeStore.consumeCalls.length, 0);
});

test("caller-selected request context cannot replace the verifier's expected context", async () => {
  const fixture = makeFixture();
  fixture.input.expectedContext.requestContextHash =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

  const result = await verifySpendHolderControlV2(fixture.input);

  assert.equal(result.ok, false);
  assert.equal(result.reason, "holder_context_mismatch");
  assert.equal(fixture.challengeStore.consumeCalls.length, 0);
});

test("rejects expired and not-yet-valid challenges", async () => {
  const expired = makeFixture();
  expired.input.now = valid.challenge.expiresAt;
  const expiredResult = await verifySpendHolderControlV2(expired.input);

  const early = makeFixture();
  early.input.now = "2026-07-27T23:59:59.999Z";
  const earlyResult = await verifySpendHolderControlV2(early.input);

  assert.equal(expiredResult.reason, "holder_challenge_expired");
  assert.equal(earlyResult.reason, "holder_challenge_not_yet_valid");
  assert.equal(expired.challengeStore.consumeCalls.length, 0);
  assert.equal(early.challengeStore.consumeCalls.length, 0);
});

test("requires a verifier-authenticated outstanding challenge store", async () => {
  const missing = makeFixture();
  delete missing.input.challengeStore;
  const missingResult = await verifySpendHolderControlV2(missing.input);

  const consumed = makeFixture({ outstanding: false });
  const consumedResult = await verifySpendHolderControlV2(consumed.input);

  assert.equal(missingResult.reason, "holder_challenge_store_required");
  assert.equal(consumedResult.reason, "holder_challenge_replayed");
  assert.equal(consumed.challengeStore.consumeCalls.length, 0);
});

test("rejects a concurrent consume race as replay", async () => {
  const fixture = makeFixture({ consumeResult: false });

  const result = await verifySpendHolderControlV2(fixture.input);

  assert.equal(result.ok, false);
  assert.equal(result.reason, "holder_challenge_replayed");
  assert.equal(result.challengeConsumed, false);
  assert.equal(fixture.challengeStore.consumeCalls.length, 1);
});

test("rejects malformed nonce encoding and challenge lifetimes over 300 seconds", async () => {
  const badNonce = makeFixture();
  badNonce.input.challenge.nonceBase64 = "AA==";
  const nonceResult = await verifySpendHolderControlV2(badNonce.input);

  const longLived = makeFixture();
  longLived.input.challenge.expiresAt = "2026-07-28T00:05:00.001Z";
  const lifetimeResult = await verifySpendHolderControlV2(longLived.input);

  assert.equal(nonceResult.reason, "malformed_holder_challenge");
  assert.equal(lifetimeResult.reason, "malformed_holder_challenge");
  assert.equal(badNonce.challengeStore.consumeCalls.length, 0);
  assert.equal(longLived.challengeStore.consumeCalls.length, 0);
});

function makeFixture({ outstanding = true, consumeResult = true } = {}) {
  const token = {
    ...structuredClone(valid.unsignedToken),
    signatures: {
      issuedBy: valid.issuerSignature.issuedBy,
      publicKey: valid.issuerSignature.publicKeyBase64,
      tokenHash: valid.issuerSignature.tokenHashHex,
      signature: valid.issuerSignature.signatureBase64
    }
  };
  const challengeStore = {
    outstandingCalls: [],
    consumeCalls: [],
    isOutstanding(input) {
      this.outstandingCalls.push(input);
      return outstanding;
    },
    consume(input) {
      this.consumeCalls.push(input);
      return consumeResult;
    }
  };
  const challenge = structuredClone(valid.challenge);
  return {
    challengeStore,
    input: {
      token,
      issuerRegistry: issuerRegistry(),
      supportedProtocolVersions: ["1.0.0-rc.1"],
      challenge,
      holderProof: structuredClone(valid.holderProof),
      expectedContext: expectedContext(challenge),
      now: valid.verificationTime,
      challengeStore
    }
  };
}

function expectedContext(challenge) {
  return {
    spendTokenHash: challenge.spendTokenHash,
    scopeId: challenge.scopeId,
    requestContextHash: challenge.requestContextHash,
    purpose: challenge.purpose,
    verifierId: challenge.verifierId
  };
}

function issuerRegistry() {
  return {
    isAuthorized: ({ issuedBy, publicKey }) =>
      issuedBy === valid.issuerSignature.issuedBy &&
      publicKey === vector.issuerKeyMaterial.publicKeyBase64
  };
}

function signIssuerToken(unsignedToken) {
  const tokenHash = createHash("sha256")
    .update(canonicalize(unsignedToken), "utf8")
    .digest("hex");
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(vector.issuerKeyMaterial.privateKeySeedHex, "hex")
    ]),
    format: "der",
    type: "pkcs8"
  });
  return {
    ...unsignedToken,
    signatures: {
      issuedBy: valid.issuerSignature.issuedBy,
      publicKey: vector.issuerKeyMaterial.publicKeyBase64,
      tokenHash,
      signature: sign(null, Buffer.from(tokenHash, "hex"), privateKey).toString(
        "base64"
      )
    }
  };
}
