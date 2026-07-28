import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  canonicalize,
  hashCampaignHolderProofAuthorizationRequestContextV1,
  hashCampaignHolderProofAuthorizationRequestContextV2,
  verifyCampaignProofAuthorizationV1
} from "../src/index.mjs";
import {
  createCampaignProofAuthorizationVerifier
} from "../src/campaign-proof-authorization.mjs";

const fixtureUrl = new URL(
  "../fixtures/campaign-proof-authorization-v1/package.json",
  import.meta.url
);
const proofManifestUrl = new URL(
  "../fixtures/h2-atomic-purchase-v2-candidate/manifest.json",
  import.meta.url
);
const fixtureTemplate = JSON.parse(await readFile(fixtureUrl, "utf8"));
const v2BindingVector = JSON.parse(
  await readFile(
    new URL(
      "../fixtures/campaign-proof-authorization-v2/request-context-vector.json",
      import.meta.url
    ),
    "utf8"
  )
);
const proofArtifactManifest = JSON.parse(
  await readFile(proofManifestUrl, "utf8")
);

test("freezes the adopted Campaign request-context hash without private witness material", () => {
  assert.equal(
    hashCampaignHolderProofAuthorizationRequestContextV1(
      fixtureTemplate.package.requestContext
    ),
    fixtureTemplate.expectedRequestContextHash
  );
  assert.equal(fixtureTemplate.privateWitnessPersisted, false);
  assert.equal(fixtureTemplate.holderPrivateKeyPersisted, false);
  assert.equal(fixtureTemplate.productionZk, false);
  assert.equal(
    fixtureTemplate.cryptographicBackendEvidence,
    "INJECTED_ACCEPTANCE_STUB"
  );
  assert.deepEqual(
    findForbiddenPrivateKeys(fixtureTemplate),
    []
  );
});

test("freezes the adopted composite V2 request context and manifest refs without weakening V1", () => {
  assert.equal(
    hashCanonical(v2BindingVector.inputManifest),
    v2BindingVector.expectedInputManifestRef
  );
  assert.equal(
    hashCampaignHolderProofAuthorizationRequestContextV2(
      v2BindingVector.requestContext
    ),
    v2BindingVector.expectedRequestContextHash
  );
  assert.throws(() =>
    hashCampaignHolderProofAuthorizationRequestContextV1(
      v2BindingVector.requestContext
    )
  );
  assert.throws(() =>
    hashCampaignHolderProofAuthorizationRequestContextV2(
      fixtureTemplate.package.requestContext
    )
  );
});

test("accepts a composite V2 package with compiled-statement and exact manifest lineage", async () => {
  const fixture = makeV2Fixture();
  const { events } = fixture;
  const verifyV2 = createCampaignProofAuthorizationVerifier({
    verifyAtomicProof({ proof }) {
      events.push("proof");
      assert.equal(
        proof.statementId,
        fixture.input.expectedRequestContext.compiledStatementId
      );
      return { ok: true };
    },
    verifyHolderControl({ expectedContext }) {
      events.push("holder");
      assert.equal(
        expectedContext.requestContextHash,
        fixture.requestContextHash
      );
      return { ok: true, challengeConsumed: true };
    }
  });

  const result = await verifyV2(fixture.input);

  assert.equal(result.ok, true);
  assert.equal(result.requestContextHash, fixture.requestContextHash);
  assert.equal(
    result.statementId,
    fixture.input.expectedRequestContext.compiledStatementId
  );
  assert.deepEqual(events, ["proof", "holder", "nullifier"]);
});

test("rejects unsorted V2 requirement lineage before proof or holder verification", async () => {
  const fixture = makeV2Fixture();
  fixture.input.package.requestContext.conditionRequirementIds.reverse();
  let externalCalls = 0;
  const verifyV2 = createCampaignProofAuthorizationVerifier({
    verifyAtomicProof() {
      externalCalls += 1;
      return { ok: true };
    },
    verifyHolderControl() {
      externalCalls += 1;
      return { ok: true, challengeConsumed: true };
    }
  });

  const result = await verifyV2(fixture.input);

  assert.equal(result.reason, "malformed_campaign_request_context");
  assert.equal(externalCalls, 0);
});

test("rejects a V2 manifest whose valid source lineage differs from the request context", async () => {
  const fixture = makeV2Fixture();
  fixture.input.authorizedInputManifest.sourceStatementIds[0] =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
  const manifestRef = hashCanonical(fixture.input.authorizedInputManifest);
  fixture.input.package.requestContext.inputManifestRef = manifestRef;
  fixture.input.expectedRequestContext.inputManifestRef = manifestRef;
  const requestContextHash =
    hashCampaignHolderProofAuthorizationRequestContextV2(
      fixture.input.expectedRequestContext
    );
  fixture.input.package.holderChallenge.requestContextHash =
    requestContextHash;
  let externalCalls = 0;
  const verifyV2 = createCampaignProofAuthorizationVerifier({
    verifyAtomicProof() {
      externalCalls += 1;
      return { ok: true };
    },
    verifyHolderControl() {
      externalCalls += 1;
      return { ok: true, challengeConsumed: true };
    }
  });

  const result = await verifyV2(fixture.input);

  assert.equal(result.reason, "authorized_input_manifest_mismatch");
  assert.equal(externalCalls, 0);
});

test("accepts the complete package and consumes holder challenge before Campaign nullifier", async () => {
  const fixture = makeFixture();
  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.ok, true);
  assert.equal(result.reason, "campaign_proof_authorization_verified");
  assert.equal(
    result.requestContextHash,
    fixtureTemplate.expectedRequestContextHash
  );
  assert.equal(result.holderChallengeConsumed, true);
  assert.equal(result.campaignNullifierConsumed, true);
  assert.equal(result.partialConsumption, false);
  assert.deepEqual(fixture.events, [
    "issuer-authorized",
    "head-accepted",
    "atomic-proof-verified",
    "issuer-authorized",
    "holder-challenge-outstanding",
    "holder-challenge-consumed",
    "campaign-nullifier-consumed"
  ]);
});

test("changed Campaign context fails before proof verification or replay consumption", async () => {
  const fixture = makeFixture();
  fixture.input.package.requestContext.campaignEpochRef =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.reason, "campaign_request_context_mismatch");
  assert.deepEqual(fixture.events, []);
});

test("changed authorized input manifest fails before proof verification", async () => {
  const fixture = makeFixture();
  fixture.input.authorizedInputManifest.acceptedSpendInputs[0].headSnapshotRef =
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.reason, "authorized_input_manifest_mismatch");
  assert.equal(result.inputManifestChecked, true);
  assert.deepEqual(fixture.events, []);
});

test("rejected atomic proof consumes neither holder challenge nor nullifier", async () => {
  const fixture = makeFixture({ proofAccepted: false });

  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.reason, "cryptographic_verification_failed");
  assert.equal(result.holderChallengeConsumed, false);
  assert.equal(result.campaignNullifierConsumed, false);
  assert.equal(result.partialConsumption, false);
  assert.deepEqual(fixture.events, [
    "issuer-authorized",
    "head-accepted",
    "atomic-proof-verified"
  ]);
});

test("rejected holder signature leaves both replay controls unconsumed", async () => {
  const fixture = makeFixture();
  const signature = Buffer.from(
    fixture.input.package.holderProof.signatureBase64,
    "base64"
  );
  signature[0] ^= 1;
  fixture.input.package.holderProof.signatureBase64 =
    signature.toString("base64");

  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.reason, "holder_signature_invalid");
  assert.equal(result.holderChallengeConsumed, false);
  assert.equal(result.campaignNullifierConsumed, false);
  assert.equal(result.partialConsumption, false);
  assert.equal(
    fixture.events.includes("holder-challenge-consumed"),
    false
  );
  assert.equal(
    fixture.events.includes("campaign-nullifier-consumed"),
    false
  );
});

test("unaccepted canonical head fails before proof or holder verification", async () => {
  const fixture = makeFixture({ headAccepted: false });

  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.reason, "spend_token_head_not_accepted");
  assert.deepEqual(fixture.events, [
    "issuer-authorized",
    "head-accepted"
  ]);
});

test("pre-existing Campaign nullifier fails before holder challenge consumption", async () => {
  const fixture = makeFixture({ nullifierSeen: true });

  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.reason, "replayed_nullifier");
  assert.equal(result.holderChallengeConsumed, false);
  assert.equal(
    fixture.events.includes("holder-challenge-consumed"),
    false
  );
  assert.equal(
    fixture.events.includes("atomic-proof-verified"),
    false
  );
});

test("nullifier consume race reports honest partial consumption and retry rule", async () => {
  const fixture = makeFixture({ nullifierConsumeResult: false });

  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.reason, "campaign_nullifier_consumption_failed");
  assert.equal(result.holderChallengeConsumed, true);
  assert.equal(result.campaignNullifierConsumed, false);
  assert.equal(result.partialConsumption, true);
  assert.equal(result.retryRule, "NEW_HOLDER_CHALLENGE_REQUIRED");
  assert.deepEqual(fixture.events.slice(-2), [
    "holder-challenge-consumed",
    "campaign-nullifier-consumed"
  ]);
});

test("holder challenge consume race does not attempt Campaign nullifier consumption", async () => {
  const fixture = makeFixture({ challengeConsumeResult: false });

  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.reason, "holder_challenge_replayed");
  assert.equal(result.holderChallengeConsumed, false);
  assert.equal(result.campaignNullifierConsumed, false);
  assert.equal(result.partialConsumption, false);
  assert.equal(
    fixture.events.includes("campaign-nullifier-consumed"),
    false
  );
});

test("expired proof authorization fails before any external verifier call", async () => {
  const fixture = makeFixture();
  fixture.input.now =
    fixture.input.expectedRequestContext.authorizationExpiresAt;

  const result = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(result.reason, "campaign_proof_authorization_expired");
  assert.deepEqual(fixture.events, []);
});

test("successful package replay is stopped by the Campaign nullifier before holder reuse", async () => {
  const fixture = makeFixture();
  const first = await verifyCampaignProofAuthorizationV1(fixture.input);
  const eventCountAfterFirst = fixture.events.length;
  const second = await verifyCampaignProofAuthorizationV1(fixture.input);

  assert.equal(first.ok, true);
  assert.equal(second.reason, "replayed_nullifier");
  assert.equal(second.holderChallengeConsumed, false);
  assert.equal(
    fixture.events.slice(eventCountAfterFirst).includes(
      "holder-challenge-consumed"
    ),
    false
  );
});

function makeFixture({
  proofAccepted = true,
  headAccepted = true,
  nullifierSeen = false,
  nullifierConsumeResult = true,
  challengeConsumeResult = true
} = {}) {
  const fixture = structuredClone(fixtureTemplate);
  const events = [];
  const expectedRequestContext = structuredClone(
    fixture.package.requestContext
  );
  let challengeOutstanding = true;
  const seenNullifiers = new Set(
    nullifierSeen
      ? [
          replayKey(
            fixture.package.atomicProof.scopeId,
            fixture.package.atomicProof.nullifier
          )
        ]
      : []
  );

  const challengeStore = {
    isOutstanding() {
      events.push("holder-challenge-outstanding");
      return challengeOutstanding;
    },
    consume() {
      events.push("holder-challenge-consumed");
      if (!challengeOutstanding || !challengeConsumeResult) return false;
      challengeOutstanding = false;
      return true;
    }
  };
  const campaignNullifierStore = {
    has(scopeId, nullifier) {
      return seenNullifiers.has(replayKey(scopeId, nullifier));
    },
    consume(scopeId, nullifier) {
      events.push("campaign-nullifier-consumed");
      const key = replayKey(scopeId, nullifier);
      if (
        seenNullifiers.has(key) ||
        nullifierConsumeResult !== true
      ) {
        return false;
      }
      seenNullifiers.add(key);
      return true;
    }
  };

  return {
    events,
    input: {
      package: fixture.package,
      expectedRequestContext,
      expectedScopeId: fixture.package.atomicProof.scopeId,
      expectedVerifierId: fixture.package.holderChallenge.verifierId,
      authorizedInputManifest: fixture.authorizedInputManifest,
      proofArtifactManifest,
      hashStatement: (statement) => hashCanonical(statement),
      backend: {
        verify() {
          events.push("atomic-proof-verified");
          return {
            ok: proofAccepted,
            reason: proofAccepted
              ? "ok"
              : "synthetic_backend_rejected"
          };
        }
      },
      issuerRegistry: {
        isAuthorized({ issuedBy, publicKey }) {
          events.push("issuer-authorized");
          return (
            issuedBy ===
              fixture.package.spendToken.signatures.issuedBy &&
            publicKey ===
              fixture.package.spendToken.signatures.publicKey
          );
        }
      },
      headStore: {
        isAccepted() {
          events.push("head-accepted");
          return headAccepted;
        }
      },
      challengeStore,
      campaignNullifierStore,
      supportedProtocolVersions: ["1.0.0-rc.1"],
      now: fixture.verificationTime
    }
  };
}

function makeV2Fixture() {
  const fixture = structuredClone(fixtureTemplate);
  const manifest = fixture.authorizedInputManifest;
  const sourceStatementId = manifest.statementId;
  delete manifest.requirementId;
  delete manifest.statementId;
  manifest.domain =
    "crinkl:buyer-state:statement-evaluation-input-manifest:v2";
  manifest.schemaVersion = 2;
  manifest.conditionRequirementIds = [
    "minimum-amount",
    "qualifying-merchant"
  ];
  manifest.sourceStatementIds = [
    sourceStatementId,
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  ].sort();
  manifest.compiledStatementId = fixture.package.atomicProof.statementId;
  manifest.proofProfileBindingRef =
    "sha256:8888888888888888888888888888888888888888888888888888888888888888";

  const requestContext = fixture.package.requestContext;
  delete requestContext.requirementId;
  delete requestContext.statementId;
  requestContext.domain =
    "crinkl:campaign:holder-proof-authorization-request-context:v2";
  requestContext.schemaVersion = 2;
  requestContext.conditionRequirementIds = [
    ...manifest.conditionRequirementIds
  ];
  requestContext.sourceStatementIds = [...manifest.sourceStatementIds];
  requestContext.compiledStatementId = manifest.compiledStatementId;
  requestContext.proofProfileBindingRef = manifest.proofProfileBindingRef;
  requestContext.inputManifestRef = hashCanonical(manifest);

  const requestContextHash =
    hashCampaignHolderProofAuthorizationRequestContextV2(requestContext);
  fixture.package.holderChallenge.requestContextHash = requestContextHash;
  const events = [];

  return {
    requestContextHash,
    input: {
      package: fixture.package,
      expectedRequestContext: structuredClone(requestContext),
      expectedScopeId: fixture.package.atomicProof.scopeId,
      expectedVerifierId: fixture.package.holderChallenge.verifierId,
      authorizedInputManifest: manifest,
      proofArtifactManifest,
      hashStatement: (statement) => hashCanonical(statement),
      challengeStore: {
        isOutstanding: () => true,
        consume: () => true
      },
      campaignNullifierStore: {
        has: () => false,
        consume() {
          events.push("nullifier");
          return true;
        }
      },
      now: fixture.verificationTime
    },
    events
  };
}

function hashCanonical(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("hex")}`;
}

function replayKey(scopeId, nullifier) {
  return `${scopeId}\u0000${nullifier}`;
}

function findForbiddenPrivateKeys(value, path = "") {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) =>
      findForbiddenPrivateKeys(item, `${path}[${index}]`)
    );
  }
  if (value && typeof value === "object") {
    const forbidden = new Set([
      "privateKey",
      "privateKeySeedHex",
      "holderPrivateKey",
      "witness",
      "openings",
      "blinding"
    ]);
    return Object.entries(value).flatMap(([key, child]) => {
      const childPath = path ? `${path}.${key}` : key;
      return [
        ...(forbidden.has(key) ? [childPath] : []),
        ...findForbiddenPrivateKeys(child, childPath)
      ];
    });
  }
  return [];
}
