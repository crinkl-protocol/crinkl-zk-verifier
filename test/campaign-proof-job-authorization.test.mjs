import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  canonicalize,
  claimCampaignProofJobAuthorizationGrantV1,
  createCampaignProofJobAuthorizer,
  hashCampaignHolderProofAuthorizationRequestContextV1,
  hashCampaignHolderProofAuthorizationRequestContextV2,
  hashCampaignProofJobAuthorizationGrantV1,
  verifyCampaignProofJobAuthorizationGrantV1
} from "../src/index.mjs";

const grantVector = JSON.parse(
  await readFile(
    new URL(
      "../fixtures/campaign-proof-job-authorization-v1/grant-vector.json",
      import.meta.url
    ),
    "utf8"
  )
);
const completedPackageFixture = JSON.parse(
  await readFile(
    new URL(
      "../fixtures/campaign-proof-authorization-v1/package.json",
      import.meta.url
    ),
    "utf8"
  )
);

test("matches the adopted canonical grant and grantRef", () => {
  assert.equal(
    canonicalize(grantVector.valid.grant),
    grantVector.valid.expectedCanonical
  );
  assert.equal(
    hashCampaignProofJobAuthorizationGrantV1(grantVector.valid.grant),
    grantVector.valid.expectedGrantRef
  );

  const result = verifyCampaignProofJobAuthorizationGrantV1({
    grant: grantVector.valid.grant,
    expectedGrantRef: grantVector.valid.expectedGrantRef,
    now: grantVector.valid.grant.authorizedAt
  });

  assert.equal(result.ok, true);
  assert.equal(
    result.reason,
    "campaign_proof_job_authorization_verified"
  );
  assert.equal(result.lifecycleState, undefined);
});

test("enforces all adopted changed-field, shape, expiry, and claim-race vectors", async () => {
  for (const negativeCase of grantVector.negativeCases) {
    if (negativeCase.id === "expired-grant") {
      const result = verifyCampaignProofJobAuthorizationGrantV1({
        grant: grantVector.valid.grant,
        expectedGrantRef: grantVector.valid.expectedGrantRef,
        now: negativeCase.verificationTime
      });
      assert.equal(result.reason, negativeCase.expectedDecision.code);
      continue;
    }
    if (negativeCase.id === "claim-race") {
      const result = await claimCampaignProofJobAuthorizationGrantV1({
        grant: grantVector.valid.grant,
        expectedGrantRef: grantVector.valid.expectedGrantRef,
        now: grantVector.valid.grant.authorizedAt,
        grantStore: {
          claim() {
            return false;
          }
        }
      });
      assert.equal(result.reason, negativeCase.expectedDecision.code);
      continue;
    }

    const changed = structuredClone(grantVector.valid.grant);
    if (negativeCase.mutation === "duplicate authorizedSpendInputs[0]") {
      changed.authorizedSpendInputs.push(
        structuredClone(changed.authorizedSpendInputs[0])
      );
    } else {
      setPath(changed, negativeCase.path, negativeCase.value);
    }
    const result = verifyCampaignProofJobAuthorizationGrantV1({
      grant: changed,
      expectedGrantRef: grantVector.valid.expectedGrantRef,
      now: grantVector.valid.grant.authorizedAt
    });
    assert.equal(
      result.reason,
      negativeCase.expectedDecision.code,
      negativeCase.id
    );
  }
});

test("atomically claims an unexpired adopted grant once", async () => {
  const calls = [];
  let state = "AUTHORIZED";
  const grantStore = {
    claim(input) {
      calls.push(input);
      if (state !== input.expectedState) return false;
      state = input.nextState;
      return true;
    }
  };

  const first = await claimCampaignProofJobAuthorizationGrantV1({
    grant: grantVector.valid.grant,
    expectedGrantRef: grantVector.valid.expectedGrantRef,
    now: grantVector.valid.grant.authorizedAt,
    grantStore
  });
  const second = await claimCampaignProofJobAuthorizationGrantV1({
    grant: grantVector.valid.grant,
    expectedGrantRef: grantVector.valid.expectedGrantRef,
    now: grantVector.valid.grant.authorizedAt,
    grantStore
  });

  assert.equal(first.reason, "campaign_proof_job_authorization_claimed");
  assert.equal(first.lifecycleState, "CLAIMED");
  assert.equal(second.reason, "proof_job_authorization_not_claimable");
  assert.deepEqual(calls[0], {
    grantRef: grantVector.valid.expectedGrantRef,
    expectedState: "AUTHORIZED",
    nextState: "CLAIMED"
  });
});

test("authorizes the existing synthetic Spend v2 holder package before proving", async () => {
  const fixture = structuredClone(completedPackageFixture);
  const events = [];
  let challengeOutstanding = true;
  let storedAuthorization;
  const authorize = createCampaignProofJobAuthorizer({
    generateGrantId: () => "proof-grant-test-1"
  });

  const result = await authorize({
    requestContext: fixture.package.requestContext,
    expectedScopeId: fixture.package.holderChallenge.scopeId,
    expectedVerifierId: fixture.package.holderChallenge.verifierId,
    authorizedInputManifest: fixture.authorizedInputManifest,
    holderAuthorizations: [
      {
        spendToken: fixture.package.spendToken,
        holderChallenge: fixture.package.holderChallenge,
        holderProof: fixture.package.holderProof
      }
    ],
    issuerRegistry: {
      isAuthorized() {
        events.push("issuer-authorized");
        return true;
      }
    },
    headStore: {
      isAccepted() {
        events.push("head-accepted");
        return true;
      }
    },
    challengeStore: {
      isOutstanding() {
        events.push("challenge-outstanding");
        return challengeOutstanding;
      },
      consume() {
        events.push("challenge-consumed");
        if (!challengeOutstanding) return false;
        challengeOutstanding = false;
        return true;
      }
    },
    grantStore: {
      authorize(value) {
        events.push("grant-authorized");
        storedAuthorization = structuredClone(value);
        return true;
      }
    },
    supportedProtocolVersions: ["1.0.0-rc.1"],
    now: fixture.verificationTime
  });

  assert.equal(result.ok, true);
  assert.equal(
    result.reason,
    "campaign_proof_job_authorization_granted"
  );
  assert.equal(result.grant.grantId, "proof-grant-test-1");
  assert.equal(
    result.grant.requestContextHash,
    fixture.expectedRequestContextHash
  );
  assert.deepEqual(result.grant.authorizedSpendInputs, [
    {
      spendId: fixture.package.spendToken.spendId,
      spendTokenHash:
        fixture.authorizedInputManifest.acceptedSpendInputs[0].spendTokenHash,
      canonicalHeadEventHash:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      challengeId: fixture.package.holderProof.challengeId
    }
  ]);
  assert.equal(
    storedAuthorization.grantRef,
    hashCampaignProofJobAuthorizationGrantV1(result.grant)
  );
  assert.equal(storedAuthorization.initialState, "AUTHORIZED");
  assert.deepEqual(events, [
    "issuer-authorized",
    "head-accepted",
    "issuer-authorized",
    "challenge-outstanding",
    "challenge-consumed",
    "grant-authorized"
  ]);
});

test("authorizes composite V2 lineage and copies only the compiled statement into the V1 grant", async () => {
  const fixture = makeSyntheticV2Fixture();
  let storedAuthorization;
  const authorize = createCampaignProofJobAuthorizer({
    generateGrantId: () => "proof-grant-composite-v2",
    verifySpendToken() {
      return fixture.admittedSpend;
    },
    verifyHolderControl() {
      return {
        ok: true,
        reason: "holder_control_verified",
        spendId: fixture.admittedSpend.spendId,
        spendTokenHash: fixture.admittedSpend.spendTokenHash,
        challengeId: fixture.challengeId,
        challengeConsumed: true
      };
    }
  });

  const result = await authorize({
    requestContext: fixture.requestContext,
    expectedScopeId: fixture.scopeId,
    expectedVerifierId: fixture.verifierId,
    authorizedInputManifest: fixture.manifest,
    holderAuthorizations: fixture.holderAuthorizations,
    headStore: { isAccepted: () => true },
    challengeStore: {
      isOutstanding: () => true,
      consume: () => true
    },
    grantStore: {
      authorize(value) {
        storedAuthorization = structuredClone(value);
        return true;
      }
    },
    now: "2026-07-28T00:02:00.000Z"
  });

  assert.equal(result.ok, true);
  assert.equal(result.grant.statementId, fixture.requestContext.compiledStatementId);
  assert.equal(
    result.grant.requestContextHash,
    hashCampaignHolderProofAuthorizationRequestContextV2(
      fixture.requestContext
    )
  );
  assert.equal(
    Object.hasOwn(result.grant, "conditionRequirementIds"),
    false
  );
  assert.equal(
    storedAuthorization.grantRef,
    hashCampaignProofJobAuthorizationGrantV1(result.grant)
  );
});

test("rejects unsorted composite manifest lineage before Spend or holder checks", async () => {
  const fixture = makeSyntheticV2Fixture();
  fixture.manifest.conditionRequirementIds.reverse();
  fixture.requestContext.inputManifestRef = hashCanonical(fixture.manifest);
  const requestContextHash =
    hashCampaignHolderProofAuthorizationRequestContextV2(
      fixture.requestContext
    );
  fixture.holderAuthorizations[0].holderChallenge.requestContextHash =
    requestContextHash;
  let externalCalls = 0;
  const authorize = createCampaignProofJobAuthorizer({
    verifySpendToken() {
      externalCalls += 1;
      return fixture.admittedSpend;
    },
    verifyHolderControl() {
      externalCalls += 1;
      return { ok: false };
    }
  });

  const result = await authorize({
    requestContext: fixture.requestContext,
    expectedScopeId: fixture.scopeId,
    expectedVerifierId: fixture.verifierId,
    authorizedInputManifest: fixture.manifest,
    holderAuthorizations: fixture.holderAuthorizations,
    headStore: { isAccepted: () => true },
    challengeStore: {
      isOutstanding: () => true,
      consume: () => true
    },
    grantStore: { authorize: () => true },
    now: "2026-07-28T00:02:00.000Z"
  });

  assert.equal(result.reason, "malformed_authorized_input_manifest");
  assert.equal(externalCalls, 0);
});

test("checks every accepted head before consuming any holder challenge", async () => {
  const fixture = structuredClone(completedPackageFixture);
  const events = [];
  const authorize = createCampaignProofJobAuthorizer({
    generateGrantId: () => "proof-grant-test-2"
  });

  const result = await authorize({
    requestContext: fixture.package.requestContext,
    expectedScopeId: fixture.package.holderChallenge.scopeId,
    expectedVerifierId: fixture.package.holderChallenge.verifierId,
    authorizedInputManifest: fixture.authorizedInputManifest,
    holderAuthorizations: [
      {
        spendToken: fixture.package.spendToken,
        holderChallenge: fixture.package.holderChallenge,
        holderProof: fixture.package.holderProof
      }
    ],
    issuerRegistry: {
      isAuthorized() {
        events.push("issuer-authorized");
        return true;
      }
    },
    headStore: {
      isAccepted() {
        events.push("head-rejected");
        return false;
      }
    },
    challengeStore: {
      isOutstanding() {
        events.push("challenge-outstanding");
        return true;
      },
      consume() {
        events.push("challenge-consumed");
        return true;
      }
    },
    grantStore: {
      authorize() {
        events.push("grant-authorized");
        return true;
      }
    },
    now: fixture.verificationTime
  });

  assert.equal(result.reason, "spend_token_head_not_accepted");
  assert.equal(result.partialConsumption, false);
  assert.deepEqual(result.consumedChallengeIds, []);
  assert.deepEqual(events, ["issuer-authorized", "head-rejected"]);
});

test("reports exact partial challenge consumption for a multi-Spend failure", async () => {
  const fixture = makeSyntheticMultiSpendFixture();
  const events = [];
  const challengeIds = fixture.holderAuthorizations.map((authorization) =>
    hashCanonical(authorization.holderChallenge)
  );
  let holderIndex = 0;
  const authorize = createCampaignProofJobAuthorizer({
    generateGrantId: () => "proof-grant-multi-spend",
    verifySpendToken({ token }) {
      const input = fixture.manifest.acceptedSpendInputs[token.index];
      return {
        ok: true,
        reason: "ok",
        spendId: input.spendId,
        spendTokenHash: input.spendTokenHash,
        headEventHash: normalizeHead(input.canonicalHeadEventHash),
        eventCount: 1,
        protocolVersion: "1.0.0-rc.1",
        issuedBy: input.issuerId,
        holderBinding: {
          scheme: "crinkl.holder.v2",
          commitment: sha256(`holder-${token.index}`)
        }
      };
    },
    verifyHolderControl({ token }) {
      const index = holderIndex;
      holderIndex += 1;
      events.push(`holder-${index}`);
      if (index === 1) {
        return {
          ok: false,
          reason: "holder_signature_invalid",
          challengeConsumed: false,
          challengeId: challengeIds[index]
        };
      }
      const input = fixture.manifest.acceptedSpendInputs[token.index];
      return {
        ok: true,
        reason: "holder_control_verified",
        spendId: input.spendId,
        spendTokenHash: input.spendTokenHash,
        challengeId: challengeIds[index],
        challengeConsumed: true
      };
    }
  });

  const result = await authorize({
    requestContext: fixture.requestContext,
    expectedScopeId: fixture.scopeId,
    expectedVerifierId: fixture.verifierId,
    authorizedInputManifest: fixture.manifest,
    holderAuthorizations: fixture.holderAuthorizations,
    headStore: {
      isAccepted({ spendId }) {
        events.push(`head-${spendId}`);
        return true;
      }
    },
    challengeStore: {
      isOutstanding() {
        return true;
      },
      consume() {
        return true;
      }
    },
    grantStore: {
      authorize() {
        events.push("grant-authorized");
        return true;
      }
    },
    now: "2026-07-28T00:02:00.000Z"
  });

  assert.equal(result.reason, "holder_signature_invalid");
  assert.equal(result.partialConsumption, true);
  assert.deepEqual(result.consumedChallengeIds, [challengeIds[0]]);
  assert.equal(result.retryRule, "NEW_HOLDER_CHALLENGES_REQUIRED");
  assert.deepEqual(events, [
    "head-spend-1",
    "head-spend-2",
    "holder-0",
    "holder-1"
  ]);
});

test("rejects duplicate multi-Spend token and challenge bindings before external checks", async () => {
  const fixture = makeSyntheticMultiSpendFixture();
  fixture.holderAuthorizations[1].holderChallenge = structuredClone(
    fixture.holderAuthorizations[0].holderChallenge
  );
  fixture.holderAuthorizations[1].holderChallenge.spendTokenHash =
    fixture.manifest.acceptedSpendInputs[1].spendTokenHash;
  fixture.holderAuthorizations[0].holderChallenge.spendTokenHash =
    fixture.manifest.acceptedSpendInputs[1].spendTokenHash;
  fixture.manifest.acceptedSpendInputs[0].spendTokenHash =
    fixture.manifest.acceptedSpendInputs[1].spendTokenHash;
  fixture.requestContext.inputManifestRef = hashCanonical(fixture.manifest);
  const requestContextHash =
    hashCampaignHolderProofAuthorizationRequestContextV1(
      fixture.requestContext
    );
  for (const authorization of fixture.holderAuthorizations) {
    authorization.holderChallenge.requestContextHash = requestContextHash;
  }
  let externalCalls = 0;
  const authorize = createCampaignProofJobAuthorizer({
    verifySpendToken() {
      externalCalls += 1;
      return { ok: false };
    },
    verifyHolderControl() {
      externalCalls += 1;
      return { ok: false };
    }
  });

  const result = await authorize({
    requestContext: fixture.requestContext,
    expectedScopeId: fixture.scopeId,
    expectedVerifierId: fixture.verifierId,
    authorizedInputManifest: fixture.manifest,
    holderAuthorizations: fixture.holderAuthorizations,
    headStore: {
      isAccepted() {
        externalCalls += 1;
        return true;
      }
    },
    challengeStore: {
      isOutstanding: () => true,
      consume: () => true
    },
    grantStore: { authorize: () => true },
    now: "2026-07-28T00:02:00.000Z"
  });

  assert.equal(result.reason, "malformed_authorized_input_manifest");
  assert.equal(result.partialConsumption, undefined);
  assert.equal(externalCalls, 0);
});

test("rejects a Spend admission from a different protocol version before holder consumption", async () => {
  const fixture = makeSyntheticMultiSpendFixture();
  fixture.manifest.acceptedSpendInputs = [
    fixture.manifest.acceptedSpendInputs[0]
  ];
  fixture.holderAuthorizations = [fixture.holderAuthorizations[0]];
  fixture.requestContext.inputManifestRef = hashCanonical(fixture.manifest);
  fixture.holderAuthorizations[0].holderChallenge.requestContextHash =
    hashCampaignHolderProofAuthorizationRequestContextV1(
      fixture.requestContext
    );
  let holderCalls = 0;
  const authorize = createCampaignProofJobAuthorizer({
    verifySpendToken() {
      const input = fixture.manifest.acceptedSpendInputs[0];
      return {
        ok: true,
        spendId: input.spendId,
        spendTokenHash: input.spendTokenHash,
        headEventHash: normalizeHead(input.canonicalHeadEventHash),
        eventCount: 1,
        protocolVersion: "2.0.0",
        issuedBy: input.issuerId
      };
    },
    verifyHolderControl() {
      holderCalls += 1;
      return { ok: false };
    }
  });

  const result = await authorize({
    requestContext: fixture.requestContext,
    expectedScopeId: fixture.scopeId,
    expectedVerifierId: fixture.verifierId,
    authorizedInputManifest: fixture.manifest,
    holderAuthorizations: fixture.holderAuthorizations,
    headStore: { isAccepted: () => true },
    challengeStore: {
      isOutstanding: () => true,
      consume: () => true
    },
    grantStore: { authorize: () => true },
    now: "2026-07-28T00:02:00.000Z"
  });

  assert.equal(result.reason, "authorized_spend_input_mismatch");
  assert.equal(result.partialConsumption, false);
  assert.equal(holderCalls, 0);
});

test("does not emit a grant when atomic AUTHORIZED persistence loses a race", async () => {
  const fixture = structuredClone(completedPackageFixture);
  let challengeOutstanding = true;
  const authorize = createCampaignProofJobAuthorizer({
    generateGrantId: () => "proof-grant-store-race"
  });

  const result = await authorize({
    requestContext: fixture.package.requestContext,
    expectedScopeId: fixture.package.holderChallenge.scopeId,
    expectedVerifierId: fixture.package.holderChallenge.verifierId,
    authorizedInputManifest: fixture.authorizedInputManifest,
    holderAuthorizations: [
      {
        spendToken: fixture.package.spendToken,
        holderChallenge: fixture.package.holderChallenge,
        holderProof: fixture.package.holderProof
      }
    ],
    issuerRegistry: { isAuthorized: () => true },
    headStore: { isAccepted: () => true },
    challengeStore: {
      isOutstanding: () => challengeOutstanding,
      consume() {
        if (!challengeOutstanding) return false;
        challengeOutstanding = false;
        return true;
      }
    },
    grantStore: { authorize: () => false },
    now: fixture.verificationTime
  });

  assert.equal(result.reason, "proof_job_authorization_store_race");
  assert.equal(result.grant, undefined);
  assert.equal(result.grantRef, undefined);
  assert.equal(result.partialConsumption, true);
  assert.deepEqual(result.consumedChallengeIds, [
    fixture.package.holderProof.challengeId
  ]);
  assert.equal(result.retryRule, "NEW_HOLDER_CHALLENGES_REQUIRED");
});

function makeSyntheticV2Fixture() {
  const base = structuredClone(completedPackageFixture);
  const manifest = base.authorizedInputManifest;
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
  manifest.compiledStatementId = base.package.atomicProof.statementId;
  manifest.proofProfileBindingRef =
    "sha256:8888888888888888888888888888888888888888888888888888888888888888";

  const requestContext = base.package.requestContext;
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

  const scopeId = manifest.relyingScopeRef;
  const verifierId = base.package.holderChallenge.verifierId;
  const requestContextHash =
    hashCampaignHolderProofAuthorizationRequestContextV2(requestContext);
  base.package.holderChallenge.requestContextHash = requestContextHash;
  const challengeId = hashCanonical(base.package.holderChallenge);
  const manifestInput = manifest.acceptedSpendInputs[0];
  const admittedSpend = {
    ok: true,
    reason: "spend_token_verified",
    spendId: manifestInput.spendId,
    spendTokenHash: manifestInput.spendTokenHash,
    headEventHash: normalizeHead(manifestInput.canonicalHeadEventHash),
    eventCount: 1,
    protocolVersion: requestContext.protocolVersion,
    issuedBy: manifestInput.issuerId
  };

  return {
    manifest,
    requestContext,
    scopeId,
    verifierId,
    challengeId,
    admittedSpend,
    holderAuthorizations: [
      {
        spendToken: base.package.spendToken,
        holderChallenge: base.package.holderChallenge,
        holderProof: base.package.holderProof
      }
    ]
  };
}

function makeSyntheticMultiSpendFixture() {
  const base = structuredClone(completedPackageFixture);
  const manifest = base.authorizedInputManifest;
  manifest.acceptedSpendInputs = [0, 1].map((index) => ({
    spendStreamNamespaceRef: sha256(`namespace-${index}`),
    issuerId: `issuer-${index}`,
    spendId: `spend-${index + 1}`,
    spendTokenHash: sha256(`token-${index}`),
    canonicalHeadEventHash: createHash("sha256")
      .update(`head-${index}`, "utf8")
      .digest("hex"),
    headSnapshotRef: sha256(`snapshot-${index}`),
    headInclusionProofRef: sha256(`inclusion-${index}`)
  }));

  const scopeId = manifest.relyingScopeRef;
  const verifierId = "crinkl-verifier-multi-spend";
  const requestContext = base.package.requestContext;
  requestContext.inputManifestRef = hashCanonical(manifest);
  const requestContextHash =
    hashCampaignHolderProofAuthorizationRequestContextV1(requestContext);
  const holderAuthorizations = manifest.acceptedSpendInputs.map(
    (input, index) => ({
      spendToken: { index },
      holderChallenge: {
        spendTokenHash: input.spendTokenHash,
        scopeId,
        requestContextHash,
        purpose: "CAMPAIGN_PROOF_AUTHORIZATION",
        verifierId
      },
      holderProof: {}
    })
  );
  return {
    manifest,
    requestContext,
    scopeId,
    verifierId,
    holderAuthorizations
  };
}

function setPath(target, path, value) {
  const parts = path.split(".");
  let cursor = target;
  for (let index = 0; index < parts.length - 1; index += 1) {
    const part = /^\d+$/u.test(parts[index])
      ? Number(parts[index])
      : parts[index];
    cursor = cursor[part];
  }
  const finalPart = /^\d+$/u.test(parts.at(-1))
    ? Number(parts.at(-1))
    : parts.at(-1);
  cursor[finalPart] = value;
}

function sha256(value) {
  return `sha256:${createHash("sha256")
    .update(value, "utf8")
    .digest("hex")}`;
}

function hashCanonical(value) {
  return sha256(canonicalize(value));
}

function normalizeHead(value) {
  return value.startsWith("sha256:") ? value : `sha256:${value}`;
}
