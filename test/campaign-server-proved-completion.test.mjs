import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  canonicalize,
  hashCampaignProofJobAuthorizationGrantV1,
  hashCampaignServerProvedCompletionPackageV1,
  verifyCampaignServerProvedCompletionV1
} from "../src/index.mjs";

const completionTemplate = JSON.parse(
  await readFile(
    new URL(
      "../fixtures/campaign-server-proved-completion-v1/valid.json",
      import.meta.url
    ),
    "utf8"
  )
);
const authorizationTemplate = JSON.parse(
  await readFile(
    new URL(
      "../fixtures/campaign-proof-authorization-v1/package.json",
      import.meta.url
    ),
    "utf8"
  )
);
const proofArtifactManifest = JSON.parse(
  await readFile(
    new URL(
      "../fixtures/h2-atomic-purchase-v2-candidate/manifest.json",
      import.meta.url
    ),
    "utf8"
  )
);

test("matches the adopted completion package, grant, and proof references", () => {
  const fixture = makeFixture();

  assert.equal(
    hashCampaignProofJobAuthorizationGrantV1(fixture.input.grant),
    completionTemplate.expectedGrantRef
  );
  assert.equal(
    hashCanonical(fixture.input.proofArtifact),
    completionTemplate.expectedProofArtifactRef
  );
  assert.equal(
    hashCampaignServerProvedCompletionPackageV1(fixture.input.package),
    completionTemplate.expectedCompletionRef
  );
});

test("completes a claimed proof job only after proof and nullifier acceptance", async () => {
  const fixture = makeFixture();

  const result = await verifyCampaignServerProvedCompletionV1(fixture.input);

  assert.equal(result.ok, true);
  assert.equal(result.reason, "campaign_server_proved_completion_verified");
  assert.equal(result.completionRef, completionTemplate.expectedCompletionRef);
  assert.equal(result.grantRef, completionTemplate.expectedGrantRef);
  assert.equal(result.campaignNullifierConsumed, true);
  assert.equal(result.grantLifecycleState, "COMPLETED");
  assert.equal(result.holderChallengeOperations, 0);
  assert.equal(result.partialConsumption, false);
  assert.deepEqual(fixture.events, [
    "lifecycle-get",
    "prover-authorized",
    "issuer-authorized",
    "head-accepted",
    "nullifier-has",
    "proof-verified",
    "nullifier-consumed",
    "lifecycle-COMPLETED"
  ]);
});

test("invalid cryptographic proof fails the claimed job without consuming its nullifier", async () => {
  const fixture = makeFixture({ proofAccepted: false });

  const result = await verifyCampaignServerProvedCompletionV1(fixture.input);

  assert.equal(result.reason, "cryptographic_verification_failed");
  assert.equal(result.campaignNullifierConsumed, false);
  assert.equal(result.grantLifecycleState, "FAILED");
  assert.equal(result.holderChallengeOperations, 0);
  assert.deepEqual(fixture.events, [
    "lifecycle-get",
    "prover-authorized",
    "issuer-authorized",
    "head-accepted",
    "nullifier-has",
    "proof-verified",
    "lifecycle-FAILED"
  ]);
});

test("nullifier consumption race fails the job and reports partial processing", async () => {
  const fixture = makeFixture({ nullifierConsumeResult: false });

  const result = await verifyCampaignServerProvedCompletionV1(fixture.input);

  assert.equal(result.reason, "campaign_nullifier_consumption_failed");
  assert.equal(result.campaignNullifierConsumed, false);
  assert.equal(result.grantLifecycleState, "FAILED");
  assert.equal(result.partialConsumption, true);
  assert.equal(result.holderChallengeOperations, 0);
  assert.deepEqual(fixture.events.slice(-2), [
    "nullifier-consumed",
    "lifecycle-FAILED"
  ]);
});

test("terminalization failure after nullifier consumption requires reconciliation", async () => {
  const fixture = makeFixture({ completionTransitionResult: false });

  const result = await verifyCampaignServerProvedCompletionV1(fixture.input);

  assert.equal(result.reason, "campaign_completion_terminalization_failed");
  assert.equal(result.campaignNullifierConsumed, true);
  assert.equal(result.grantLifecycleState, "CLAIMED");
  assert.equal(result.partialConsumption, true);
  assert.equal(result.reconciliationRequired, true);
  assert.equal(result.holderChallengeOperations, 0);
  assert.deepEqual(fixture.events.slice(-2), [
    "nullifier-consumed",
    "lifecycle-COMPLETED"
  ]);
});

test("unclaimed and differently claimed jobs fail before proof work", async () => {
  const unclaimed = makeFixture({
    lifecycle: {
      state: "AUTHORIZED"
    }
  });
  const unclaimedResult =
    await verifyCampaignServerProvedCompletionV1(unclaimed.input);
  assert.equal(
    unclaimedResult.reason,
    "proof_job_authorization_not_claimed"
  );
  assert.deepEqual(unclaimed.events, ["lifecycle-get"]);

  const otherProver = makeFixture({
    lifecycle: {
      ...completionTemplate.grantLifecycle,
      claimedBy: "other-prover"
    }
  });
  const otherResult =
    await verifyCampaignServerProvedCompletionV1(otherProver.input);
  assert.equal(otherResult.reason, "proof_job_claimed_by_other_prover");
  assert.deepEqual(otherProver.events, ["lifecycle-get"]);
});

test("changed proof content is rejected against its canonical reference and terminalized", async () => {
  const fixture = makeFixture();
  fixture.input.proofArtifact.proof = "dGFtcGVyZWQ=";

  const result = await verifyCampaignServerProvedCompletionV1(fixture.input);

  assert.equal(result.reason, "proof_artifact_ref_mismatch");
  assert.equal(result.grantLifecycleState, "FAILED");
  assert.deepEqual(fixture.events, [
    "lifecycle-get",
    "prover-authorized",
    "lifecycle-FAILED"
  ]);
});

test("proof lineage mismatch fails before cryptographic verification", async () => {
  const fixture = makeFixture();
  fixture.input.proofArtifact.issuedBy = "other-prover";
  rebindProofAndCompletion(fixture.input);

  const result = await verifyCampaignServerProvedCompletionV1(fixture.input);

  assert.equal(result.reason, "proof_job_lineage_mismatch");
  assert.equal(result.grantLifecycleState, "FAILED");
  assert.deepEqual(fixture.events, [
    "lifecycle-get",
    "prover-authorized",
    "lifecycle-FAILED"
  ]);
});

test("enforces the adopted proof-lineage mutation decisions", async () => {
  const cases = [
    {
      id: "proof-created-before-claim",
      path: "createdAt",
      value: "2026-07-28T00:02:59.999Z",
      reason: "proof_job_time_mismatch"
    },
    {
      id: "proof-issued-by-other-prover",
      path: "issuedBy",
      value: "other-prover",
      reason: "proof_job_lineage_mismatch"
    },
    {
      id: "changed-proof-profile",
      path: "circuitId",
      value: "H2_OTHER_V1",
      reason: "proof_job_lineage_mismatch"
    },
    {
      id: "changed-statement",
      path: "statementId",
      value:
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      reason: "proof_job_lineage_mismatch"
    },
    {
      id: "changed-scope",
      path: "scopeId",
      value:
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      reason: "proof_job_lineage_mismatch"
    },
    {
      id: "changed-spend-token",
      path: "spendTokenHash",
      value:
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      reason: "proof_job_lineage_mismatch"
    },
    {
      id: "changed-spend-head",
      path: "binding.headEventHash",
      value:
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      reason: "proof_job_lineage_mismatch"
    },
    {
      id: "changed-public-scope",
      path: "publicInputs.scopeId",
      value:
        "sha256:0101010101010101010101010101010101010101010101010101010101010101",
      reason: "proof_job_lineage_mismatch"
    },
    {
      id: "changed-public-nullifier",
      path: "publicInputs.nullifier",
      value:
        "sha256:0202020202020202020202020202020202020202020202020202020202020202",
      reason: "proof_job_lineage_mismatch"
    },
    {
      id: "changed-public-spend-token",
      path: "publicInputs.spendTokenHash",
      value:
        "sha256:0303030303030303030303030303030303030303030303030303030303030303",
      reason: "proof_job_lineage_mismatch"
    }
  ];

  for (const vectorCase of cases) {
    const fixture = makeFixture();
    setPath(
      fixture.input.proofArtifact,
      vectorCase.path,
      vectorCase.value
    );
    rebindProofAndCompletion(fixture.input);

    const result =
      await verifyCampaignServerProvedCompletionV1(fixture.input);

    assert.equal(result.reason, vectorCase.reason, vectorCase.id);
    assert.equal(result.grantLifecycleState, "FAILED", vectorCase.id);
    assert.equal(
      fixture.events.includes("proof-verified"),
      false,
      vectorCase.id
    );
    assert.equal(
      fixture.events.includes("nullifier-consumed"),
      false,
      vectorCase.id
    );
  }
});

test("a multi-Spend grant cannot silently complete from one atomic proof", async () => {
  const fixture = makeFixture();
  fixture.input.grant.authorizedSpendInputs.push({
    spendId: "spend-holder-vector-2",
    spendTokenHash:
      "sha256:1212121212121212121212121212121212121212121212121212121212121212",
    canonicalHeadEventHash:
      "sha256:3434343434343434343434343434343434343434343434343434343434343434",
    challengeId:
      "sha256:5656565656565656565656565656565656565656565656565656565656565656"
  });
  rebindGrantAndCompletion(fixture.input);

  const result = await verifyCampaignServerProvedCompletionV1(fixture.input);

  assert.equal(result.reason, "proof_job_lineage_mismatch");
  assert.equal(result.grantLifecycleState, "FAILED");
  assert.equal(fixture.events.includes("proof-verified"), false);
  assert.equal(fixture.events.includes("nullifier-consumed"), false);
});

test("completion performs no holder challenge operation", async () => {
  const fixture = makeFixture();
  let holderOperations = 0;
  fixture.input.holderChallengeStore = {
    isOutstanding() {
      holderOperations += 1;
      throw new Error("holder operation prohibited");
    },
    consume() {
      holderOperations += 1;
      throw new Error("holder operation prohibited");
    }
  };

  const result = await verifyCampaignServerProvedCompletionV1(fixture.input);

  assert.equal(result.ok, true);
  assert.equal(result.holderChallengeOperations, 0);
  assert.equal(holderOperations, 0);
});

test("strict package, grant, expiry, and prover gates run before proof work", async () => {
  const unknownField = makeFixture();
  unknownField.input.package.extra = true;
  const unknownResult =
    await verifyCampaignServerProvedCompletionV1(unknownField.input);
  assert.equal(unknownResult.reason, "completion_package_shape_invalid");
  assert.deepEqual(unknownField.events, []);

  const changedPackage = makeFixture();
  changedPackage.input.package.proverId = "other-prover";
  const changedPackageResult =
    await verifyCampaignServerProvedCompletionV1(changedPackage.input);
  assert.equal(changedPackageResult.reason, "completion_ref_mismatch");
  assert.deepEqual(changedPackage.events, []);

  const changedGrant = makeFixture();
  changedGrant.input.grant.grantId = "other-grant";
  const changedGrantResult =
    await verifyCampaignServerProvedCompletionV1(changedGrant.input);
  assert.equal(changedGrantResult.reason, "grant_ref_mismatch");
  assert.deepEqual(changedGrant.events, []);

  const expired = makeFixture();
  expired.input.package.completedAt = expired.input.grant.expiresAt;
  expired.input.expectedCompletionRef =
    hashCampaignServerProvedCompletionPackageV1(expired.input.package);
  const expiredResult =
    await verifyCampaignServerProvedCompletionV1(expired.input);
  assert.equal(expiredResult.reason, "proof_job_authorization_expired");
  assert.deepEqual(expired.events, [
    "lifecycle-get",
    "prover-authorized"
  ]);

  const unauthorized = makeFixture({ proverAuthorized: false });
  const unauthorizedResult =
    await verifyCampaignServerProvedCompletionV1(unauthorized.input);
  assert.equal(unauthorizedResult.reason, "prover_not_authorized");
  assert.deepEqual(unauthorized.events, [
    "lifecycle-get",
    "prover-authorized"
  ]);
});

test("a failed terminal transition is explicit and requires reconciliation", async () => {
  const fixture = makeFixture({
    proofAccepted: false,
    failureTransitionResult: false
  });

  const result = await verifyCampaignServerProvedCompletionV1(fixture.input);

  assert.equal(result.reason, "proof_job_failure_terminalization_failed");
  assert.equal(result.failedReason, "cryptographic_verification_failed");
  assert.equal(result.grantLifecycleState, "CLAIMED");
  assert.equal(result.reconciliationRequired, true);
  assert.equal(result.holderChallengeOperations, 0);
  assert.equal(result.campaignNullifierConsumed, false);
});

function makeFixture({
  proofAccepted = true,
  nullifierConsumeResult = true,
  completionTransitionResult = true,
  failureTransitionResult = true,
  proverAuthorized = true,
  lifecycle = completionTemplate.grantLifecycle
} = {}) {
  const events = [];
  const proofArtifact = structuredClone(
    authorizationTemplate.package.atomicProof
  );
  proofArtifact.issuedBy = completionTemplate.package.proverId;
  proofArtifact.createdAt = "2026-07-28T00:03:30.000Z";
  const spendToken = structuredClone(
    authorizationTemplate.package.spendToken
  );
  let currentLifecycle = structuredClone(lifecycle);
  const consumedNullifiers = new Set();

  return {
    events,
    input: {
      package: structuredClone(completionTemplate.package),
      expectedCompletionRef: completionTemplate.expectedCompletionRef,
      grant: structuredClone(completionTemplate.grant),
      proofArtifact,
      spendTokens: [spendToken],
      proofArtifactManifest,
      hashStatement: hashCanonical,
      backend: {
        verify() {
          events.push("proof-verified");
          return {
            ok: proofAccepted,
            reason: proofAccepted
              ? "ok"
              : "cryptographic_verification_failed"
          };
        }
      },
      issuerRegistry: {
        isAuthorized({ issuedBy, publicKey }) {
          events.push("issuer-authorized");
          return (
            issuedBy === spendToken.signatures.issuedBy &&
            publicKey === spendToken.signatures.publicKey
          );
        }
      },
      headStore: {
        isAccepted() {
          events.push("head-accepted");
          return true;
        }
      },
      proverRegistry: {
        isAuthorized({ proverId }) {
          events.push("prover-authorized");
          return (
            proverAuthorized &&
            proverId === completionTemplate.package.proverId
          );
        }
      },
      grantLifecycleStore: {
        get() {
          events.push("lifecycle-get");
          return structuredClone(currentLifecycle);
        },
        transition({ expectedState, nextState }) {
          events.push(`lifecycle-${nextState}`);
          if (
            currentLifecycle.state !== expectedState ||
            (nextState === "COMPLETED" && !completionTransitionResult) ||
            (nextState === "FAILED" && !failureTransitionResult)
          ) {
            return false;
          }
          currentLifecycle = {
            state: nextState
          };
          return true;
        }
      },
      campaignNullifierStore: {
        has(scopeId, nullifier) {
          events.push("nullifier-has");
          return consumedNullifiers.has(replayKey(scopeId, nullifier));
        },
        consume(scopeId, nullifier) {
          events.push("nullifier-consumed");
          const key = replayKey(scopeId, nullifier);
          if (
            !nullifierConsumeResult ||
            consumedNullifiers.has(key)
          ) {
            return false;
          }
          consumedNullifiers.add(key);
          return true;
        }
      }
    }
  };
}

function rebindProofAndCompletion(input) {
  input.package.proofArtifactRef = hashCanonical(input.proofArtifact);
  input.expectedCompletionRef =
    hashCampaignServerProvedCompletionPackageV1(input.package);
}

function rebindGrantAndCompletion(input) {
  input.package.grantRef =
    hashCampaignProofJobAuthorizationGrantV1(input.grant);
  input.expectedCompletionRef =
    hashCampaignServerProvedCompletionPackageV1(input.package);
}

function hashCanonical(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("hex")}`;
}

function replayKey(scopeId, nullifier) {
  return `${scopeId}\u0000${nullifier}`;
}

function setPath(target, path, value) {
  const segments = path.split(".");
  let current = target;
  for (const segment of segments.slice(0, -1)) {
    current = current[segment];
  }
  current[segments.at(-1)] = value;
}
