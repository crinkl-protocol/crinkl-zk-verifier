import { createHash, randomBytes } from "node:crypto";

import {
  hashCampaignHolderProofAuthorizationRequestContextV1
} from "./campaign-proof-authorization.mjs";
import { verifySpendHolderControlV2 } from "./spend-holder-control.mjs";
import {
  canonicalize,
  verifySpendAttestationTokenV2
} from "./spend-token-admission.mjs";

const GRANT_DOMAIN =
  "crinkl:campaign:proof-job-authorization-grant:v1";
const INPUT_MANIFEST_DOMAIN =
  "crinkl:buyer-state:statement-evaluation-input-manifest:v1";
const PROTOCOL_VERSION = "1.0.0-rc.1";
const HOLDER_PURPOSE = "CAMPAIGN_PROOF_AUTHORIZATION";
const DEFAULT_MAXIMUM_GRANT_LIFETIME_MS = 15 * 60 * 1000;
const SHA256_ID_RE = /^sha256:[0-9a-f]{64}$/;
const RAW_SHA256_RE = /^[0-9a-f]{64}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const TIMESTAMP_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const GRANT_KEYS = Object.freeze([
  "domain",
  "schemaVersion",
  "protocolVersion",
  "grantId",
  "requestContextHash",
  "campaignId",
  "campaignEpochRef",
  "campaignPolicyPackageRef",
  "scopeId",
  "statementId",
  "proofProfile",
  "inputManifestRef",
  "recipientDisclosurePolicyRef",
  "authorizedSpendInputs",
  "verifierId",
  "authorizedAt",
  "expiresAt"
]);
const PROOF_PROFILE_KEYS = Object.freeze([
  "proofSystem",
  "circuitId",
  "verifyingKeyId"
]);
const AUTHORIZED_SPEND_INPUT_KEYS = Object.freeze([
  "spendId",
  "spendTokenHash",
  "canonicalHeadEventHash",
  "challengeId"
]);
const INPUT_MANIFEST_KEYS = Object.freeze([
  "domain",
  "schemaVersion",
  "protocolVersion",
  "conditionId",
  "requirementId",
  "statementId",
  "statementEvaluationProfileRef",
  "evaluationContextHash",
  "evaluationCutoff",
  "relyingScopeRef",
  "acceptedSpendInputs",
  "sourceBindings",
  "sourceSelectionBindings",
  "inputDisclosure",
  "stableSubjectFields"
]);
const SPEND_INPUT_KEYS = Object.freeze([
  "spendStreamNamespaceRef",
  "issuerId",
  "spendId",
  "spendTokenHash",
  "canonicalHeadEventHash",
  "headSnapshotRef",
  "headInclusionProofRef"
]);
const SOURCE_BINDING_KEYS = Object.freeze(["sourceProfile", "sourceRef"]);
const SOURCE_SELECTION_KEYS = Object.freeze([
  "sourceProfile",
  "requestRef",
  "checkpointRef",
  "selectionRef"
]);
const HOLDER_AUTHORIZATION_KEYS = Object.freeze([
  "spendToken",
  "holderChallenge",
  "holderProof"
]);

export function hashCampaignProofJobAuthorizationGrantV1(grant) {
  const shape = validateGrant(grant);
  if (!shape.ok) {
    throw new TypeError(shape.reason);
  }
  return hashCanonical(grant);
}

export function verifyCampaignProofJobAuthorizationGrantV1({
  grant,
  expectedGrantRef,
  now = new Date()
} = {}) {
  const shape = validateGrant(grant);
  if (!shape.ok) {
    return rejected("grant_shape_invalid");
  }
  if (!isSha256Id(expectedGrantRef)) {
    return rejected("grant_ref_invalid");
  }

  let grantRef;
  try {
    grantRef = hashCanonical(grant);
  } catch {
    return rejected("grant_shape_invalid");
  }
  if (grantRef !== expectedGrantRef) {
    return rejected("grant_ref_mismatch", { grantRef });
  }

  const verificationTime = parseTime(now);
  const expiresAt = parseTimestamp(grant.expiresAt);
  if (verificationTime === null || expiresAt === null) {
    return rejected("grant_shape_invalid");
  }
  if (verificationTime >= expiresAt) {
    return rejected("proof_job_authorization_expired", { grantRef });
  }

  return {
    ok: true,
    reason: "campaign_proof_job_authorization_verified",
    grantRef,
    grantId: grant.grantId
  };
}

export async function claimCampaignProofJobAuthorizationGrantV1({
  grant,
  expectedGrantRef,
  now = new Date(),
  grantStore
} = {}) {
  const verification = verifyCampaignProofJobAuthorizationGrantV1({
    grant,
    expectedGrantRef,
    now
  });
  if (!verification.ok) return verification;
  if (!isGrantClaimStore(grantStore)) {
    return rejected("proof_job_authorization_store_required", {
      grantRef: verification.grantRef
    });
  }

  let claimed = false;
  try {
    claimed =
      (await grantStore.claim({
        grantRef: verification.grantRef,
        expectedState: "AUTHORIZED",
        nextState: "CLAIMED"
      })) === true;
  } catch {
    claimed = false;
  }
  if (!claimed) {
    return rejected("proof_job_authorization_not_claimable", {
      grantRef: verification.grantRef
    });
  }

  return {
    ...verification,
    reason: "campaign_proof_job_authorization_claimed",
    lifecycleState: "CLAIMED"
  };
}

export function createCampaignProofJobAuthorizer({
  verifySpendToken = verifySpendAttestationTokenV2,
  verifyHolderControl = verifySpendHolderControlV2,
  generateGrantId = defaultGenerateGrantId,
  maximumGrantLifetimeMs = DEFAULT_MAXIMUM_GRANT_LIFETIME_MS
} = {}) {
  if (
    typeof verifySpendToken !== "function" ||
    typeof verifyHolderControl !== "function" ||
    typeof generateGrantId !== "function" ||
    !Number.isSafeInteger(maximumGrantLifetimeMs) ||
    maximumGrantLifetimeMs <= 0
  ) {
    throw new TypeError("proof-job authorizer dependencies are invalid");
  }

  return async function authorizeCampaignProofJobV1(input = {}) {
    const {
      requestContext,
      expectedScopeId,
      expectedVerifierId,
      authorizedInputManifest,
      holderAuthorizations,
      issuerRegistry,
      headStore,
      challengeStore,
      grantStore,
      supportedProtocolVersions = [PROTOCOL_VERSION],
      now = new Date()
    } = input;

    let requestContextHash;
    try {
      requestContextHash =
        hashCampaignHolderProofAuthorizationRequestContextV1(requestContext);
    } catch {
      return rejected("malformed_campaign_request_context");
    }
    if (!isSha256Id(expectedScopeId) || !isIdentifier(expectedVerifierId)) {
      return rejected("campaign_request_context_mismatch", {
        requestContextHash,
        requestContextChecked: true
      });
    }

    const authorizationTime = parseTime(now);
    const authorizationExpiresAt = parseTimestamp(
      requestContext.authorizationExpiresAt
    );
    if (
      authorizationTime === null ||
      authorizationExpiresAt === null ||
      authorizationTime >= authorizationExpiresAt
    ) {
      return rejected("campaign_proof_authorization_expired", {
        requestContextHash,
        requestContextChecked: true
      });
    }
    if (
      authorizationExpiresAt - authorizationTime >
      maximumGrantLifetimeMs
    ) {
      return rejected("campaign_proof_authorization_lifetime_exceeded", {
        requestContextHash,
        requestContextChecked: true
      });
    }

    const manifestCheck = validateAuthorizedInputManifest({
      manifest: authorizedInputManifest,
      requestContext,
      expectedScopeId
    });
    if (!manifestCheck.ok) {
      return rejected(manifestCheck.reason, {
        requestContextHash,
        requestContextChecked: true,
        inputManifestChecked: true
      });
    }
    if (
      !Array.isArray(holderAuthorizations) ||
      holderAuthorizations.length !==
        authorizedInputManifest.acceptedSpendInputs.length ||
      !holderAuthorizations.every((authorization) =>
        isExactRecord(authorization, HOLDER_AUTHORIZATION_KEYS)
      )
    ) {
      return rejected("holder_authorization_set_mismatch", {
        requestContextHash,
        requestContextChecked: true,
        inputManifestChecked: true
      });
    }
    if (!isHeadStore(headStore)) {
      return rejected("spend_token_head_store_required", {
        requestContextHash,
        requestContextChecked: true,
        inputManifestChecked: true
      });
    }
    if (!isChallengeStore(challengeStore)) {
      return rejected("holder_challenge_store_required", {
        requestContextHash,
        requestContextChecked: true,
        inputManifestChecked: true
      });
    }
    if (!isGrantAuthorizationStore(grantStore)) {
      return rejected("proof_job_authorization_store_required", {
        requestContextHash,
        requestContextChecked: true,
        inputManifestChecked: true
      });
    }

    const admissions = [];
    const challengeIds = [];
    const challengeIdsSeen = new Set();
    for (
      let index = 0;
      index < authorizedInputManifest.acceptedSpendInputs.length;
      index += 1
    ) {
      const manifestInput =
        authorizedInputManifest.acceptedSpendInputs[index];
      const holderAuthorization = holderAuthorizations[index];
      const challengeCheck = validateChallengeBinding({
        challenge: holderAuthorization.holderChallenge,
        manifestInput,
        requestContextHash,
        expectedScopeId,
        expectedVerifierId
      });
      if (!challengeCheck.ok) {
        return rejected(challengeCheck.reason, {
          requestContextHash,
          requestContextChecked: true,
          inputManifestChecked: true,
          spendHeadsChecked: false,
          consumedChallengeIds: [],
          partialConsumption: false
        });
      }
      let challengeId;
      try {
        challengeId = hashCanonical(holderAuthorization.holderChallenge);
      } catch {
        challengeId = null;
      }
      if (!isSha256Id(challengeId) || challengeIdsSeen.has(challengeId)) {
        return rejected("holder_authorization_set_mismatch", {
          requestContextHash,
          requestContextChecked: true,
          inputManifestChecked: true,
          spendHeadsChecked: false,
          consumedChallengeIds: [],
          partialConsumption: false
        });
      }
      challengeIdsSeen.add(challengeId);
      challengeIds.push(challengeId);

      let admission;
      try {
        admission = await verifySpendToken({
          token: holderAuthorization.spendToken,
          issuerRegistry,
          supportedProtocolVersions
        });
      } catch {
        admission = { ok: false, reason: "spend_token_verifier_failed" };
      }
      if (!isRecord(admission) || admission.ok !== true) {
        return rejected(
          isRecord(admission) && isNonEmptyString(admission.reason)
            ? admission.reason
            : "spend_token_verifier_failed",
          {
            requestContextHash,
            requestContextChecked: true,
            inputManifestChecked: true,
            spendHeadsChecked: false,
            consumedChallengeIds: [],
            partialConsumption: false
          }
        );
      }
      if (
        admission.spendId !== manifestInput.spendId ||
        admission.spendTokenHash !== manifestInput.spendTokenHash ||
        admission.headEventHash !==
          normalizeSha256Id(manifestInput.canonicalHeadEventHash) ||
        admission.issuedBy !== manifestInput.issuerId ||
        admission.protocolVersion !== requestContext.protocolVersion
      ) {
        return rejected("authorized_spend_input_mismatch", {
          requestContextHash,
          requestContextChecked: true,
          inputManifestChecked: true,
          spendHeadsChecked: false,
          consumedChallengeIds: [],
          partialConsumption: false
        });
      }

      let headAccepted = false;
      try {
        headAccepted =
          (await headStore.isAccepted({
            spendId: admission.spendId,
            spendTokenHash: admission.spendTokenHash,
            headEventHash: admission.headEventHash,
            eventCount: admission.eventCount,
            protocolVersion: admission.protocolVersion
          })) === true;
      } catch {
        headAccepted = false;
      }
      if (!headAccepted) {
        return rejected("spend_token_head_not_accepted", {
          requestContextHash,
          requestContextChecked: true,
          inputManifestChecked: true,
          spendHeadsChecked: false,
          consumedChallengeIds: [],
          partialConsumption: false
        });
      }
      admissions.push(admission);
    }

    const consumedChallengeIds = [];
    const authorizedSpendInputs = [];
    for (
      let index = 0;
      index < authorizedInputManifest.acceptedSpendInputs.length;
      index += 1
    ) {
      const manifestInput =
        authorizedInputManifest.acceptedSpendInputs[index];
      const holderAuthorization = holderAuthorizations[index];
      let holderResult;
      try {
        holderResult = await verifyHolderControl({
          token: holderAuthorization.spendToken,
          issuerRegistry,
          supportedProtocolVersions,
          challenge: holderAuthorization.holderChallenge,
          holderProof: holderAuthorization.holderProof,
          expectedContext: {
            spendTokenHash: manifestInput.spendTokenHash,
            scopeId: expectedScopeId,
            requestContextHash,
            purpose: HOLDER_PURPOSE,
            verifierId: expectedVerifierId
          },
          now,
          challengeStore
        });
      } catch {
        holderResult = {
          ok: false,
          reason: "campaign_holder_verifier_failed"
        };
      }

      if (!isRecord(holderResult) || holderResult.ok !== true) {
        if (
          isRecord(holderResult) &&
          holderResult.challengeConsumed === true &&
          isSha256Id(holderResult.challengeId)
        ) {
          consumedChallengeIds.push(holderResult.challengeId);
        }
        return rejected(
          isRecord(holderResult) && isNonEmptyString(holderResult.reason)
            ? holderResult.reason
            : "campaign_holder_verifier_failed",
          partialFailureFields(consumedChallengeIds, {
            requestContextHash,
            requestContextChecked: true,
            inputManifestChecked: true,
            spendHeadsChecked: true,
            holderControlsChecked: index + 1
          })
        );
      }
      if (
        holderResult.challengeConsumed !== true ||
        !isSha256Id(holderResult.challengeId) ||
        holderResult.challengeId !== challengeIds[index] ||
        holderResult.spendId !== admissions[index].spendId ||
        holderResult.spendTokenHash !== admissions[index].spendTokenHash
      ) {
        if (
          holderResult.challengeConsumed === true &&
          isSha256Id(holderResult.challengeId)
        ) {
          consumedChallengeIds.push(holderResult.challengeId);
        }
        return rejected(
          "holder_authorization_result_mismatch",
          partialFailureFields(consumedChallengeIds, {
            requestContextHash,
            requestContextChecked: true,
            inputManifestChecked: true,
            spendHeadsChecked: true,
            holderControlsChecked: index + 1
          })
        );
      }

      consumedChallengeIds.push(holderResult.challengeId);
      authorizedSpendInputs.push({
        spendId: manifestInput.spendId,
        spendTokenHash: manifestInput.spendTokenHash,
        canonicalHeadEventHash: normalizeSha256Id(
          manifestInput.canonicalHeadEventHash
        ),
        challengeId: holderResult.challengeId
      });
    }

    let grantId;
    try {
      grantId = generateGrantId();
    } catch {
      grantId = null;
    }
    if (!isIdentifier(grantId)) {
      return rejected(
        "grant_id_generation_failed",
        partialFailureFields(consumedChallengeIds, {
          requestContextHash,
          requestContextChecked: true,
          inputManifestChecked: true,
          spendHeadsChecked: true,
          holderControlsChecked: authorizedSpendInputs.length
        })
      );
    }

    const grant = {
      domain: GRANT_DOMAIN,
      schemaVersion: 1,
      protocolVersion: PROTOCOL_VERSION,
      grantId,
      requestContextHash,
      campaignId: requestContext.campaignId,
      campaignEpochRef: requestContext.campaignEpochRef,
      campaignPolicyPackageRef: requestContext.campaignPolicyPackageRef,
      scopeId: expectedScopeId,
      statementId: requestContext.statementId,
      proofProfile: { ...requestContext.proofProfile },
      inputManifestRef: requestContext.inputManifestRef,
      recipientDisclosurePolicyRef:
        requestContext.recipientDisclosurePolicyRef,
      authorizedSpendInputs,
      verifierId: expectedVerifierId,
      authorizedAt: new Date(authorizationTime).toISOString(),
      expiresAt: requestContext.authorizationExpiresAt
    };

    let grantRef;
    try {
      grantRef = hashCampaignProofJobAuthorizationGrantV1(grant);
    } catch {
      return rejected(
        "grant_shape_invalid",
        partialFailureFields(consumedChallengeIds, {
          requestContextHash,
          requestContextChecked: true,
          inputManifestChecked: true,
          spendHeadsChecked: true,
          holderControlsChecked: authorizedSpendInputs.length
        })
      );
    }

    let authorized = false;
    try {
      authorized =
        (await grantStore.authorize({
          grantRef,
          grant,
          initialState: "AUTHORIZED"
        })) === true;
    } catch {
      authorized = false;
    }
    if (!authorized) {
      return rejected(
        "proof_job_authorization_store_race",
        partialFailureFields(consumedChallengeIds, {
          requestContextHash,
          requestContextChecked: true,
          inputManifestChecked: true,
          spendHeadsChecked: true,
          holderControlsChecked: authorizedSpendInputs.length
        })
      );
    }

    return {
      ok: true,
      reason: "campaign_proof_job_authorization_granted",
      grant,
      grantRef,
      lifecycleState: "AUTHORIZED",
      requestContextHash,
      requestContextChecked: true,
      inputManifestChecked: true,
      spendHeadsChecked: true,
      holderControlsChecked: authorizedSpendInputs.length,
      consumedChallengeIds,
      partialConsumption: false
    };
  };
}

function validateGrant(grant) {
  if (
    !isExactRecord(grant, GRANT_KEYS) ||
    !isExactRecord(grant.proofProfile, PROOF_PROFILE_KEYS) ||
    grant.domain !== GRANT_DOMAIN ||
    grant.schemaVersion !== 1 ||
    grant.protocolVersion !== PROTOCOL_VERSION ||
    !isIdentifier(grant.grantId) ||
    !isIdentifier(grant.campaignId) ||
    !isIdentifier(grant.verifierId) ||
    !isIdentifier(grant.proofProfile.proofSystem) ||
    !isIdentifier(grant.proofProfile.circuitId) ||
    !isSha256Id(grant.requestContextHash) ||
    !isSha256Id(grant.campaignEpochRef) ||
    !isSha256Id(grant.campaignPolicyPackageRef) ||
    !isSha256Id(grant.scopeId) ||
    !isSha256Id(grant.statementId) ||
    !isSha256Id(grant.proofProfile.verifyingKeyId) ||
    !isSha256Id(grant.inputManifestRef) ||
    !isSha256Id(grant.recipientDisclosurePolicyRef) ||
    !Array.isArray(grant.authorizedSpendInputs) ||
    grant.authorizedSpendInputs.length === 0 ||
    !grant.authorizedSpendInputs.every(
      (input) =>
        isExactRecord(input, AUTHORIZED_SPEND_INPUT_KEYS) &&
        isIdentifier(input.spendId) &&
        isSha256Id(input.spendTokenHash) &&
        isSha256Id(input.canonicalHeadEventHash) &&
        isSha256Id(input.challengeId)
    )
  ) {
    return { ok: false, reason: "grant_shape_invalid" };
  }
  const authorizedAt = parseTimestamp(grant.authorizedAt);
  const expiresAt = parseTimestamp(grant.expiresAt);
  if (
    authorizedAt === null ||
    expiresAt === null ||
    expiresAt <= authorizedAt ||
    hasDuplicateField(grant.authorizedSpendInputs, "spendId") ||
    hasDuplicateField(grant.authorizedSpendInputs, "spendTokenHash") ||
    hasDuplicateField(grant.authorizedSpendInputs, "challengeId")
  ) {
    return { ok: false, reason: "grant_shape_invalid" };
  }
  return { ok: true };
}

function validateAuthorizedInputManifest({
  manifest,
  requestContext,
  expectedScopeId
}) {
  if (
    !isExactRecord(manifest, INPUT_MANIFEST_KEYS) ||
    manifest.domain !== INPUT_MANIFEST_DOMAIN ||
    manifest.schemaVersion !== 1 ||
    manifest.protocolVersion !== PROTOCOL_VERSION ||
    manifest.inputDisclosure !==
      "NON_PORTABLE_AUTHORIZED_EVALUATION_BOUNDARY_ONLY" ||
    manifest.stableSubjectFields !== "PROHIBITED" ||
    !isTimestamp(manifest.evaluationCutoff) ||
    !isSha256Id(manifest.relyingScopeRef) ||
    !Array.isArray(manifest.acceptedSpendInputs) ||
    manifest.acceptedSpendInputs.length === 0 ||
    !manifest.acceptedSpendInputs.every(validateManifestSpendInput) ||
    hasDuplicateField(manifest.acceptedSpendInputs, "spendId") ||
    hasDuplicateField(manifest.acceptedSpendInputs, "spendTokenHash") ||
    !Array.isArray(manifest.sourceBindings) ||
    manifest.sourceBindings.length === 0 ||
    !manifest.sourceBindings.every(
      (binding) =>
        isExactRecord(binding, SOURCE_BINDING_KEYS) &&
        isIdentifier(binding.sourceProfile) &&
        isSha256Id(binding.sourceRef)
    ) ||
    !Array.isArray(manifest.sourceSelectionBindings) ||
    !manifest.sourceSelectionBindings.every(
      (binding) =>
        isExactRecord(binding, SOURCE_SELECTION_KEYS) &&
        isIdentifier(binding.sourceProfile) &&
        isSha256Id(binding.requestRef) &&
        isSha256Id(binding.checkpointRef) &&
        isSha256Id(binding.selectionRef)
    ) ||
    hasCanonicalDuplicates(manifest.sourceBindings) ||
    hasCanonicalDuplicates(manifest.sourceSelectionBindings)
  ) {
    return { ok: false, reason: "malformed_authorized_input_manifest" };
  }

  let inputManifestRef;
  try {
    inputManifestRef = hashCanonical(manifest);
  } catch {
    return { ok: false, reason: "malformed_authorized_input_manifest" };
  }
  if (
    inputManifestRef !== requestContext.inputManifestRef ||
    manifest.conditionId !== requestContext.conditionId ||
    manifest.requirementId !== requestContext.requirementId ||
    manifest.statementId !== requestContext.statementId ||
    manifest.statementEvaluationProfileRef !==
      requestContext.statementEvaluationProfileRef ||
    manifest.evaluationContextHash !== requestContext.evaluationContextHash ||
    manifest.relyingScopeRef !== expectedScopeId
  ) {
    return { ok: false, reason: "authorized_input_manifest_mismatch" };
  }
  return { ok: true };
}

function validateManifestSpendInput(input) {
  return (
    isExactRecord(input, SPEND_INPUT_KEYS) &&
    isIdentifier(input.issuerId) &&
    isIdentifier(input.spendId) &&
    isSha256Id(input.spendStreamNamespaceRef) &&
    isSha256Id(input.spendTokenHash) &&
    typeof input.canonicalHeadEventHash === "string" &&
    RAW_SHA256_RE.test(input.canonicalHeadEventHash) &&
    isSha256Id(input.headSnapshotRef) &&
    isSha256Id(input.headInclusionProofRef)
  );
}

function validateChallengeBinding({
  challenge,
  manifestInput,
  requestContextHash,
  expectedScopeId,
  expectedVerifierId
}) {
  if (!isRecord(challenge)) {
    return { ok: false, reason: "malformed_holder_challenge" };
  }
  if (
    challenge.spendTokenHash !== manifestInput.spendTokenHash ||
    challenge.scopeId !== expectedScopeId ||
    challenge.requestContextHash !== requestContextHash ||
    challenge.purpose !== HOLDER_PURPOSE ||
    challenge.verifierId !== expectedVerifierId
  ) {
    return { ok: false, reason: "holder_context_mismatch" };
  }
  return { ok: true };
}

function partialFailureFields(consumedChallengeIds, extra) {
  const consumed = [...consumedChallengeIds];
  return {
    ...extra,
    consumedChallengeIds: consumed,
    partialConsumption: consumed.length > 0,
    ...(consumed.length > 0
      ? { retryRule: "NEW_HOLDER_CHALLENGES_REQUIRED" }
      : {})
  };
}

function hashCanonical(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("hex")}`;
}

function defaultGenerateGrantId() {
  return `proof-grant-${randomBytes(16).toString("hex")}`;
}

function hasCanonicalDuplicates(values) {
  try {
    const canonicalValues = values.map((value) => canonicalize(value));
    return new Set(canonicalValues).size !== canonicalValues.length;
  } catch {
    return true;
  }
}

function hasDuplicateField(values, field) {
  return new Set(values.map((value) => value[field])).size !== values.length;
}

function normalizeSha256Id(value) {
  if (typeof value !== "string") return null;
  if (RAW_SHA256_RE.test(value)) return `sha256:${value}`;
  return SHA256_ID_RE.test(value) ? value : null;
}

function isGrantAuthorizationStore(value) {
  return isRecord(value) && typeof value.authorize === "function";
}

function isGrantClaimStore(value) {
  return isRecord(value) && typeof value.claim === "function";
}

function isHeadStore(value) {
  return isRecord(value) && typeof value.isAccepted === "function";
}

function isChallengeStore(value) {
  return (
    isRecord(value) &&
    typeof value.isOutstanding === "function" &&
    typeof value.consume === "function"
  );
}

function isExactRecord(value, keys) {
  return (
    isRecord(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isIdentifier(value) {
  return typeof value === "string" && IDENTIFIER_RE.test(value);
}

function isSha256Id(value) {
  return typeof value === "string" && SHA256_ID_RE.test(value);
}

function isTimestamp(value) {
  return parseTimestamp(value) !== null;
}

function parseTimestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP_RE.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
    ? parsed
    : null;
}

function parseTime(value) {
  if (value instanceof Date) {
    const parsed = value.getTime();
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }
  return parseTimestamp(value);
}

function rejected(reason, extra = {}) {
  return { ok: false, reason, ...extra };
}
