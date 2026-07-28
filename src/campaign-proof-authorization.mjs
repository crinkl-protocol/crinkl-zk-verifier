import { createHash } from "node:crypto";

import { canonicalize } from "./spend-token-admission.mjs";

const REQUEST_CONTEXT_DOMAIN =
  "crinkl:campaign:holder-proof-authorization-request-context:v1";
const INPUT_MANIFEST_DOMAIN =
  "crinkl:buyer-state:statement-evaluation-input-manifest:v1";
const PROTOCOL_VERSION = "1.0.0-rc.1";
const HOLDER_PURPOSE = "CAMPAIGN_PROOF_AUTHORIZATION";
const SHA256_ID_RE = /^sha256:[0-9a-f]{64}$/;
const RAW_SHA256_RE = /^[0-9a-f]{64}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const TIMESTAMP_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const PACKAGE_KEYS = Object.freeze([
  "schemaVersion",
  "requestContext",
  "spendToken",
  "holderChallenge",
  "holderProof",
  "atomicProof"
]);
const REQUEST_CONTEXT_KEYS = Object.freeze([
  "domain",
  "schemaVersion",
  "protocolVersion",
  "campaignId",
  "campaignEpochRef",
  "campaignPolicyPackageRef",
  "conditionId",
  "requirementId",
  "evaluationContextHash",
  "statementId",
  "statementEvaluationProfileRef",
  "proofProfile",
  "inputManifestRef",
  "recipientDisclosurePolicyRef",
  "authorizationExpiresAt"
]);
const PROOF_PROFILE_KEYS = Object.freeze([
  "proofSystem",
  "circuitId",
  "verifyingKeyId"
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

export function hashCampaignHolderProofAuthorizationRequestContextV1(
  requestContext
) {
  const shape = validateRequestContext(requestContext);
  if (!shape.ok) {
    throw new TypeError(shape.reason);
  }
  return hashCanonical(requestContext);
}

export function createCampaignProofAuthorizationVerifier({
  verifyAtomicProof,
  verifyHolderControl
}) {
  if (
    typeof verifyAtomicProof !== "function" ||
    typeof verifyHolderControl !== "function"
  ) {
    throw new TypeError("campaign verifier dependencies are required");
  }

  return async function verifyCampaignProofAuthorizationV1(input = {}) {
    if (!isRecord(input) || !isExactRecord(input.package, PACKAGE_KEYS)) {
      return rejected("malformed_campaign_authorization_package");
    }

    const {
      package: authorizationPackage,
      expectedRequestContext,
      expectedScopeId,
      expectedVerifierId,
      authorizedInputManifest,
      proofArtifactManifest,
      hashStatement,
      backend,
      issuerRegistry,
      headStore,
      challengeStore,
      campaignNullifierStore,
      supportedProtocolVersions = [PROTOCOL_VERSION],
      now = new Date()
    } = input;

    if (
      authorizationPackage.schemaVersion !== 1 ||
      !isSha256Id(expectedScopeId) ||
      !isIdentifier(expectedVerifierId)
    ) {
      return rejected("malformed_campaign_authorization_package");
    }

    const actualContextCheck = validateRequestContext(
      authorizationPackage.requestContext
    );
    const expectedContextCheck = validateRequestContext(expectedRequestContext);
    if (!actualContextCheck.ok || !expectedContextCheck.ok) {
      return rejected("malformed_campaign_request_context");
    }

    let requestContextHash;
    try {
      const actualCanonical = canonicalize(
        authorizationPackage.requestContext
      );
      const expectedCanonical = canonicalize(expectedRequestContext);
      if (actualCanonical !== expectedCanonical) {
        return rejected("campaign_request_context_mismatch", {
          requestContextChecked: true
        });
      }
      requestContextHash = hashCanonical(expectedRequestContext);
    } catch {
      return rejected("malformed_campaign_request_context");
    }

    const verificationTime = parseTime(now);
    const authorizationExpiresAt = parseTimestamp(
      expectedRequestContext.authorizationExpiresAt
    );
    if (verificationTime === null || authorizationExpiresAt === null) {
      return rejected("malformed_campaign_request_context");
    }
    if (verificationTime >= authorizationExpiresAt) {
      return rejected("campaign_proof_authorization_expired", {
        requestContextHash,
        requestContextChecked: true
      });
    }

    const proof = authorizationPackage.atomicProof;
    const challenge = authorizationPackage.holderChallenge;
    if (!isRecord(proof) || !isRecord(challenge)) {
      return rejected("malformed_campaign_authorization_package", {
        requestContextHash,
        requestContextChecked: true
      });
    }

    if (
      expectedRequestContext.proofProfile.proofSystem !== proof.proofSystem ||
      expectedRequestContext.proofProfile.circuitId !== proof.circuitId ||
      expectedRequestContext.proofProfile.verifyingKeyId !==
        proof.verifyingKeyId ||
      expectedRequestContext.statementId !== proof.statementId ||
      expectedRequestContext.protocolVersion !== proof.protocolVersion ||
      proof.scopeId !== expectedScopeId ||
      challenge.scopeId !== expectedScopeId ||
      challenge.requestContextHash !== requestContextHash ||
      challenge.purpose !== HOLDER_PURPOSE ||
      challenge.verifierId !== expectedVerifierId ||
      challenge.spendTokenHash !== proof.spendTokenHash
    ) {
      return rejected("campaign_request_context_mismatch", {
        requestContextHash,
        requestContextChecked: true
      });
    }

    const manifestCheck = verifyAuthorizedInputManifest({
      manifest: authorizedInputManifest,
      expectedRequestContext,
      expectedScopeId,
      spendToken: authorizationPackage.spendToken,
      proof
    });
    if (!manifestCheck.ok) {
      return rejected(manifestCheck.reason, {
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
    if (!isCampaignNullifierStore(campaignNullifierStore)) {
      return rejected("nullifier_replay_store_required", {
        requestContextHash,
        requestContextChecked: true,
        inputManifestChecked: true
      });
    }

    let atomicProofResult;
    try {
      atomicProofResult = await verifyAtomicProof({
        proof,
        spendToken: authorizationPackage.spendToken,
        manifest: proofArtifactManifest,
        hashStatement,
        backend,
        seenNullifiers: campaignNullifierStore,
        verificationPolicy: {
          spendTokenAdmission: "required",
          headAcceptance: "required",
          nullifierReplay: "optional"
        },
        issuerRegistry,
        headStore
      });
    } catch {
      atomicProofResult = {
        ok: false,
        reason: "campaign_proof_verifier_failed"
      };
    }
    if (!isRecord(atomicProofResult) || atomicProofResult.ok !== true) {
      return rejected(
        isRecord(atomicProofResult) && isNonEmptyString(atomicProofResult.reason)
          ? atomicProofResult.reason
          : "cryptographic_verification_failed",
        {
          requestContextHash,
          requestContextChecked: true,
          inputManifestChecked: true,
          atomicProofChecked: true,
          holderChallengeConsumed: false,
          campaignNullifierConsumed: false,
          partialConsumption: false
        }
      );
    }

    let holderResult;
    try {
      holderResult = await verifyHolderControl({
        token: authorizationPackage.spendToken,
        issuerRegistry,
        supportedProtocolVersions,
        challenge,
        holderProof: authorizationPackage.holderProof,
        expectedContext: {
          spendTokenHash: proof.spendTokenHash,
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
      return rejected(
        isRecord(holderResult) && isNonEmptyString(holderResult.reason)
          ? holderResult.reason
          : "holder_signature_invalid",
        {
          requestContextHash,
          requestContextChecked: true,
          inputManifestChecked: true,
          atomicProofChecked: true,
          holderControlChecked: true,
          holderChallengeConsumed:
            isRecord(holderResult) &&
            holderResult.challengeConsumed === true,
          campaignNullifierConsumed: false,
          partialConsumption:
            isRecord(holderResult) &&
            holderResult.challengeConsumed === true
        }
      );
    }

    let nullifierConsumed = false;
    try {
      nullifierConsumed =
        (await campaignNullifierStore.consume(
          proof.scopeId,
          proof.nullifier
        )) === true;
    } catch {
      nullifierConsumed = false;
    }
    if (!nullifierConsumed) {
      return rejected("campaign_nullifier_consumption_failed", {
        requestContextHash,
        requestContextChecked: true,
        inputManifestChecked: true,
        atomicProofChecked: true,
        holderControlChecked: true,
        holderChallengeConsumed: true,
        campaignNullifierChecked: true,
        campaignNullifierConsumed: false,
        partialConsumption: true,
        retryRule: "NEW_HOLDER_CHALLENGE_REQUIRED"
      });
    }

    return {
      ok: true,
      reason: "campaign_proof_authorization_verified",
      requestContextHash,
      campaignId: expectedRequestContext.campaignId,
      campaignEpochRef: expectedRequestContext.campaignEpochRef,
      statementId: proof.statementId,
      scopeId: proof.scopeId,
      nullifier: proof.nullifier,
      spendTokenHash: proof.spendTokenHash,
      requestContextChecked: true,
      inputManifestChecked: true,
      atomicProofChecked: true,
      holderControlChecked: true,
      holderChallengeConsumed: true,
      campaignNullifierChecked: true,
      campaignNullifierConsumed: true,
      partialConsumption: false
    };
  };
}

function validateRequestContext(value) {
  if (
    !isExactRecord(value, REQUEST_CONTEXT_KEYS) ||
    !isExactRecord(value.proofProfile, PROOF_PROFILE_KEYS) ||
    value.domain !== REQUEST_CONTEXT_DOMAIN ||
    value.schemaVersion !== 1 ||
    value.protocolVersion !== PROTOCOL_VERSION ||
    !isIdentifier(value.campaignId) ||
    !isIdentifier(value.requirementId) ||
    !isIdentifier(value.proofProfile.proofSystem) ||
    !isIdentifier(value.proofProfile.circuitId) ||
    !isTimestamp(value.authorizationExpiresAt)
  ) {
    return { ok: false, reason: "malformed_campaign_request_context" };
  }

  for (const field of [
    "campaignEpochRef",
    "campaignPolicyPackageRef",
    "conditionId",
    "evaluationContextHash",
    "statementId",
    "statementEvaluationProfileRef",
    "inputManifestRef",
    "recipientDisclosurePolicyRef"
  ]) {
    if (!isSha256Id(value[field])) {
      return { ok: false, reason: "malformed_campaign_request_context" };
    }
  }
  if (!isSha256Id(value.proofProfile.verifyingKeyId)) {
    return { ok: false, reason: "malformed_campaign_request_context" };
  }
  return { ok: true };
}

function verifyAuthorizedInputManifest({
  manifest,
  expectedRequestContext,
  expectedScopeId,
  spendToken,
  proof
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
    manifest.acceptedSpendInputs.length !== 1 ||
    !Array.isArray(manifest.sourceBindings) ||
    manifest.sourceBindings.length === 0 ||
    !Array.isArray(manifest.sourceSelectionBindings) ||
    !manifest.sourceBindings.every(
      (binding) =>
        isExactRecord(binding, SOURCE_BINDING_KEYS) &&
        isIdentifier(binding.sourceProfile) &&
        isSha256Id(binding.sourceRef)
    ) ||
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
    inputManifestRef !== expectedRequestContext.inputManifestRef ||
    manifest.conditionId !== expectedRequestContext.conditionId ||
    manifest.requirementId !== expectedRequestContext.requirementId ||
    manifest.statementId !== expectedRequestContext.statementId ||
    manifest.statementEvaluationProfileRef !==
      expectedRequestContext.statementEvaluationProfileRef ||
    manifest.evaluationContextHash !==
      expectedRequestContext.evaluationContextHash ||
    manifest.relyingScopeRef !== expectedScopeId
  ) {
    return { ok: false, reason: "authorized_input_manifest_mismatch" };
  }

  const acceptedSpend = manifest.acceptedSpendInputs[0];
  if (
    !isExactRecord(acceptedSpend, SPEND_INPUT_KEYS) ||
    !isIdentifier(acceptedSpend.issuerId) ||
    !isIdentifier(acceptedSpend.spendId) ||
    !isSha256Id(acceptedSpend.spendStreamNamespaceRef) ||
    !isSha256Id(acceptedSpend.spendTokenHash) ||
    !isRawSha256(acceptedSpend.canonicalHeadEventHash) ||
    !isSha256Id(acceptedSpend.headSnapshotRef) ||
    !isSha256Id(acceptedSpend.headInclusionProofRef) ||
    !isRecord(spendToken) ||
    acceptedSpend.spendId !== proof.spendId ||
    acceptedSpend.spendId !== spendToken.spendId ||
    acceptedSpend.issuerId !== spendToken.signatures?.issuedBy ||
    acceptedSpend.spendTokenHash !== proof.spendTokenHash ||
    acceptedSpend.canonicalHeadEventHash !==
      normalizeRawSha256(proof.binding?.headEventHash)
  ) {
    return { ok: false, reason: "authorized_spend_input_mismatch" };
  }
  return { ok: true };
}

function hashCanonical(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("hex")}`;
}

function hasCanonicalDuplicates(values) {
  try {
    const canonicalValues = values.map((value) => canonicalize(value));
    return new Set(canonicalValues).size !== canonicalValues.length;
  } catch {
    return true;
  }
}

function normalizeRawSha256(value) {
  if (typeof value !== "string") return null;
  if (RAW_SHA256_RE.test(value)) return value;
  return SHA256_ID_RE.test(value) ? value.slice("sha256:".length) : null;
}

function isCampaignNullifierStore(value) {
  return (
    isRecord(value) &&
    typeof value.has === "function" &&
    typeof value.consume === "function"
  );
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

function isRawSha256(value) {
  return typeof value === "string" && RAW_SHA256_RE.test(value);
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
