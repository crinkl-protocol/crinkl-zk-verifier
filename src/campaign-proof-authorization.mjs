import { createHash } from "node:crypto";

import { canonicalize } from "./spend-token-admission.mjs";

const REQUEST_CONTEXT_V1_DOMAIN =
  "crinkl:campaign:holder-proof-authorization-request-context:v1";
const REQUEST_CONTEXT_V2_DOMAIN =
  "crinkl:campaign:holder-proof-authorization-request-context:v2";
const INPUT_MANIFEST_V1_DOMAIN =
  "crinkl:buyer-state:statement-evaluation-input-manifest:v1";
const INPUT_MANIFEST_V2_DOMAIN =
  "crinkl:buyer-state:statement-evaluation-input-manifest:v2";
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
const REQUEST_CONTEXT_V1_KEYS = Object.freeze([
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
const REQUEST_CONTEXT_V2_KEYS = Object.freeze([
  "domain",
  "schemaVersion",
  "protocolVersion",
  "campaignId",
  "campaignEpochRef",
  "campaignPolicyPackageRef",
  "conditionId",
  "conditionRequirementIds",
  "sourceStatementIds",
  "compiledStatementId",
  "statementEvaluationProfileRef",
  "proofProfileBindingRef",
  "evaluationContextHash",
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
const INPUT_MANIFEST_V1_KEYS = Object.freeze([
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
const INPUT_MANIFEST_V2_KEYS = Object.freeze([
  "domain",
  "schemaVersion",
  "protocolVersion",
  "conditionId",
  "conditionRequirementIds",
  "sourceStatementIds",
  "compiledStatementId",
  "statementEvaluationProfileRef",
  "proofProfileBindingRef",
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
const V2_SOURCE_PROFILES = new Set([
  "CATEGORY_TAXONOMY_REGISTRY_V1",
  "DECLARED_ENTITY_SET_REGISTRY_V1",
  "EVIDENCE_COMPLETENESS_OR_NON_MEMBERSHIP_SOURCE",
  "MARKET_REGISTRY_V1",
  "MERCHANT_IDENTITY_REGISTRY_V1",
  "POSITIVE_CAMPAIGN_PROVENANCE_SOURCES_V1",
  "PRIVATE_PURCHASE_GROUPING_SOURCES_V1",
  "PRODUCT_CATALOG_REGISTRY_V1",
  "PURCHASE_LEVEL_PRODUCT_IDENTITY_SOURCE",
  "SCOPED_SUBJECT_BINDING_SOURCES_V1",
  "SPEND_ISSUER_AND_CANONICAL_HEAD_SOURCES_V1"
]);

export function hashCampaignHolderProofAuthorizationRequestContextV1(
  requestContext
) {
  const shape = validateRequestContext(requestContext);
  if (!shape.ok || shape.version !== 1) {
    throw new TypeError(
      shape.reason ?? "campaign request context version mismatch"
    );
  }
  return hashCanonical(requestContext);
}

export function hashCampaignHolderProofAuthorizationRequestContextV2(
  requestContext
) {
  const shape = validateRequestContext(requestContext);
  if (!shape.ok || shape.version !== 2) {
    throw new TypeError(
      shape.reason ?? "campaign request context version mismatch"
    );
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
      expectedContextCheck.statementId !== proof.statementId ||
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
  if (!isRecord(value)) {
    return { ok: false, reason: "malformed_campaign_request_context" };
  }
  if (value.schemaVersion === 1) {
    return validateRequestContextV1(value);
  }
  if (value.schemaVersion === 2) {
    return validateRequestContextV2(value);
  }
  return { ok: false, reason: "malformed_campaign_request_context" };
}

function validateRequestContextV1(value) {
  if (
    !isExactRecord(value, REQUEST_CONTEXT_V1_KEYS) ||
    !isExactRecord(value.proofProfile, PROOF_PROFILE_KEYS) ||
    value.domain !== REQUEST_CONTEXT_V1_DOMAIN ||
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
  return { ok: true, version: 1, statementId: value.statementId };
}

function validateRequestContextV2(value) {
  if (
    !isExactRecord(value, REQUEST_CONTEXT_V2_KEYS) ||
    !isExactRecord(value.proofProfile, PROOF_PROFILE_KEYS) ||
    value.domain !== REQUEST_CONTEXT_V2_DOMAIN ||
    value.schemaVersion !== 2 ||
    value.protocolVersion !== PROTOCOL_VERSION ||
    !isIdentifier(value.campaignId) ||
    !isSortedUniqueIdentifiers(value.conditionRequirementIds, 2) ||
    !isSortedUniqueSha256Ids(value.sourceStatementIds, 1) ||
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
    "compiledStatementId",
    "statementEvaluationProfileRef",
    "proofProfileBindingRef",
    "evaluationContextHash",
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
  return {
    ok: true,
    version: 2,
    statementId: value.compiledStatementId
  };
}

function verifyAuthorizedInputManifest({
  manifest,
  expectedRequestContext,
  expectedScopeId,
  spendToken,
  proof
}) {
  const contextShape = validateRequestContext(expectedRequestContext);
  if (
    !contextShape.ok ||
    !validateInputManifestShape(manifest, contextShape.version, {
      acceptedSpendCount: 1
    })
  ) {
    return { ok: false, reason: "malformed_authorized_input_manifest" };
  }

  let inputManifestRef;
  try {
    inputManifestRef = hashCanonical(manifest);
  } catch {
    return { ok: false, reason: "malformed_authorized_input_manifest" };
  }
  const lineageMatches =
    contextShape.version === 1
      ? manifest.requirementId === expectedRequestContext.requirementId &&
        manifest.statementId === expectedRequestContext.statementId
      : arraysEqual(
          manifest.conditionRequirementIds,
          expectedRequestContext.conditionRequirementIds
        ) &&
        arraysEqual(
          manifest.sourceStatementIds,
          expectedRequestContext.sourceStatementIds
        ) &&
        manifest.compiledStatementId ===
          expectedRequestContext.compiledStatementId &&
        manifest.proofProfileBindingRef ===
          expectedRequestContext.proofProfileBindingRef;
  if (
    inputManifestRef !== expectedRequestContext.inputManifestRef ||
    manifest.conditionId !== expectedRequestContext.conditionId ||
    !lineageMatches ||
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

function validateInputManifestShape(
  manifest,
  version,
  { acceptedSpendCount }
) {
  const keys =
    version === 1 ? INPUT_MANIFEST_V1_KEYS : INPUT_MANIFEST_V2_KEYS;
  const domain =
    version === 1 ? INPUT_MANIFEST_V1_DOMAIN : INPUT_MANIFEST_V2_DOMAIN;
  if (
    !isExactRecord(manifest, keys) ||
    manifest.domain !== domain ||
    manifest.schemaVersion !== version ||
    manifest.protocolVersion !== PROTOCOL_VERSION ||
    manifest.inputDisclosure !==
      "NON_PORTABLE_AUTHORIZED_EVALUATION_BOUNDARY_ONLY" ||
    manifest.stableSubjectFields !== "PROHIBITED" ||
    !isTimestamp(manifest.evaluationCutoff) ||
    !isSha256Id(manifest.relyingScopeRef) ||
    !Array.isArray(manifest.acceptedSpendInputs) ||
    manifest.acceptedSpendInputs.length !== acceptedSpendCount ||
    !Array.isArray(manifest.sourceBindings) ||
    manifest.sourceBindings.length === 0 ||
    !Array.isArray(manifest.sourceSelectionBindings) ||
    !manifest.sourceBindings.every(
      (binding) =>
        isExactRecord(binding, SOURCE_BINDING_KEYS) &&
        isAcceptedSourceProfile(binding.sourceProfile, version) &&
        isSha256Id(binding.sourceRef)
    ) ||
    !manifest.sourceSelectionBindings.every(
      (binding) =>
        isExactRecord(binding, SOURCE_SELECTION_KEYS) &&
        isAcceptedSourceProfile(binding.sourceProfile, version) &&
        isSha256Id(binding.requestRef) &&
        isSha256Id(binding.checkpointRef) &&
        isSha256Id(binding.selectionRef)
    ) ||
    hasCanonicalDuplicates(manifest.sourceBindings) ||
    hasCanonicalDuplicates(manifest.sourceSelectionBindings)
  ) {
    return false;
  }
  if (version === 1) {
    return (
      isSha256Id(manifest.conditionId) &&
      isIdentifier(manifest.requirementId) &&
      isSha256Id(manifest.statementId) &&
      isSha256Id(manifest.statementEvaluationProfileRef) &&
      isSha256Id(manifest.evaluationContextHash)
    );
  }
  return (
    isSha256Id(manifest.conditionId) &&
    isSortedUniqueIdentifiers(manifest.conditionRequirementIds, 2) &&
    isSortedUniqueSha256Ids(manifest.sourceStatementIds, 1) &&
    isSha256Id(manifest.compiledStatementId) &&
    isSha256Id(manifest.statementEvaluationProfileRef) &&
    isSha256Id(manifest.proofProfileBindingRef) &&
    isSha256Id(manifest.evaluationContextHash)
  );
}

function hashCanonical(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("hex")}`;
}

function arraysEqual(left, right) {
  return (
    Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function isAcceptedSourceProfile(value, version) {
  return (
    isIdentifier(value) &&
    (version === 1 || V2_SOURCE_PROFILES.has(value))
  );
}

function isSortedUniqueIdentifiers(value, minimumLength) {
  return isStrictlySortedUnique(
    value,
    minimumLength,
    (item) => isIdentifier(item)
  );
}

function isSortedUniqueSha256Ids(value, minimumLength) {
  return isStrictlySortedUnique(
    value,
    minimumLength,
    (item) => isSha256Id(item)
  );
}

function isStrictlySortedUnique(value, minimumLength, validateItem) {
  if (!Array.isArray(value) || value.length < minimumLength) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!validateItem(value[index])) return false;
    if (index > 0 && value[index - 1] >= value[index]) return false;
  }
  return true;
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
