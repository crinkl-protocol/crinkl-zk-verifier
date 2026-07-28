import { createHash } from "node:crypto";

import { hashCampaignProofJobAuthorizationGrantV1 } from "./campaign-proof-job-authorization.mjs";
import { canonicalize } from "./spend-token-admission.mjs";

const COMPLETION_DOMAIN =
  "crinkl:campaign:server-proved-completion-package:v1";
const PROTOCOL_VERSION = "1.0.0-rc.1";
const SHA256_ID_RE = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const TIMESTAMP_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PACKAGE_KEYS = Object.freeze([
  "domain",
  "schemaVersion",
  "protocolVersion",
  "grantRef",
  "proofArtifactRef",
  "proverId",
  "completedAt"
]);

export function hashCampaignServerProvedCompletionPackageV1(
  completionPackage
) {
  if (!validatePackage(completionPackage)) {
    throw new TypeError("completion_package_shape_invalid");
  }
  return hashCanonical(completionPackage);
}

export function createCampaignServerProvedCompletionVerifier({
  verifyProof
} = {}) {
  if (typeof verifyProof !== "function") {
    throw new TypeError("server completion verifier dependency is required");
  }

  return async function verifyCampaignServerProvedCompletionV1(input = {}) {
    const {
      package: completionPackage,
      expectedCompletionRef,
      grant,
      proofArtifact,
      spendTokens,
      proofArtifactManifest,
      hashStatement,
      backend,
      issuerRegistry,
      headStore,
      proverRegistry,
      grantLifecycleStore,
      campaignNullifierStore
    } = input;

    if (!validatePackage(completionPackage)) {
      return rejected("completion_package_shape_invalid");
    }
    if (!isSha256Id(expectedCompletionRef)) {
      return rejected("completion_ref_invalid");
    }

    let completionRef;
    try {
      completionRef = hashCampaignServerProvedCompletionPackageV1(
        completionPackage
      );
    } catch {
      return rejected("completion_package_shape_invalid");
    }
    if (completionRef !== expectedCompletionRef) {
      return rejected("completion_ref_mismatch", { completionRef });
    }

    let grantRef;
    try {
      grantRef = hashCampaignProofJobAuthorizationGrantV1(grant);
    } catch {
      return rejected("grant_shape_invalid", { completionRef });
    }
    if (grantRef !== completionPackage.grantRef) {
      return rejected("grant_ref_mismatch", { completionRef, grantRef });
    }
    if (!isGrantLifecycleStore(grantLifecycleStore)) {
      return rejected("proof_job_lifecycle_store_required", {
        completionRef,
        grantRef
      });
    }

    let lifecycle;
    try {
      lifecycle = await grantLifecycleStore.get({ grantRef });
    } catch {
      lifecycle = null;
    }
    if (!isClaimedLifecycle(lifecycle)) {
      return rejected("proof_job_authorization_not_claimed", {
        completionRef,
        grantRef
      });
    }
    if (lifecycle.claimedBy !== completionPackage.proverId) {
      return rejected("proof_job_claimed_by_other_prover", {
        completionRef,
        grantRef
      });
    }
    if (!isProverRegistry(proverRegistry)) {
      return rejected("prover_registry_required", {
        completionRef,
        grantRef
      });
    }
    let proverAuthorized = false;
    try {
      proverAuthorized =
        (await proverRegistry.isAuthorized({
          proverId: completionPackage.proverId,
          grantRef,
          claimedAt: lifecycle.claimedAt,
          completedAt: completionPackage.completedAt
        })) === true;
    } catch {
      proverAuthorized = false;
    }
    if (!proverAuthorized) {
      return rejected("prover_not_authorized", {
        completionRef,
        grantRef
      });
    }

    const claimedAt = parseTimestamp(lifecycle.claimedAt);
    const completedAt = parseTimestamp(completionPackage.completedAt);
    const expiresAt = parseTimestamp(grant.expiresAt);
    if (
      claimedAt === null ||
      completedAt === null ||
      expiresAt === null ||
      completedAt < claimedAt ||
      completedAt >= expiresAt
    ) {
      return rejected("proof_job_authorization_expired", {
        completionRef,
        grantRef
      });
    }

    let proofArtifactRef;
    try {
      proofArtifactRef = hashCanonical(proofArtifact);
    } catch {
      return await failClaimedGrant({
        reason: "proof_artifact_shape_invalid",
        completionRef,
        grantRef,
        grantLifecycleStore
      });
    }
    if (proofArtifactRef !== completionPackage.proofArtifactRef) {
      return await failClaimedGrant({
        reason: "proof_artifact_ref_mismatch",
        completionRef,
        grantRef,
        grantLifecycleStore
      });
    }

    const lineage = validateProofLineage({
      grant,
      completionPackage,
      proofArtifact,
      lifecycle,
      spendTokens
    });
    if (!lineage.ok) {
      return await failClaimedGrant({
        reason: lineage.reason,
        completionRef,
        grantRef,
        grantLifecycleStore
      });
    }
    if (!isCampaignNullifierStore(campaignNullifierStore)) {
      return await failClaimedGrant({
        reason: "nullifier_replay_store_required",
        completionRef,
        grantRef,
        grantLifecycleStore
      });
    }

    let proofResult;
    try {
      proofResult = await verifyProof({
        proof: proofArtifact,
        spendToken: spendTokens[0],
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
      proofResult = {
        ok: false,
        reason: "campaign_proof_verifier_failed"
      };
    }
    if (!isRecord(proofResult) || proofResult.ok !== true) {
      return await failClaimedGrant({
        reason:
          isRecord(proofResult) && isNonEmptyString(proofResult.reason)
            ? proofResult.reason
            : "cryptographic_verification_failed",
        completionRef,
        grantRef,
        grantLifecycleStore,
        extra: {
          proofChecked: true,
          campaignNullifierConsumed: false
        }
      });
    }

    let nullifierConsumed = false;
    try {
      nullifierConsumed =
        (await campaignNullifierStore.consume(
          proofArtifact.scopeId,
          proofArtifact.nullifier
        )) === true;
    } catch {
      nullifierConsumed = false;
    }
    if (!nullifierConsumed) {
      return await failClaimedGrant({
        reason: "campaign_nullifier_consumption_failed",
        completionRef,
        grantRef,
        grantLifecycleStore,
        extra: {
          proofChecked: true,
          campaignNullifierChecked: true,
          campaignNullifierConsumed: false,
          partialConsumption: true
        }
      });
    }

    let completed = false;
    try {
      completed =
        (await grantLifecycleStore.transition({
          grantRef,
          expectedState: "CLAIMED",
          nextState: "COMPLETED",
          reason: "CAMPAIGN_SERVER_PROVED_COMPLETION_VERIFIED"
        })) === true;
    } catch {
      completed = false;
    }
    if (!completed) {
      return rejected("campaign_completion_terminalization_failed", {
        completionRef,
        grantRef,
        proofChecked: true,
        campaignNullifierChecked: true,
        campaignNullifierConsumed: true,
        grantLifecycleState: "CLAIMED",
        holderChallengeOperations: 0,
        partialConsumption: true,
        reconciliationRequired: true
      });
    }

    return {
      ok: true,
      reason: "campaign_server_proved_completion_verified",
      completionRef,
      grantRef,
      proofArtifactRef,
      campaignId: grant.campaignId,
      statementId: grant.statementId,
      scopeId: grant.scopeId,
      nullifier: proofArtifact.nullifier,
      proofChecked: true,
      campaignNullifierChecked: true,
      campaignNullifierConsumed: true,
      grantLifecycleState: "COMPLETED",
      holderChallengeOperations: 0,
      partialConsumption: false
    };
  };
}

function validatePackage(value) {
  return (
    isExactRecord(value, PACKAGE_KEYS) &&
    value.domain === COMPLETION_DOMAIN &&
    value.schemaVersion === 1 &&
    value.protocolVersion === PROTOCOL_VERSION &&
    isSha256Id(value.grantRef) &&
    isSha256Id(value.proofArtifactRef) &&
    isIdentifier(value.proverId) &&
    parseTimestamp(value.completedAt) !== null
  );
}

function validateProofLineage({
  grant,
  completionPackage,
  proofArtifact,
  lifecycle,
  spendTokens
}) {
  if (
    !isRecord(proofArtifact) ||
    !isRecord(proofArtifact.binding) ||
    !isRecord(proofArtifact.publicInputs) ||
    !Array.isArray(grant.authorizedSpendInputs) ||
    grant.authorizedSpendInputs.length !== 1 ||
    !Array.isArray(spendTokens) ||
    spendTokens.length !== 1 ||
    !isRecord(spendTokens[0])
  ) {
    return { ok: false, reason: "proof_job_lineage_mismatch" };
  }
  const input = grant.authorizedSpendInputs[0];
  if (
    proofArtifact.protocolVersion !== grant.protocolVersion ||
    proofArtifact.issuedBy !== completionPackage.proverId ||
    proofArtifact.proofSystem !== grant.proofProfile?.proofSystem ||
    proofArtifact.circuitId !== grant.proofProfile?.circuitId ||
    proofArtifact.verifyingKeyId !== grant.proofProfile?.verifyingKeyId ||
    proofArtifact.statementId !== grant.statementId ||
    proofArtifact.scopeId !== grant.scopeId ||
    proofArtifact.publicInputs.scopeId !== proofArtifact.scopeId ||
    proofArtifact.publicInputs.statementId !== proofArtifact.statementId ||
    !isSha256Id(proofArtifact.nullifier) ||
    proofArtifact.publicInputs.nullifier !== proofArtifact.nullifier ||
    proofArtifact.spendId !== input.spendId ||
    proofArtifact.spendTokenHash !== input.spendTokenHash ||
    proofArtifact.publicInputs.spendTokenHash !== input.spendTokenHash ||
    normalizeSha256Id(proofArtifact.binding.headEventHash) !==
      input.canonicalHeadEventHash ||
    normalizeSha256Id(proofArtifact.publicInputs.headEventHash) !==
      input.canonicalHeadEventHash
  ) {
    return { ok: false, reason: "proof_job_lineage_mismatch" };
  }

  const proofCreatedAt = parseTimestamp(proofArtifact.createdAt);
  const claimedAt = parseTimestamp(lifecycle.claimedAt);
  const completedAt = parseTimestamp(completionPackage.completedAt);
  if (
    proofCreatedAt === null ||
    claimedAt === null ||
    completedAt === null ||
    proofCreatedAt < claimedAt ||
    proofCreatedAt > completedAt
  ) {
    return { ok: false, reason: "proof_job_time_mismatch" };
  }
  return { ok: true };
}

async function failClaimedGrant({
  reason,
  completionRef,
  grantRef,
  grantLifecycleStore,
  extra = {}
}) {
  let failed = false;
  try {
    failed =
      (await grantLifecycleStore.transition({
        grantRef,
        expectedState: "CLAIMED",
        nextState: "FAILED",
        reason
      })) === true;
  } catch {
    failed = false;
  }
  if (!failed) {
    return rejected("proof_job_failure_terminalization_failed", {
      completionRef,
      grantRef,
      failedReason: reason,
      grantLifecycleState: "CLAIMED",
      holderChallengeOperations: 0,
      reconciliationRequired: true,
      ...extra
    });
  }
  return rejected(reason, {
    completionRef,
    grantRef,
    grantLifecycleState: "FAILED",
    holderChallengeOperations: 0,
    ...extra
  });
}

function isClaimedLifecycle(value) {
  return (
    isRecord(value) &&
    value.state === "CLAIMED" &&
    isIdentifier(value.claimedBy) &&
    parseTimestamp(value.claimedAt) !== null
  );
}

function isGrantLifecycleStore(value) {
  return (
    isRecord(value) &&
    typeof value.get === "function" &&
    typeof value.transition === "function"
  );
}

function isCampaignNullifierStore(value) {
  return (
    isRecord(value) &&
    typeof value.has === "function" &&
    typeof value.consume === "function"
  );
}

function isProverRegistry(value) {
  return isRecord(value) && typeof value.isAuthorized === "function";
}

function hashCanonical(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("hex")}`;
}

function normalizeSha256Id(value) {
  if (typeof value !== "string") return null;
  if (/^[0-9a-f]{64}$/u.test(value)) return `sha256:${value}`;
  return isSha256Id(value) ? value : null;
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

function parseTimestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP_RE.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
    ? parsed
    : null;
}

function rejected(reason, extra = {}) {
  return { ok: false, reason, ...extra };
}
