import {
  createHash,
  createPublicKey,
  verify as verifySignature
} from "node:crypto";

import {
  canonicalize,
  verifySpendAttestationTokenV2
} from "./spend-token-admission.mjs";

const CHALLENGE_DOMAIN = "crinkl.spend-holder-challenge.v2";
const HOLDER_SCHEME = "crinkl.holder.v2";
const HOLDER_COMMITMENT_DOMAIN = Buffer.from("crinkl.holder.v2:", "utf8");
const MAXIMUM_CHALLENGE_LIFETIME_MS = 300_000;
const SHA256_ID_RE = /^sha256:[0-9a-f]{64}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PURPOSES = new Set([
  "TOKEN_PRESENTATION",
  "CAMPAIGN_PROOF_AUTHORIZATION",
  "CAMPAIGN_ACTION_AUTHORIZATION"
]);
const CHALLENGE_KEYS = Object.freeze([
  "domain",
  "schemaVersion",
  "nonceBase64",
  "spendTokenHash",
  "scopeId",
  "requestContextHash",
  "purpose",
  "verifierId",
  "issuedAt",
  "expiresAt"
]);
const PROOF_KEYS = Object.freeze([
  "schemaVersion",
  "scheme",
  "spendTokenHash",
  "scopeId",
  "challengeId",
  "holderPublicKeyBase64",
  "signatureBase64"
]);
const EXPECTED_CONTEXT_KEYS = Object.freeze([
  "spendTokenHash",
  "scopeId",
  "requestContextHash",
  "purpose",
  "verifierId"
]);

export async function verifySpendHolderControlV2({
  token,
  issuerRegistry,
  supportedProtocolVersions,
  challenge,
  holderProof,
  expectedContext,
  now = new Date(),
  challengeStore
} = {}) {
  const admission = await verifySpendAttestationTokenV2({
    token,
    issuerRegistry,
    supportedProtocolVersions
  });
  if (!admission.ok) {
    return rejected(admission.reason, { tokenAdmissionChecked: true });
  }
  if (!admission.holderBinding) {
    return rejected("holder_control_unavailable", {
      tokenAdmissionChecked: true,
      spendId: admission.spendId,
      spendTokenHash: admission.spendTokenHash
    });
  }

  if (!isExactRecord(challenge, CHALLENGE_KEYS)) {
    return rejected("malformed_holder_challenge", admissionFields(admission));
  }
  if (!isExactRecord(holderProof, PROOF_KEYS)) {
    return rejected("malformed_holder_proof", admissionFields(admission));
  }
  if (!isExactRecord(expectedContext, EXPECTED_CONTEXT_KEYS)) {
    return rejected("malformed_holder_context", admissionFields(admission));
  }

  const issuedAt = parseTimestamp(challenge.issuedAt);
  const expiresAt = parseTimestamp(challenge.expiresAt);
  const verificationTime = parseNow(now);
  if (
    challenge.domain !== CHALLENGE_DOMAIN ||
    challenge.schemaVersion !== 2 ||
    !isCanonicalBase64OfLength(challenge.nonceBase64, 32) ||
    !isSha256Id(challenge.spendTokenHash) ||
    !isSha256Id(challenge.scopeId) ||
    !isSha256Id(challenge.requestContextHash) ||
    !PURPOSES.has(challenge.purpose) ||
    !isNonEmptyString(challenge.verifierId) ||
    issuedAt === null ||
    expiresAt === null ||
    verificationTime === null ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > MAXIMUM_CHALLENGE_LIFETIME_MS
  ) {
    return rejected("malformed_holder_challenge", admissionFields(admission));
  }
  if (
    expectedContext.spendTokenHash !== challenge.spendTokenHash ||
    expectedContext.scopeId !== challenge.scopeId ||
    expectedContext.requestContextHash !== challenge.requestContextHash ||
    expectedContext.purpose !== challenge.purpose ||
    expectedContext.verifierId !== challenge.verifierId ||
    challenge.spendTokenHash !== admission.spendTokenHash
  ) {
    return rejected("holder_context_mismatch", admissionFields(admission));
  }
  if (verificationTime < issuedAt) {
    return rejected("holder_challenge_not_yet_valid", admissionFields(admission));
  }
  if (verificationTime >= expiresAt) {
    return rejected("holder_challenge_expired", admissionFields(admission));
  }

  if (
    holderProof.schemaVersion !== 2 ||
    holderProof.scheme !== HOLDER_SCHEME ||
    !isSha256Id(holderProof.spendTokenHash) ||
    !isSha256Id(holderProof.scopeId) ||
    !isSha256Id(holderProof.challengeId) ||
    !isCanonicalBase64OfLength(holderProof.holderPublicKeyBase64, 32) ||
    !isCanonicalBase64OfLength(holderProof.signatureBase64, 64)
  ) {
    return rejected("malformed_holder_proof", admissionFields(admission));
  }

  let challengeCanonical;
  try {
    challengeCanonical = canonicalize(challenge);
  } catch {
    return rejected("malformed_holder_challenge", admissionFields(admission));
  }
  const challengeDigest = createHash("sha256")
    .update(challengeCanonical, "utf8")
    .digest();
  const challengeId = `sha256:${challengeDigest.toString("hex")}`;
  const challengeKey = {
    verifierId: challenge.verifierId,
    nonceBase64: challenge.nonceBase64
  };

  if (!isChallengeStore(challengeStore)) {
    return rejected("holder_challenge_store_required", {
      ...admissionFields(admission),
      challengeId
    });
  }
  let outstanding = false;
  try {
    outstanding = (await challengeStore.isOutstanding(challengeKey)) === true;
  } catch {
    outstanding = false;
  }
  if (!outstanding) {
    return rejected("holder_challenge_replayed", {
      ...admissionFields(admission),
      challengeId,
      challengeChecked: true
    });
  }

  const holderPublicKeyBytes = Buffer.from(
    holderProof.holderPublicKeyBase64,
    "base64"
  );
  const holderCommitment = `sha256:${createHash("sha256")
    .update(HOLDER_COMMITMENT_DOMAIN)
    .update(admission.spendId, "utf8")
    .update(holderPublicKeyBytes)
    .digest("hex")}`;
  if (holderCommitment !== admission.holderBinding.commitment) {
    return rejected("holder_commitment_mismatch", {
      ...admissionFields(admission),
      challengeId,
      challengeChecked: true
    });
  }
  if (holderProof.challengeId !== challengeId) {
    return rejected("holder_challenge_id_mismatch", {
      ...admissionFields(admission),
      challengeId,
      challengeChecked: true
    });
  }
  if (
    holderProof.spendTokenHash !== challenge.spendTokenHash ||
    holderProof.scopeId !== challenge.scopeId
  ) {
    return rejected("holder_proof_binding_mismatch", {
      ...admissionFields(admission),
      challengeId,
      challengeChecked: true
    });
  }

  let signatureValid = false;
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, holderPublicKeyBytes]),
      format: "der",
      type: "spki"
    });
    signatureValid = verifySignature(
      null,
      challengeDigest,
      publicKey,
      Buffer.from(holderProof.signatureBase64, "base64")
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    return rejected("holder_signature_invalid", {
      ...admissionFields(admission),
      challengeId,
      challengeChecked: true
    });
  }

  let consumed = false;
  try {
    consumed = (await challengeStore.consume(challengeKey)) === true;
  } catch {
    consumed = false;
  }
  if (!consumed) {
    return rejected("holder_challenge_replayed", {
      ...admissionFields(admission),
      challengeId,
      challengeChecked: true,
      challengeConsumed: false
    });
  }

  return {
    ok: true,
    reason: "holder_control_verified",
    ...admissionFields(admission),
    scopeId: challenge.scopeId,
    requestContextHash: challenge.requestContextHash,
    purpose: challenge.purpose,
    verifierId: challenge.verifierId,
    challengeId,
    challengeChecked: true,
    challengeConsumed: true
  };
}

function admissionFields(admission) {
  return {
    tokenAdmissionChecked: true,
    spendId: admission.spendId,
    spendTokenHash: admission.spendTokenHash
  };
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

function isSha256Id(value) {
  return typeof value === "string" && SHA256_ID_RE.test(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isCanonicalBase64OfLength(value, expectedLength) {
  if (!isNonEmptyString(value)) return false;
  try {
    const bytes = Buffer.from(value, "base64");
    return bytes.length === expectedLength && bytes.toString("base64") === value;
  } catch {
    return false;
  }
}

function parseTimestamp(value) {
  if (!isNonEmptyString(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
    ? parsed
    : null;
}

function parseNow(value) {
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
