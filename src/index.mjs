import { createHash } from "node:crypto";
import { verifySpendAttestationTokenV1 } from "./spend-token-admission.mjs";

export { createHalo2CliBackend } from "./halo2-cli-backend.mjs";
export {
  canonicalize,
  verifySpendAttestationTokenV1
} from "./spend-token-admission.mjs";

export const H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER = Object.freeze([
  "spendIdHash",
  "headEventHash",
  "spendTokenHash",
  "statementId",
  "scopeId",
  "nullifier",
  "expectedStoreHash",
  "minDayIndex",
  "thresholdCents",
  "commitmentStore",
  "commitmentDayIndex",
  "commitmentTotal"
]);

export const H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER = Object.freeze([
  "spendIdHash",
  "headEventHash",
  "spendTokenHash",
  "statementId",
  "scopeId",
  "nullifier",
  "storeSetRoot",
  "minDayIndex",
  "minimumAmountCents",
  "commitmentStore",
  "commitmentDayIndex",
  "commitmentTotal",
  "maxDayIndex",
  "expectedCurrencyCode",
  "commitmentCurrency"
]);

const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const POSEIDON_RE = /^poseidon:[0-9a-f]{64}$/;
const CIRCUIT_PROFILES = Object.freeze({
  H2_PROMO_OPEN_MIN_V1: Object.freeze({
    publicInputOrder: H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER,
    validatePublicInputs: validateOpenMinPublicInputs,
    requiredTokenCommitments: Object.freeze({})
  }),
  H2_ATOMIC_PURCHASE_V2_CANDIDATE: Object.freeze({
    publicInputOrder: H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER,
    validatePublicInputs: validateAtomicPurchaseV2PublicInputs,
    requiredTokenCommitments: Object.freeze({
      C_store: "commitmentStore",
      C_dayIndex: "commitmentDayIndex",
      C_total: "commitmentTotal",
      C_currency: "commitmentCurrency"
    })
  })
});

export async function verifySpendZkProof(input) {
  if (!isRecord(input)) {
    return rejected("invalid_input");
  }

  const {
    proof,
    manifest,
    spendToken,
    hashStatement,
    backend,
    seenNullifiers,
    verificationPolicy,
    issuerRegistry,
    headStore
  } = input;
  const shape = validateProofShape(proof);
  if (!shape.ok) {
    return rejected(shape.reason);
  }

  const profile = Object.hasOwn(CIRCUIT_PROFILES, proof.circuitId)
    ? CIRCUIT_PROFILES[proof.circuitId]
    : null;
  if (!profile) {
    return rejected("unknown_circuit_id", proof);
  }

  const publicInputCheck = profile.validatePublicInputs(proof);
  if (!publicInputCheck.ok) {
    return rejected(publicInputCheck.reason, proof);
  }

  if (!isRecord(manifest) || manifest.schemaVersion !== 1 || !Array.isArray(manifest.entries)) {
    return rejected("malformed_proof_artifact", proof);
  }

  const registryEntry = resolveRegistryEntry(manifest, proof);
  if (!registryEntry.ok) {
    return rejected(registryEntry.reason, proof);
  }
  if (
    manifest.protocolVersion !== proof.protocolVersion ||
    registryEntry.entry.protocolVersion !== proof.protocolVersion
  ) {
    return rejected("unsupported_protocol_version", proof);
  }

  const orderCheck = verifyPublicInputOrder(
    registryEntry.entry.publicInputOrder,
    profile.publicInputOrder
  );
  if (!orderCheck) {
    return rejected("public_input_order_mismatch", proof);
  }

  if (typeof hashStatement !== "function") {
    return rejected("statement_id_mismatch", proof);
  }

  const statementId = hashStatement(proof.statement);
  if (statementId !== proof.statementId) {
    return rejected("statement_id_mismatch", proof);
  }

  const bindingCheck = verifyBindings({ proof, spendToken, profile });
  if (!bindingCheck.ok) {
    return rejected(bindingCheck.reason, proof);
  }

  const policyResult = normalizeVerificationPolicy(verificationPolicy);
  if (!policyResult.ok) {
    return rejected("invalid_verification_policy", proof);
  }
  const policy = policyResult.policy;
  let spendTokenAdmissionChecked = false;
  let headAcceptanceChecked = false;
  if (policy.spendTokenAdmission === "required") {
    const admission = await verifySpendAttestationTokenV1({
      token: spendToken,
      issuerRegistry,
      supportedProtocolVersions: [proof.protocolVersion]
    });
    spendTokenAdmissionChecked = true;
    if (!admission.ok) {
      return rejected(admission.reason, proof, { spendTokenAdmissionChecked });
    }
    if (
      admission.spendId !== proof.spendId ||
      admission.spendTokenHash !== proof.spendTokenHash ||
      admission.headEventHash !== normalizeSha256Id(proof.binding.headEventHash)
    ) {
      return rejected("spend_token_mismatch", proof, {
        spendTokenAdmissionChecked
      });
    }

    if (policy.headAcceptance === "required") {
      headAcceptanceChecked = true;
      if (!headStore || typeof headStore.isAccepted !== "function") {
        return rejected("spend_token_head_not_accepted", proof, {
          spendTokenAdmissionChecked,
          headAcceptanceChecked
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
        return rejected("spend_token_head_not_accepted", proof, {
          spendTokenAdmissionChecked,
          headAcceptanceChecked
        });
      }
    }
  }

  if (policy.nullifierReplay === "required" && !isConsumableReplayStore(seenNullifiers)) {
    return rejected("nullifier_replay_store_required", proof, {
      spendTokenAdmissionChecked,
      headAcceptanceChecked,
      replayChecked: false
    });
  }

  const replayCheck = verifyReplay({ scopeId: proof.scopeId, nullifier: proof.nullifier, seenNullifiers });
  if (!replayCheck.ok) {
    return rejected("replayed_nullifier", proof, {
      spendTokenAdmissionChecked,
      headAcceptanceChecked,
      replayChecked: true
    });
  }

  if (!backend || typeof backend.verify !== "function") {
    return rejected("unsupported_cryptographic_backend", proof, {
      spendTokenAdmissionChecked,
      headAcceptanceChecked,
      replayChecked: replayCheck.checked
    });
  }

  const cryptographicResult = await backend.verify({
    proof,
    registryEntry: registryEntry.entry,
    publicInputOrder: profile.publicInputOrder
  });

  if (!isRecord(cryptographicResult) || cryptographicResult.ok !== true) {
    return rejected("cryptographic_verification_failed", proof, {
      spendTokenAdmissionChecked,
      headAcceptanceChecked,
      replayChecked: replayCheck.checked
    });
  }

  let replayRecorded = false;
  if (policy.nullifierReplay === "required") {
    const recordResult = await consumeReplay({
      scopeId: proof.scopeId,
      nullifier: proof.nullifier,
      seenNullifiers
    });
    if (!recordResult.ok) {
      return rejected("replayed_nullifier", proof, {
        spendTokenAdmissionChecked,
        headAcceptanceChecked,
        replayChecked: true,
        replayRecorded: false
      });
    }
    replayRecorded = true;
  }

  return accepted(proof, {
    spendTokenAdmissionChecked,
    headAcceptanceChecked,
    replayChecked: replayCheck.checked,
    replayRecorded
  });
}

function validateProofShape(proof) {
  if (!isRecord(proof) || proof.schemaVersion !== 1) {
    return { ok: false, reason: "malformed_proof_artifact" };
  }

  if (!isNonEmptyString(proof.protocolVersion)) {
    return { ok: false, reason: "unsupported_protocol_version" };
  }

  const requiredHashes = [
    "spendTokenHash",
    "statementId",
    "scopeId",
    "nullifier",
    "verifyingKeyId"
  ];

  for (const field of requiredHashes) {
    if (!isHash(proof[field])) {
      return { ok: false, reason: "malformed_proof_artifact" };
    }
  }

  if (
    !isNonEmptyString(proof.spendId) ||
    !isRecord(proof.binding) ||
    !isHash(proof.binding.headEventHash) ||
    !isRecord(proof.statement) ||
    !isNonEmptyString(proof.proofSystem) ||
    !isNonEmptyString(proof.circuitId) ||
    !isRecord(proof.publicInputs) ||
    !isNonEmptyString(proof.proof) ||
    !isNonEmptyString(proof.issuedBy) ||
    !isNonEmptyString(proof.createdAt) ||
    Number.isNaN(Date.parse(proof.createdAt))
  ) {
    return { ok: false, reason: "malformed_proof_artifact" };
  }

  if (proof.proofSystem !== "HALO2_IPA") {
    return { ok: false, reason: "unknown_proof_system" };
  }

  return { ok: true };
}

function validateOpenMinPublicInputs(proof) {
  const publicInputs = proof.publicInputs;
  for (const field of H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER) {
    if (!(field in publicInputs)) {
      return { ok: false, reason: "malformed_proof_artifact" };
    }
  }

  const expectedHashInputs = [
    "spendIdHash",
    "headEventHash",
    "spendTokenHash",
    "statementId",
    "scopeId",
    "nullifier",
    "expectedStoreHash"
  ];

  for (const field of expectedHashInputs) {
    if (!isHash(publicInputs[field])) {
      return { ok: false, reason: "malformed_proof_artifact" };
    }
  }

  if (
    !isPoseidon(publicInputs.commitmentStore) ||
    !isPoseidon(publicInputs.commitmentDayIndex) ||
    !isPoseidon(publicInputs.commitmentTotal) ||
    !isUnsignedInteger(publicInputs.minDayIndex) ||
    !isUnsignedInteger(publicInputs.thresholdCents)
  ) {
    return { ok: false, reason: "malformed_proof_artifact" };
  }

  const statement = proof.statement;
  const mismatches = [
    publicInputs.spendIdHash !== hashString(proof.spendId),
    publicInputs.headEventHash !== proof.binding.headEventHash,
    publicInputs.spendTokenHash !== proof.spendTokenHash,
    publicInputs.statementId !== proof.statementId,
    publicInputs.scopeId !== proof.scopeId,
    publicInputs.nullifier !== proof.nullifier,
    publicInputs.expectedStoreHash !== statement.expectedStoreHash,
    String(publicInputs.minDayIndex) !== String(statement.minDayIndex),
    String(publicInputs.thresholdCents) !== String(statement.thresholdCents)
  ];

  if (mismatches.some(Boolean)) {
    return { ok: false, reason: "public_input_mismatch" };
  }

  return { ok: true };
}

function validateAtomicPurchaseV2PublicInputs(proof) {
  const publicInputs = proof.publicInputs;
  for (const field of H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER) {
    if (!(field in publicInputs)) {
      return { ok: false, reason: "malformed_proof_artifact" };
    }
  }

  const expectedHashInputs = [
    "spendIdHash",
    "headEventHash",
    "spendTokenHash",
    "statementId",
    "scopeId",
    "nullifier"
  ];
  for (const field of expectedHashInputs) {
    if (!isHash(publicInputs[field])) {
      return { ok: false, reason: "malformed_proof_artifact" };
    }
  }

  if (
    !isPoseidon(publicInputs.storeSetRoot) ||
    !isPoseidon(publicInputs.commitmentStore) ||
    !isPoseidon(publicInputs.commitmentDayIndex) ||
    !isPoseidon(publicInputs.commitmentTotal) ||
    !isPoseidon(publicInputs.commitmentCurrency) ||
    !isU32(publicInputs.minDayIndex) ||
    !isU32(publicInputs.maxDayIndex) ||
    !isU32(publicInputs.minimumAmountCents) ||
    !isUnsignedInteger(publicInputs.expectedCurrencyCode) ||
    publicInputs.expectedCurrencyCode > 0xffffff
  ) {
    return { ok: false, reason: "malformed_proof_artifact" };
  }

  const statement = proof.statement;
  const currencyCode = isRecord(statement)
    ? encodeIso4217Alpha3(statement.currency)
    : null;
  if (
    !isRecord(statement) ||
    !isPoseidon(statement.storeSetRoot) ||
    !isU32(statement.minDayIndex) ||
    !isU32(statement.maxDayIndex) ||
    !isU32(statement.minimumAmountCents) ||
    currencyCode === null ||
    statement.minDayIndex > statement.maxDayIndex
  ) {
    return { ok: false, reason: "malformed_proof_artifact" };
  }

  const mismatches = [
    publicInputs.spendIdHash !== hashString(proof.spendId),
    publicInputs.headEventHash !== proof.binding.headEventHash,
    publicInputs.spendTokenHash !== proof.spendTokenHash,
    publicInputs.statementId !== proof.statementId,
    publicInputs.scopeId !== proof.scopeId,
    publicInputs.nullifier !== proof.nullifier,
    publicInputs.storeSetRoot !== statement.storeSetRoot,
    String(publicInputs.minDayIndex) !== String(statement.minDayIndex),
    String(publicInputs.maxDayIndex) !== String(statement.maxDayIndex),
    String(publicInputs.minimumAmountCents) !== String(statement.minimumAmountCents),
    publicInputs.expectedCurrencyCode !== currencyCode
  ];

  if (mismatches.some(Boolean)) {
    return { ok: false, reason: "public_input_mismatch" };
  }

  return { ok: true };
}

function resolveRegistryEntry(manifest, proof) {
  const proofSystemMatches = manifest.entries.some((entry) => entry?.proofSystem === proof.proofSystem);
  if (!proofSystemMatches) {
    return { ok: false, reason: "unknown_proof_system" };
  }

  const circuitMatches = manifest.entries.some(
    (entry) => entry?.proofSystem === proof.proofSystem && entry?.circuitId === proof.circuitId
  );
  if (!circuitMatches) {
    return { ok: false, reason: "unknown_circuit_id" };
  }

  const entry = manifest.entries.find(
    (candidate) =>
      candidate?.schemaVersion === 1 &&
      candidate?.proofSystem === proof.proofSystem &&
      candidate?.circuitId === proof.circuitId &&
      candidate?.verifyingKeyId === proof.verifyingKeyId
  );

  if (!isRecord(entry)) {
    return { ok: false, reason: "unknown_verifying_key_id" };
  }

  return { ok: true, entry };
}

function verifyPublicInputOrder(publicInputOrder, expectedOrder) {
  return (
    Array.isArray(publicInputOrder) &&
    publicInputOrder.length === expectedOrder.length &&
    publicInputOrder.every((field, index) => field === expectedOrder[index])
  );
}

function verifyBindings({ proof, spendToken, profile }) {
  if (!isRecord(spendToken)) {
    return Object.keys(profile.requiredTokenCommitments).length === 0
      ? { ok: true }
      : { ok: false, reason: "spend_token_commitment_mismatch" };
  }

  const tokenHash = normalizeSha256Id(spendToken.signatures?.tokenHash);
  const headEventHash = normalizeSha256Id(spendToken.lineage?.headEventHash);
  const protocolVersion = spendToken.protocol?.protocolVersion;

  if (
    tokenHash !== proof.spendTokenHash ||
    headEventHash !== normalizeSha256Id(proof.binding.headEventHash)
  ) {
    return { ok: false, reason: "spend_token_mismatch" };
  }

  if (protocolVersion !== proof.protocolVersion) {
    return { ok: false, reason: "unsupported_protocol_version" };
  }

  const commitments = spendToken.zk?.commitments;
  for (const [tokenField, publicInputField] of Object.entries(profile.requiredTokenCommitments)) {
    if (!isRecord(commitments) || commitments[tokenField] !== proof.publicInputs[publicInputField]) {
      return { ok: false, reason: "spend_token_commitment_mismatch" };
    }
  }

  return { ok: true };
}

function verifyReplay({ scopeId, nullifier, seenNullifiers }) {
  if (!seenNullifiers) {
    return { ok: true, checked: false };
  }

  if (seenNullifiers instanceof Set) {
    return { ok: !seenNullifiers.has(replayKey(scopeId, nullifier)), checked: true };
  }

  if (typeof seenNullifiers.has === "function") {
    return { ok: !seenNullifiers.has(scopeId, nullifier), checked: true };
  }

  return { ok: false, checked: true };
}

function normalizeVerificationPolicy(value) {
  if (value === undefined) {
    return {
      ok: true,
      policy: {
        spendTokenAdmission: "legacy",
        headAcceptance: "token-bound",
        nullifierReplay: "optional"
      }
    };
  }
  if (!isRecord(value)) {
    return { ok: false };
  }
  const allowedKeys = new Set([
    "spendTokenAdmission",
    "headAcceptance",
    "nullifierReplay"
  ]);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    return { ok: false };
  }
  if (
    !["legacy", "required"].includes(value.spendTokenAdmission ?? "legacy") ||
    !["token-bound", "required"].includes(value.headAcceptance ?? "token-bound") ||
    !["optional", "required"].includes(value.nullifierReplay ?? "optional")
  ) {
    return { ok: false };
  }
  const policy = {
    spendTokenAdmission: value.spendTokenAdmission ?? "legacy",
    headAcceptance: value.headAcceptance ?? "token-bound",
    nullifierReplay: value.nullifierReplay ?? "optional"
  };
  if (
    policy.headAcceptance === "required" &&
    policy.spendTokenAdmission !== "required"
  ) {
    return { ok: false };
  }
  return {
    ok: true,
    policy
  };
}

function isConsumableReplayStore(value) {
  return Boolean(
    value &&
      !(value instanceof Set) &&
      typeof value.has === "function" &&
      typeof value.consume === "function"
  );
}

async function consumeReplay({ scopeId, nullifier, seenNullifiers }) {
  try {
    return {
      ok: (await seenNullifiers.consume(scopeId, nullifier)) === true
    };
  } catch {
    return { ok: false };
  }
}

function accepted(proof, extra = {}) {
  return {
    ok: true,
    reason: "ok",
    proofSystem: proof.proofSystem,
    circuitId: proof.circuitId,
    verifyingKeyId: proof.verifyingKeyId,
    statementId: proof.statementId,
    scopeId: proof.scopeId,
    nullifier: proof.nullifier,
    ...extra
  };
}

function rejected(reason, proof = {}, extra = {}) {
  return {
    ok: false,
    reason,
    proofSystem: proof.proofSystem,
    circuitId: proof.circuitId,
    verifyingKeyId: proof.verifyingKeyId,
    statementId: proof.statementId,
    scopeId: proof.scopeId,
    nullifier: proof.nullifier,
    ...extra
  };
}

function replayKey(scopeId, nullifier) {
  return `${scopeId}\u0000${nullifier}`;
}

function hashString(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function isHash(value) {
  return typeof value === "string" && HASH_RE.test(value);
}

function normalizeSha256Id(value) {
  if (typeof value !== "string") return null;
  if (HASH_RE.test(value)) return value;
  return /^[0-9a-f]{64}$/.test(value) ? `sha256:${value}` : null;
}

function isPoseidon(value) {
  return typeof value === "string" && POSEIDON_RE.test(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isUnsignedInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

function isU32(value) {
  return isUnsignedInteger(value) && value <= 0xffffffff;
}

function encodeIso4217Alpha3(value) {
  if (typeof value !== "string" || !/^[A-Z]{3}$/.test(value)) {
    return null;
  }
  return (
    (value.charCodeAt(0) << 16) |
    (value.charCodeAt(1) << 8) |
    value.charCodeAt(2)
  );
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
