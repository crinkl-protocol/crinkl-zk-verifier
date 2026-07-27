import {
  createHash,
  createPublicKey,
  verify as verifySignature
} from "node:crypto";

const RAW_SHA256_RE = /^[0-9a-f]{64}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export async function verifySpendAttestationTokenV1({
  token,
  issuerRegistry,
  supportedProtocolVersions
} = {}) {
  if (!isRecord(token) || !isRecord(token.signatures)) {
    return rejected("malformed_spend_token");
  }

  const { signatures, ...unsignedToken } = token;
  if (
    token.tokenType !== "SPEND_ATTESTATION" ||
    token.schemaVersion !== 1 ||
    !isNonEmptyString(token.spendId) ||
    !isRecord(token.canonical) ||
    !isRecord(token.lineage) ||
    !isHashLike(token.lineage.headEventHash) ||
    !Number.isInteger(token.lineage.eventCount) ||
    token.lineage.eventCount < 1 ||
    !isRecord(token.protocol) ||
    !isNonEmptyString(token.protocol.protocolVersion) ||
    !isNonEmptyString(signatures.issuedBy) ||
    !isBase64OfLength(signatures.publicKey, 32) ||
    !RAW_SHA256_RE.test(signatures.tokenHash ?? "") ||
    !isBase64OfLength(signatures.signature, 64)
  ) {
    return rejected("malformed_spend_token");
  }
  if (
    supportedProtocolVersions !== undefined &&
    (!Array.isArray(supportedProtocolVersions) ||
      !supportedProtocolVersions.includes(token.protocol.protocolVersion))
  ) {
    return rejected("unsupported_protocol_version");
  }

  let canonical;
  try {
    canonical = canonicalize(unsignedToken);
  } catch {
    return rejected("malformed_spend_token");
  }

  const computedTokenHash = createHash("sha256")
    .update(canonical, "utf8")
    .digest("hex");
  if (computedTokenHash !== signatures.tokenHash) {
    return rejected("spend_token_hash_mismatch");
  }

  let signatureValid = false;
  try {
    const rawPublicKey = Buffer.from(signatures.publicKey, "base64");
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
      format: "der",
      type: "spki"
    });
    signatureValid = verifySignature(
      null,
      Buffer.from(computedTokenHash, "hex"),
      publicKey,
      Buffer.from(signatures.signature, "base64")
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    return rejected("spend_token_signature_invalid");
  }

  if (!issuerRegistry || typeof issuerRegistry.isAuthorized !== "function") {
    return rejected("spend_token_issuer_unauthorized");
  }

  let issuerAuthorized = false;
  try {
    issuerAuthorized =
      (await issuerRegistry.isAuthorized({
        issuedBy: signatures.issuedBy,
        publicKey: signatures.publicKey,
        protocolVersion: token.protocol.protocolVersion
      })) === true;
  } catch {
    issuerAuthorized = false;
  }
  if (!issuerAuthorized) {
    return rejected("spend_token_issuer_unauthorized");
  }

  return {
    ok: true,
    reason: "ok",
    spendId: token.spendId,
    spendTokenHash: `sha256:${computedTokenHash}`,
    headEventHash: normalizeSha256Id(token.lineage.headEventHash),
    eventCount: token.lineage.eventCount,
    protocolVersion: token.protocol.protocolVersion,
    issuedBy: signatures.issuedBy,
    publicKey: signatures.publicKey
  };
}

export function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("RFC 8785 cannot canonicalize non-finite numbers");
    }
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .filter((key) => value[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError(`RFC 8785 cannot canonicalize ${typeof value}`);
}

function normalizeSha256Id(value) {
  if (RAW_SHA256_RE.test(value ?? "")) return `sha256:${value}`;
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value)
    ? value
    : null;
}

function isHashLike(value) {
  return normalizeSha256Id(value) !== null;
}

function isBase64OfLength(value, expectedLength) {
  if (typeof value !== "string" || value.length === 0) return false;
  try {
    const decoded = Buffer.from(value, "base64");
    return (
      decoded.length === expectedLength &&
      decoded.toString("base64").replace(/=+$/u, "") ===
        value.replace(/=+$/u, "")
    );
  } catch {
    return false;
  }
}

function rejected(reason) {
  return { ok: false, reason };
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}
