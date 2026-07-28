export type VerificationReason =
  | "ok"
  | "invalid_input"
  | "malformed_proof_artifact"
  | "unsupported_protocol_version"
  | "spend_token_mismatch"
  | "spend_token_commitment_mismatch"
  | "statement_id_mismatch"
  | "unknown_proof_system"
  | "unknown_circuit_id"
  | "unknown_verifying_key_id"
  | "public_input_order_mismatch"
  | "public_input_mismatch"
  | "replayed_nullifier"
  | "unsupported_cryptographic_backend"
  | "cryptographic_verification_failed";

export interface VerificationResult {
  ok: boolean;
  reason: VerificationReason;
  proofSystem?: string;
  circuitId?: string;
  verifyingKeyId?: string;
  statementId?: string;
  scopeId?: string;
  nullifier?: string;
  replayChecked?: boolean;
}

export interface VerifierRegistryEntryV1 {
  schemaVersion: 1;
  protocolVersion: string;
  proofSystem: string;
  circuitId: string;
  verifyingKeyId: string;
  publicInputOrder: string[];
  defaultK?: number;
  verifierParams?: {
    k?: number;
    defaultK?: number;
    [key: string]: unknown;
  };
  verifierKeyIdProfile?: string;
  artifactHash?: string;
  sourceCommit?: string;
  status?: string;
}

export interface VerifierRegistryManifestV1 {
  schemaVersion: 1;
  protocolVersion: string;
  entries: VerifierRegistryEntryV1[];
}

export interface VerificationBackend {
  verify(input: {
    proof: Record<string, unknown>;
    registryEntry: VerifierRegistryEntryV1;
    publicInputOrder: string[];
  }): Promise<{ ok: boolean; reason?: string }> | { ok: boolean; reason?: string };
}

export interface NullifierReplayStore {
  has(scopeId: string, nullifier: string): boolean;
}

export interface VerifySpendZkProofInput {
  spendToken?: Record<string, unknown>;
  proof: Record<string, unknown>;
  manifest: VerifierRegistryManifestV1;
  hashStatement(statement: unknown): string;
  backend?: VerificationBackend;
  seenNullifiers?: NullifierReplayStore | Set<string>;
}

export const H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER: readonly string[];
export const H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER: readonly string[];

export function verifySpendZkProof(input: VerifySpendZkProofInput): Promise<VerificationResult>;

export interface Halo2CliBackendOptions {
  command?: string;
  argsPrefix?: string[];
  cargoManifestPath?: string;
  cwd?: string;
  k?: number;
}

export function createHalo2CliBackend(options?: Halo2CliBackendOptions): VerificationBackend;
