export type VerificationReason =
  | "ok"
  | "invalid_input"
  | "malformed_proof_artifact"
  | "unsupported_protocol_version"
  | "malformed_spend_token"
  | "spend_token_mismatch"
  | "spend_token_hash_mismatch"
  | "spend_token_signature_invalid"
  | "spend_token_issuer_unauthorized"
  | "spend_token_head_not_accepted"
  | "spend_token_commitment_mismatch"
  | "invalid_verification_policy"
  | "statement_id_mismatch"
  | "unknown_proof_system"
  | "unknown_circuit_id"
  | "unknown_verifying_key_id"
  | "public_input_order_mismatch"
  | "public_input_mismatch"
  | "nullifier_replay_store_required"
  | "replayed_nullifier"
  | "unsupported_cryptographic_backend"
  | "cryptographic_verification_failed";

export type HolderControlReason =
  | VerificationReason
  | "holder_control_verified"
  | "holder_control_unavailable"
  | "malformed_holder_challenge"
  | "malformed_holder_context"
  | "malformed_holder_proof"
  | "holder_context_mismatch"
  | "holder_challenge_not_yet_valid"
  | "holder_challenge_expired"
  | "holder_challenge_store_required"
  | "holder_challenge_replayed"
  | "holder_commitment_mismatch"
  | "holder_challenge_id_mismatch"
  | "holder_proof_binding_mismatch"
  | "holder_signature_invalid";

export type CampaignProofAuthorizationReason =
  | VerificationReason
  | HolderControlReason
  | "campaign_proof_authorization_verified"
  | "malformed_campaign_authorization_package"
  | "malformed_campaign_request_context"
  | "campaign_request_context_mismatch"
  | "campaign_proof_authorization_expired"
  | "malformed_authorized_input_manifest"
  | "authorized_input_manifest_mismatch"
  | "authorized_spend_input_mismatch"
  | "campaign_proof_verifier_failed"
  | "campaign_holder_verifier_failed"
  | "campaign_nullifier_consumption_failed";

export interface VerificationResult {
  ok: boolean;
  reason: VerificationReason;
  proofSystem?: string;
  circuitId?: string;
  verifyingKeyId?: string;
  statementId?: string;
  scopeId?: string;
  nullifier?: string;
  spendTokenAdmissionChecked?: boolean;
  headAcceptanceChecked?: boolean;
  replayChecked?: boolean;
  replayRecorded?: boolean;
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
  consume(scopeId: string, nullifier: string): Promise<boolean> | boolean;
}

export interface SpendTokenIssuerRegistry {
  isAuthorized(input: {
    issuedBy: string;
    publicKey: string;
    protocolVersion: string;
  }): Promise<boolean> | boolean;
}

export interface SpendTokenHeadStore {
  isAccepted(input: {
    spendId: string;
    spendTokenHash: string;
    headEventHash: string;
    eventCount: number;
    protocolVersion: string;
  }): Promise<boolean> | boolean;
}

export interface VerificationPolicy {
  spendTokenAdmission?: "legacy" | "required";
  headAcceptance?: "token-bound" | "required";
  nullifierReplay?: "optional" | "required";
}

export interface VerifySpendZkProofInput {
  spendToken?: Record<string, unknown>;
  proof: Record<string, unknown>;
  manifest: VerifierRegistryManifestV1;
  hashStatement(statement: unknown): string;
  backend?: VerificationBackend;
  seenNullifiers?: NullifierReplayStore | Set<string>;
  verificationPolicy?: VerificationPolicy;
  issuerRegistry?: SpendTokenIssuerRegistry;
  headStore?: SpendTokenHeadStore;
}

export const H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER: readonly string[];
export const H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER: readonly string[];

export function verifySpendZkProof(input: VerifySpendZkProofInput): Promise<VerificationResult>;

export interface SpendTokenAdmissionResult {
  ok: boolean;
  reason: VerificationReason;
  spendId?: string;
  spendTokenHash?: string;
  headEventHash?: string;
  eventCount?: number;
  schemaVersion?: 1 | 2;
  protocolVersion?: string;
  issuedBy?: string;
  publicKey?: string;
  holderBinding?: {
    scheme: "crinkl.holder.v2";
    commitment: string;
  };
}

export function canonicalize(value: unknown): string;
export function verifySpendAttestationToken(input: {
  token: Record<string, unknown>;
  issuerRegistry?: SpendTokenIssuerRegistry;
  supportedProtocolVersions?: string[];
}): Promise<SpendTokenAdmissionResult>;
export function verifySpendAttestationTokenV1(input: {
  token: Record<string, unknown>;
  issuerRegistry?: SpendTokenIssuerRegistry;
  supportedProtocolVersions?: string[];
}): Promise<SpendTokenAdmissionResult>;
export function verifySpendAttestationTokenV2(input: {
  token: Record<string, unknown>;
  issuerRegistry?: SpendTokenIssuerRegistry;
  supportedProtocolVersions?: string[];
}): Promise<SpendTokenAdmissionResult>;

export type SpendHolderPurposeV2 =
  | "TOKEN_PRESENTATION"
  | "CAMPAIGN_PROOF_AUTHORIZATION"
  | "CAMPAIGN_ACTION_AUTHORIZATION";

export interface SpendHolderChallengeV2 {
  domain: "crinkl.spend-holder-challenge.v2";
  schemaVersion: 2;
  nonceBase64: string;
  spendTokenHash: string;
  scopeId: string;
  requestContextHash: string;
  purpose: SpendHolderPurposeV2;
  verifierId: string;
  issuedAt: string;
  expiresAt: string;
}

export interface SpendHolderControlProofV2 {
  schemaVersion: 2;
  scheme: "crinkl.holder.v2";
  spendTokenHash: string;
  scopeId: string;
  challengeId: string;
  holderPublicKeyBase64: string;
  signatureBase64: string;
}

export interface SpendHolderExpectedContextV2 {
  spendTokenHash: string;
  scopeId: string;
  requestContextHash: string;
  purpose: SpendHolderPurposeV2;
  verifierId: string;
}

export interface SpendHolderChallengeKeyV2 {
  verifierId: string;
  nonceBase64: string;
}

export interface SpendHolderChallengeStoreV2 {
  isOutstanding(
    input: SpendHolderChallengeKeyV2
  ): Promise<boolean> | boolean;
  consume(input: SpendHolderChallengeKeyV2): Promise<boolean> | boolean;
}

export interface SpendHolderControlResultV2 {
  ok: boolean;
  reason: HolderControlReason;
  tokenAdmissionChecked?: boolean;
  spendId?: string;
  spendTokenHash?: string;
  scopeId?: string;
  requestContextHash?: string;
  purpose?: SpendHolderPurposeV2;
  verifierId?: string;
  challengeId?: string;
  challengeChecked?: boolean;
  challengeConsumed?: boolean;
}

export function verifySpendHolderControlV2(input: {
  token: Record<string, unknown>;
  issuerRegistry?: SpendTokenIssuerRegistry;
  supportedProtocolVersions?: string[];
  challenge: SpendHolderChallengeV2;
  holderProof: SpendHolderControlProofV2;
  expectedContext: SpendHolderExpectedContextV2;
  now?: Date | string | number;
  challengeStore?: SpendHolderChallengeStoreV2;
}): Promise<SpendHolderControlResultV2>;

export interface CampaignHolderProofAuthorizationRequestContextV1 {
  domain: "crinkl:campaign:holder-proof-authorization-request-context:v1";
  schemaVersion: 1;
  protocolVersion: "1.0.0-rc.1";
  campaignId: string;
  campaignEpochRef: string;
  campaignPolicyPackageRef: string;
  conditionId: string;
  requirementId: string;
  evaluationContextHash: string;
  statementId: string;
  statementEvaluationProfileRef: string;
  proofProfile: {
    proofSystem: string;
    circuitId: string;
    verifyingKeyId: string;
  };
  inputManifestRef: string;
  recipientDisclosurePolicyRef: string;
  authorizationExpiresAt: string;
}

export interface CampaignProofAuthorizationPackageV1 {
  schemaVersion: 1;
  requestContext: CampaignHolderProofAuthorizationRequestContextV1;
  spendToken: Record<string, unknown>;
  holderChallenge: SpendHolderChallengeV2;
  holderProof: SpendHolderControlProofV2;
  atomicProof: Record<string, unknown>;
}

export interface CampaignProofAuthorizationResultV1 {
  ok: boolean;
  reason: CampaignProofAuthorizationReason;
  requestContextHash?: string;
  campaignId?: string;
  campaignEpochRef?: string;
  statementId?: string;
  scopeId?: string;
  nullifier?: string;
  spendTokenHash?: string;
  requestContextChecked?: boolean;
  inputManifestChecked?: boolean;
  atomicProofChecked?: boolean;
  holderControlChecked?: boolean;
  holderChallengeConsumed?: boolean;
  campaignNullifierChecked?: boolean;
  campaignNullifierConsumed?: boolean;
  partialConsumption?: boolean;
  retryRule?: "NEW_HOLDER_CHALLENGE_REQUIRED";
}

export function hashCampaignHolderProofAuthorizationRequestContextV1(
  requestContext: CampaignHolderProofAuthorizationRequestContextV1
): string;

export function verifyCampaignProofAuthorizationV1(input: {
  package: CampaignProofAuthorizationPackageV1;
  expectedRequestContext: CampaignHolderProofAuthorizationRequestContextV1;
  expectedScopeId: string;
  expectedVerifierId: string;
  authorizedInputManifest: Record<string, unknown>;
  proofArtifactManifest: VerifierRegistryManifestV1;
  hashStatement(statement: unknown): string;
  backend?: VerificationBackend;
  issuerRegistry?: SpendTokenIssuerRegistry;
  headStore?: SpendTokenHeadStore;
  challengeStore?: SpendHolderChallengeStoreV2;
  campaignNullifierStore?: NullifierReplayStore;
  supportedProtocolVersions?: string[];
  now?: Date | string | number;
}): Promise<CampaignProofAuthorizationResultV1>;

export interface Halo2CliBackendOptions {
  command?: string;
  argsPrefix?: string[];
  cargoManifestPath?: string;
  cwd?: string;
  k?: number;
}

export function createHalo2CliBackend(options?: Halo2CliBackendOptions): VerificationBackend;
