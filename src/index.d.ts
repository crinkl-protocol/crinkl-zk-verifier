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

export interface CampaignProofJobAuthorizationGrantV1 {
  domain: "crinkl:campaign:proof-job-authorization-grant:v1";
  schemaVersion: 1;
  protocolVersion: "1.0.0-rc.1";
  grantId: string;
  requestContextHash: string;
  campaignId: string;
  campaignEpochRef: string;
  campaignPolicyPackageRef: string;
  scopeId: string;
  statementId: string;
  proofProfile: {
    proofSystem: string;
    circuitId: string;
    verifyingKeyId: string;
  };
  inputManifestRef: string;
  recipientDisclosurePolicyRef: string;
  authorizedSpendInputs: Array<{
    spendId: string;
    spendTokenHash: string;
    canonicalHeadEventHash: string;
    challengeId: string;
  }>;
  verifierId: string;
  authorizedAt: string;
  expiresAt: string;
}

export type CampaignProofJobAuthorizationReason =
  | VerificationReason
  | HolderControlReason
  | "campaign_proof_job_authorization_granted"
  | "campaign_proof_job_authorization_verified"
  | "campaign_proof_job_authorization_claimed"
  | "malformed_campaign_request_context"
  | "campaign_request_context_mismatch"
  | "campaign_proof_authorization_expired"
  | "campaign_proof_authorization_lifetime_exceeded"
  | "malformed_authorized_input_manifest"
  | "authorized_input_manifest_mismatch"
  | "authorized_spend_input_mismatch"
  | "holder_authorization_set_mismatch"
  | "holder_authorization_result_mismatch"
  | "spend_token_head_store_required"
  | "spend_token_verifier_failed"
  | "campaign_holder_verifier_failed"
  | "grant_id_generation_failed"
  | "grant_shape_invalid"
  | "grant_ref_invalid"
  | "grant_ref_mismatch"
  | "proof_job_authorization_expired"
  | "proof_job_authorization_store_required"
  | "proof_job_authorization_store_race"
  | "proof_job_authorization_not_claimable";

export interface CampaignProofJobAuthorizationGrantStoreV1 {
  authorize(input: {
    grantRef: string;
    grant: CampaignProofJobAuthorizationGrantV1;
    initialState: "AUTHORIZED";
  }): Promise<boolean> | boolean;
  claim?(input: {
    grantRef: string;
    expectedState: "AUTHORIZED";
    nextState: "CLAIMED";
  }): Promise<boolean> | boolean;
}

export interface CampaignProofJobAuthorizationResultV1 {
  ok: boolean;
  reason: CampaignProofJobAuthorizationReason;
  grant?: CampaignProofJobAuthorizationGrantV1;
  grantRef?: string;
  grantId?: string;
  lifecycleState?: "AUTHORIZED" | "CLAIMED";
  requestContextHash?: string;
  requestContextChecked?: boolean;
  inputManifestChecked?: boolean;
  spendHeadsChecked?: boolean;
  holderControlsChecked?: number;
  consumedChallengeIds?: string[];
  partialConsumption?: boolean;
  retryRule?: "NEW_HOLDER_CHALLENGES_REQUIRED";
}

export interface CampaignProofJobHolderAuthorizationV1 {
  spendToken: Record<string, unknown>;
  holderChallenge: SpendHolderChallengeV2;
  holderProof: SpendHolderControlProofV2;
}

export function hashCampaignProofJobAuthorizationGrantV1(
  grant: CampaignProofJobAuthorizationGrantV1
): string;

export function verifyCampaignProofJobAuthorizationGrantV1(input: {
  grant: CampaignProofJobAuthorizationGrantV1;
  expectedGrantRef: string;
  now?: Date | string | number;
}): CampaignProofJobAuthorizationResultV1;

export function claimCampaignProofJobAuthorizationGrantV1(input: {
  grant: CampaignProofJobAuthorizationGrantV1;
  expectedGrantRef: string;
  now?: Date | string | number;
  grantStore?: {
    claim(input: {
      grantRef: string;
      expectedState: "AUTHORIZED";
      nextState: "CLAIMED";
    }): Promise<boolean> | boolean;
  };
}): Promise<CampaignProofJobAuthorizationResultV1>;

export function createCampaignProofJobAuthorizer(options?: {
  verifySpendToken?(input: {
    token: Record<string, unknown>;
    issuerRegistry?: SpendTokenIssuerRegistry;
    supportedProtocolVersions?: string[];
  }): Promise<SpendTokenAdmissionResult> | SpendTokenAdmissionResult;
  verifyHolderControl?(input: {
    token: Record<string, unknown>;
    issuerRegistry?: SpendTokenIssuerRegistry;
    supportedProtocolVersions?: string[];
    challenge: SpendHolderChallengeV2;
    holderProof: SpendHolderControlProofV2;
    expectedContext: SpendHolderExpectedContextV2;
    now?: Date | string | number;
    challengeStore?: SpendHolderChallengeStoreV2;
  }): Promise<SpendHolderControlResultV2> | SpendHolderControlResultV2;
  generateGrantId?(): string;
  maximumGrantLifetimeMs?: number;
}): (input: {
  requestContext: CampaignHolderProofAuthorizationRequestContextV1;
  expectedScopeId: string;
  expectedVerifierId: string;
  authorizedInputManifest: Record<string, unknown>;
  holderAuthorizations: CampaignProofJobHolderAuthorizationV1[];
  issuerRegistry?: SpendTokenIssuerRegistry;
  headStore?: SpendTokenHeadStore;
  challengeStore?: SpendHolderChallengeStoreV2;
  grantStore?: CampaignProofJobAuthorizationGrantStoreV1;
  supportedProtocolVersions?: string[];
  now?: Date | string | number;
}) => Promise<CampaignProofJobAuthorizationResultV1>;

export interface CampaignServerProvedCompletionPackageV1 {
  domain: "crinkl:campaign:server-proved-completion-package:v1";
  schemaVersion: 1;
  protocolVersion: "1.0.0-rc.1";
  grantRef: string;
  proofArtifactRef: string;
  proverId: string;
  completedAt: string;
}

export type CampaignServerProvedCompletionReason =
  | VerificationReason
  | "campaign_server_proved_completion_verified"
  | "completion_package_shape_invalid"
  | "completion_ref_invalid"
  | "completion_ref_mismatch"
  | "grant_shape_invalid"
  | "grant_ref_mismatch"
  | "proof_job_lifecycle_store_required"
  | "proof_job_authorization_not_claimed"
  | "proof_job_claimed_by_other_prover"
  | "prover_registry_required"
  | "prover_not_authorized"
  | "proof_job_authorization_expired"
  | "proof_artifact_shape_invalid"
  | "proof_artifact_ref_mismatch"
  | "proof_job_lineage_mismatch"
  | "proof_job_time_mismatch"
  | "campaign_proof_verifier_failed"
  | "campaign_nullifier_consumption_failed"
  | "campaign_completion_terminalization_failed"
  | "proof_job_failure_terminalization_failed";

export interface CampaignProofJobLifecycleStoreV1 {
  get(input: {
    grantRef: string;
  }): Promise<{
    state: string;
    claimedBy?: string;
    claimedAt?: string;
  } | null> | {
    state: string;
    claimedBy?: string;
    claimedAt?: string;
  } | null;
  transition(input: {
    grantRef: string;
    expectedState: "CLAIMED";
    nextState: "COMPLETED" | "FAILED";
    reason: string;
  }): Promise<boolean> | boolean;
}

export interface CampaignProverRegistryV1 {
  isAuthorized(input: {
    proverId: string;
    grantRef: string;
    claimedAt: string;
    completedAt: string;
  }): Promise<boolean> | boolean;
}

export interface CampaignServerProvedCompletionResultV1 {
  ok: boolean;
  reason: CampaignServerProvedCompletionReason;
  completionRef?: string;
  grantRef?: string;
  proofArtifactRef?: string;
  campaignId?: string;
  statementId?: string;
  scopeId?: string;
  nullifier?: string;
  proofChecked?: boolean;
  campaignNullifierChecked?: boolean;
  campaignNullifierConsumed?: boolean;
  grantLifecycleState?: "CLAIMED" | "COMPLETED" | "FAILED";
  holderChallengeOperations?: 0;
  partialConsumption?: boolean;
  reconciliationRequired?: boolean;
  failedReason?: string;
}

export function hashCampaignServerProvedCompletionPackageV1(
  completionPackage: CampaignServerProvedCompletionPackageV1
): string;

export function verifyCampaignServerProvedCompletionV1(input: {
  package: CampaignServerProvedCompletionPackageV1;
  expectedCompletionRef: string;
  grant: CampaignProofJobAuthorizationGrantV1;
  proofArtifact: Record<string, unknown>;
  spendTokens: Record<string, unknown>[];
  proofArtifactManifest: VerifierRegistryManifestV1;
  hashStatement(statement: unknown): string;
  backend?: VerificationBackend;
  issuerRegistry?: SpendTokenIssuerRegistry;
  headStore?: SpendTokenHeadStore;
  proverRegistry?: CampaignProverRegistryV1;
  grantLifecycleStore?: CampaignProofJobLifecycleStoreV1;
  campaignNullifierStore?: NullifierReplayStore;
}): Promise<CampaignServerProvedCompletionResultV1>;

export interface Halo2CliBackendOptions {
  command?: string;
  argsPrefix?: string[];
  cargoManifestPath?: string;
  cwd?: string;
  k?: number;
}

export function createHalo2CliBackend(options?: Halo2CliBackendOptions): VerificationBackend;
