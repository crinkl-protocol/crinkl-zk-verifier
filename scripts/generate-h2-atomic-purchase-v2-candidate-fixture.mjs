import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER } from "../src/index.mjs";

const zkDemoBinary = process.env.CRNKL_ZK_DEMO_BIN;
const sourceRoot = process.env.CRNKL_ZK_DEMO_SOURCE_ROOT;
const protocolVersion = "1.0.0-rc.2";
const proofSystem = "HALO2_IPA";
const profileId = "CAMPAIGN_QUALIFICATION_ATOMIC_PURCHASE_PROFILE_V2_CANDIDATE";
const circuitId = "H2_ATOMIC_PURCHASE_V2_CANDIDATE";
const verifierKeyIdProfile = "halo2_atomic_purchase_v2_candidate_k14";
const k = 14;

if (!zkDemoBinary || !sourceRoot) {
  console.error("set CRNKL_ZK_DEMO_BIN and CRNKL_ZK_DEMO_SOURCE_ROOT");
  process.exit(1);
}

const fixtureDir = new URL("../fixtures/h2-atomic-purchase-v2-candidate/", import.meta.url);
await mkdir(fixtureDir, { recursive: true });

const sourceCommit = git(["-C", sourceRoot, "rev-parse", "HEAD"]);
const binarySha256 = await fileHashPath(zkDemoBinary);
const temporaryDirectory = await mkdtemp(join(tmpdir(), "crnkl-atomic-v2-fixture-"));

try {
  const totalCents = 2_450;
  const dayIndex = 20_290;
  const minimumAmountCents = 2_000;
  const minDayIndex = 20_280;
  const maxDayIndex = 20_310;
  const currency = "USD";
  const spendId = "spend-atomic-purchase-v2-public-fixture-001";
  const headEventHash = hash("atomic-purchase-v2-public-fixture-head-001");
  const storeHash = hash("merchant:raposa:public-fixture-001");
  const otherStoreHash = hash("merchant:raposa:public-fixture-002");
  const scopeId = hash("campaign:raposa:atomic-purchase-v2:scope-001");
  const nullifier = hash("campaign:raposa:atomic-purchase-v2:nullifier-001");

  const storeHashesFile = join(temporaryDirectory, "store-hashes.json");
  await writeFile(storeHashesFile, `${JSON.stringify([storeHash, otherStoreHash])}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
  const storeProof = await runZkDemo([
    "compute-store-proof",
    "--store-hash",
    storeHash,
    "--store-hashes-file",
    storeHashesFile
  ]);

  const openings = await runZkDemo([
    "derive-openings",
    "--total-cents",
    String(totalCents),
    "--day-index",
    String(dayIndex),
    "--store-hash",
    storeHash,
    "--spend-id",
    spendId,
    "--head-event-hash",
    headEventHash.slice("sha256:".length),
    "--currency",
    currency,
    "--seed-hex",
    rawHash("atomic-purchase-v2-public-fixture-seed-001")
  ]);

  const commitments = {
    C_store: openings.commitmentStore,
    C_dayIndex: openings.commitmentDayIndex,
    C_total: openings.commitmentTotal,
    C_currency: openings.commitmentCurrency
  };
  const spendTokenBody = {
    schemaVersion: 1,
    protocol: { protocolVersion },
    spend: { spendId },
    lineage: { headEventHash },
    issuer: { issuerId: "pricechain-labs-public-fixture" },
    zk: { commitments }
  };
  const spendTokenHash = hash(canonicalJson(spendTokenBody));
  const spendToken = {
    ...spendTokenBody,
    signatures: { tokenHash: spendTokenHash }
  };

  const statement = {
    domain: "crinkl:statement:v1",
    schemaVersion: 1,
    type: "PRIVATE_COMMERCE_ATOMIC_PURCHASE",
    protocolVersion,
    storeSetRoot: storeProof.storeSetRoot,
    minDayIndex,
    maxDayIndex,
    minimumAmountCents,
    currency
  };
  const statementId = hash(canonicalJson(statement));

  const proveRequest = {
    totalCents,
    dayIndex,
    storeHash,
    minimumAmountCents,
    minDayIndex,
    maxDayIndex,
    currency,
    expectedCurrency: currency,
    storeSetRoot: storeProof.storeSetRoot,
    merkleProof: storeProof.proof,
    spendId,
    headEventHash,
    spendTokenHash,
    statementId,
    scopeId,
    nullifier,
    blindingStoreB64: openings.blindingStoreB64,
    blindingDayIndexB64: openings.blindingDayIndexB64,
    blindingTotalB64: openings.blindingTotalB64,
    blindingCurrencyB64: openings.blindingCurrencyB64,
    k
  };
  const proveRequestFile = join(temporaryDirectory, "prove-request.json");
  await writeFile(proveRequestFile, `${JSON.stringify(proveRequest)}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
  const prove = await runZkDemo([
    "prove-atomic-purchase-v2",
    "--request-file",
    proveRequestFile
  ]);

  if (
    prove.proofSystem !== proofSystem ||
    prove.profileId !== profileId ||
    prove.circuitId !== circuitId ||
    prove.productionZk !== false ||
    prove.proofBytes !== 3_072
  ) {
    throw new Error("atomic purchase v2 prover returned an unexpected candidate profile");
  }

  const verifierParams = {
    k,
    defaultK: k,
    curveFamily: "pasta",
    transcript: "halo2_ipa",
    currencyEncoding: "ISO_4217_ALPHA3_ASCII_U24_BE",
    commitmentEncoding: "zk_demo_rs_atomic_purchase_v2_candidate",
    publicInputOrder: [...H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER]
  };
  const verifierArtifactProfile = {
    domain: "crinkl:verifier-artifact-profile:v1",
    schemaVersion: 1,
    protocolVersion,
    proofSystem,
    profileId,
    circuitId,
    verifyingKeyId: prove.verifyingKeyId,
    verifierKeyIdProfile,
    sourceCommit,
    binarySha256,
    verifierParams,
    publicInputOrder: [...H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER]
  };
  const artifactHash = hash(canonicalJson(verifierArtifactProfile));

  const proof = {
    schemaVersion: 1,
    protocolVersion,
    spendId,
    spendTokenHash,
    binding: { headEventHash },
    statement,
    statementId,
    scopeId,
    nullifier,
    proofSystem,
    circuitId,
    verifyingKeyId: prove.verifyingKeyId,
    publicInputs: prove.publicInputs,
    proof: prove.proof,
    issuedBy: "crinkl-proof-service-atomic-v2-candidate-fixture",
    createdAt: "2026-07-27T00:00:00.000Z",
    k
  };
  const manifest = {
    schemaVersion: 1,
    protocolVersion,
    entries: [
      {
        schemaVersion: 1,
        protocolVersion,
        proofSystem,
        profileId,
        circuitId,
        verifyingKeyId: prove.verifyingKeyId,
        publicInputOrder: [...H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER],
        verifierKeyIdProfile,
        artifactHash,
        sourceCommit,
        binarySha256,
        validFromProtocolVersion: protocolVersion,
        auditStatus: "INTERNAL_REVIEW",
        verifierParams,
        maturity: "LAB_CANDIDATE_NOT_ADOPTED",
        productionZk: false,
        status: "candidate"
      }
    ]
  };
  const verificationCases = {
    schemaVersion: 1,
    validCase: { id: "VALID_REAL_PROOF", expected: "ACCEPT" },
    rejectCases: [
      {
        id: "PROOF_BYTES_CHANGED",
        mutation: "proof.proof",
        expected: "REJECT"
      },
      {
        id: "BOUND_MINIMUM_AMOUNT_CHANGED",
        mutation:
          "proof.statement.minimumAmountCents + proof.statementId + proof.publicInputs.statementId + proof.publicInputs.minimumAmountCents",
        expected: "REJECT"
      },
      {
        id: "BOUND_STORE_SET_ROOT_CHANGED",
        mutation:
          "proof.statement.storeSetRoot + proof.statementId + proof.publicInputs.statementId + proof.publicInputs.storeSetRoot",
        expected: "REJECT"
      },
      {
        id: "BOUND_CURRENCY_COMMITMENT_CHANGED",
        mutation: "proof.publicInputs.commitmentCurrency + spendToken.zk.commitments.C_currency",
        expected: "REJECT"
      }
    ]
  };

  await writeJson("valid-proof.json", proof);
  await writeJson("statement.json", statement);
  await writeJson("spend-token.json", spendToken);
  await writeJson("manifest.json", manifest);
  await writeJson("verification-cases.json", verificationCases);

  const metadata = {
    schemaVersion: 1,
    generatedAt: "2026-07-27T00:00:00.000Z",
    generator: "scripts/generate-h2-atomic-purchase-v2-candidate-fixture.mjs",
    protocolVersion,
    proofSystem,
    profileId,
    circuitId,
    maturity: "LAB_CANDIDATE_NOT_ADOPTED",
    productionZk: false,
    sourceCommit,
    binarySha256,
    artifactHash,
    proofBytes: prove.proofBytes,
    verifyingKeyId: prove.verifyingKeyId,
    verifierArtifactProfile,
    statementHashAlgorithm: "sha256(canonical-json-with-sorted-object-keys)",
    tokenHashBoundary: "sha256(canonical fixture token excluding signatures)",
    issuerSignatureBoundary: "UPSTREAM_SPEND_TOKEN_ADMISSION_NOT_REPROVED_BY_THIS_FIXTURE",
    privateWitnessPersisted: false,
    fileHashes: {
      "valid-proof.json": await fileHash("valid-proof.json"),
      "statement.json": await fileHash("statement.json"),
      "spend-token.json": await fileHash("spend-token.json"),
      "manifest.json": await fileHash("manifest.json"),
      "verification-cases.json": await fileHash("verification-cases.json")
    }
  };
  await writeJson("fixture-metadata.json", metadata);

  console.log(
    JSON.stringify({
      ok: true,
      artifactHash,
      sourceCommit,
      binarySha256,
      proofBytes: prove.proofBytes
    })
  );
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

async function runZkDemo(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(zkDemoBinary, args, {
      stdio: ["ignore", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `crnkl-zk-demo exited with code ${code}`));
        return;
      }

      resolve(JSON.parse(stdout.trim().split("\n").at(-1)));
    });
  });
}

function git(args) {
  const result = spawnSync("git", args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "git command failed");
  }

  return result.stdout.trim();
}

async function writeJson(fileName, value) {
  await writeFile(new URL(fileName, fixtureDir), `${JSON.stringify(value, null, 2)}\n`);
}

async function fileHash(fileName) {
  return fileHashPath(new URL(fileName, fixtureDir));
}

async function fileHashPath(fileName) {
  const bytes = await readFile(fileName);
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function hash(value) {
  return `sha256:${rawHash(value)}`;
}

function rawHash(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}
