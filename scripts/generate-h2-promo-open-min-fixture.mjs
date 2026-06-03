import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER } from "../src/index.mjs";

const cargoManifestPath = process.env.CRNKL_ZK_DEMO_MANIFEST_PATH;
const protocolVersion = "1.0.0-rc.2";
const proofSystem = "HALO2_IPA";
const circuitId = "H2_PROMO_OPEN_MIN_V1";
const verifierKeyIdProfile = "halo2_pinned_debug_v1";
const k = 14;

if (!cargoManifestPath) {
  console.error("set CRNKL_ZK_DEMO_MANIFEST_PATH to the zk-demo-rs Cargo.toml path");
  process.exit(1);
}

const fixtureDir = new URL("../fixtures/h2-promo-open-min-v1/", import.meta.url);
await mkdir(fixtureDir, { recursive: true });

const platformRoot = path.resolve(path.dirname(cargoManifestPath), "..", "..");
const sourceCommit = git(["-C", platformRoot, "rev-parse", "HEAD"]);

const totalCents = 1500;
const dayIndex = 20100;
const thresholdCents = 1000;
const minDayIndex = 20000;
const spendId = "spend-public-beta-h2-open-min-valid-001";
const headEventHashRaw = rawHash("public-beta-h2-open-min-head-event-001");
const headEventHash = `sha256:${headEventHashRaw}`;
const expectedStoreHash = hash("public-beta-h2-open-min-store-001");
const spendTokenHash = hash("public-beta-h2-open-min-spend-token-001");
const statement = {
  domain: "crinkl:statement:v1",
  schemaVersion: 1,
  type: "SPEND_STOREHASH_EQ_AND_DAYINDEX_GTE_AND_TOTAL_GTE",
  protocolVersion,
  expectedStoreHash,
  minDayIndex,
  thresholdCents,
  currency: "USD"
};
const statementId = hash(canonicalJson(statement));
const scopeId = hash("public-beta-h2-open-min-scope-001");
const nullifier = hash("public-beta-h2-open-min-nullifier-001");

const openings = await runZkDemo([
  "derive-openings",
  "--total-cents",
  String(totalCents),
  "--day-index",
  String(dayIndex),
  "--store-hash",
  expectedStoreHash,
  "--spend-id",
  spendId,
  "--head-event-hash",
  headEventHashRaw,
  "--seed-hex",
  rawHash("public-beta-h2-open-min-seed-001")
]);

const prove = await runZkDemo([
  "prove-promo-open-min",
  "--total-cents",
  String(totalCents),
  "--day-index",
  String(dayIndex),
  "--store-hash",
  expectedStoreHash,
  "--expected-store-hash",
  expectedStoreHash,
  "--threshold-cents",
  String(thresholdCents),
  "--min-day-index",
  String(minDayIndex),
  "--spend-id",
  spendId,
  "--head-event-hash",
  headEventHash,
  "--spend-token-hash",
  spendTokenHash,
  "--statement-id",
  statementId,
  "--scope-id",
  scopeId,
  "--nullifier",
  nullifier,
  "--blinding-store-b64",
  openings.blindingStoreB64,
  "--blinding-day-index-b64",
  openings.blindingDayIndexB64,
  "--blinding-total-b64",
  openings.blindingTotalB64,
  "--k",
  String(k)
]);

const verifierParams = {
  k,
  defaultK: k,
  curveFamily: "pasta",
  transcript: "halo2_ipa",
  hashFunctions: ["sha256", "poseidon"],
  commitmentEncoding: "zk_demo_rs_promo_open_min_v1",
  publicInputOrder: [...H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER]
};

const verifierArtifactProfile = {
  domain: "crinkl:verifier-artifact-profile:v1",
  schemaVersion: 1,
  protocolVersion,
  proofSystem,
  circuitId,
  verifyingKeyId: prove.verifyingKeyId,
  verifierKeyIdProfile,
  sourceCommit,
  verifierParams,
  publicInputOrder: [...H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER]
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
  issuedBy: "crinkl-proof-service-alpha-fixture",
  createdAt: "2026-06-02T00:00:00.000Z",
  k
};

const spendToken = {
  schemaVersion: 1,
  protocol: { protocolVersion },
  lineage: { headEventHash },
  signatures: { tokenHash: spendTokenHash }
};

const manifest = {
  schemaVersion: 1,
  protocolVersion,
  entries: [
    {
      schemaVersion: 1,
      protocolVersion,
      proofSystem,
      circuitId,
      verifyingKeyId: prove.verifyingKeyId,
      publicInputOrder: [...H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER],
      verifierKeyIdProfile,
      artifactHash,
      sourceCommit,
      validFromProtocolVersion: protocolVersion,
      auditStatus: "INTERNAL_REVIEW",
      verifierParams,
      status: "beta_public"
    }
  ]
};

await writeJson("valid-proof.json", proof);
await writeJson("spend-token.json", spendToken);
await writeJson("manifest.json", manifest);

const metadata = {
  schemaVersion: 1,
  generatedAt: "2026-06-02T00:00:00.000Z",
  generator: "scripts/generate-h2-promo-open-min-fixture.mjs",
  protocolVersion,
  proofSystem,
  circuitId,
  sourceCommit,
  artifactHash,
  verifierArtifactProfile,
  statementHashAlgorithm: "sha256(canonical-json-with-sorted-object-keys)",
  fileHashes: {
    "valid-proof.json": await fileHash("valid-proof.json"),
    "spend-token.json": await fileHash("spend-token.json"),
    "manifest.json": await fileHash("manifest.json")
  }
};
await writeJson("fixture-metadata.json", metadata);

console.log(JSON.stringify({ ok: true, artifactHash, sourceCommit }));

async function runZkDemo(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "cargo",
      ["run", "--quiet", "--manifest-path", cargoManifestPath, "--", ...args],
      { stdio: ["ignore", "pipe", "pipe"] }
    );

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
  const bytes = await readFile(new URL(fileName, fixtureDir));
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
