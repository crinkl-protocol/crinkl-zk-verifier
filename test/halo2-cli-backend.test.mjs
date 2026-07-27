import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER,
  H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER,
  createHalo2CliBackend,
  verifySpendZkProof
} from "../src/index.mjs";

const cargoManifestPath = process.env.CRNKL_ZK_DEMO_MANIFEST_PATH;
const fixtureDir = new URL("../fixtures/h2-promo-open-min-v1/", import.meta.url);
let realFixturePromise;

test("real Halo2 CLI backend verifies a generated open-min proof", async (t) => {
  if (!cargoManifestPath) {
    t.skip("set CRNKL_ZK_DEMO_MANIFEST_PATH to run the real Halo2 backend test");
    return;
  }
  const fixture = await getRealHalo2Fixture(t);
  const result = await verifySpendZkProof({
    ...fixture,
    backend: createHalo2CliBackend({ cargoManifestPath })
  });

  assert.equal(result.ok, true);
  assert.equal(result.reason, "ok");
});

test("real Halo2 CLI backend verifies the published open-min fixture", async (t) => {
  if (!cargoManifestPath) {
    t.skip("set CRNKL_ZK_DEMO_MANIFEST_PATH to run the real Halo2 backend test");
    return;
  }

  const fixture = await loadPublishedFixture();
  const result = await verifySpendZkProof({
    ...fixture,
    backend: createHalo2CliBackend({ cargoManifestPath })
  });

  assert.equal(result.ok, true);
  assert.equal(result.reason, "ok");
});

test("real Halo2 CLI backend rejects changed commitment public input", async (t) => {
  if (!cargoManifestPath) {
    t.skip("set CRNKL_ZK_DEMO_MANIFEST_PATH to run the real Halo2 backend test");
    return;
  }
  const fixture = await getRealHalo2Fixture(t);
  fixture.proof.publicInputs.commitmentTotal = poseidon("changed-total-commitment");

  const result = await verifySpendZkProof({
    ...fixture,
    backend: createHalo2CliBackend({ cargoManifestPath })
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "cryptographic_verification_failed");
});

test("real Halo2 CLI backend rejects changed proof bytes", async (t) => {
  if (!cargoManifestPath) {
    t.skip("set CRNKL_ZK_DEMO_MANIFEST_PATH to run the real Halo2 backend test");
    return;
  }
  const fixture = await getRealHalo2Fixture(t);
  fixture.proof.proof = "Y2hhbmdlZA==";

  const result = await verifySpendZkProof({
    ...fixture,
    backend: createHalo2CliBackend({ cargoManifestPath })
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "cryptographic_verification_failed");
});

test("Halo2 CLI backend sends atomic purchase v2 through the JSON request contract", async () => {
  const fixture = makeAtomicPurchaseV2Fixture();
  const verifierScript = `
    const { readFileSync } = require("node:fs");
    const args = process.argv.slice(1);
    const requestIndex = args.indexOf("--request-file");
    const request = JSON.parse(readFileSync(args[requestIndex + 1], "utf8"));
    const ok =
      args[0] === "verify-atomic-purchase-v2" &&
      request.k === 14 &&
      request.proof === "cHJvb2Y=" &&
      request.publicInputs.expectedCurrencyCode === 5591876 &&
      request.publicInputs.commitmentCurrency.startsWith("poseidon:");
    process.stdout.write(JSON.stringify({
      ok,
      circuitId: "H2_ATOMIC_PURCHASE_V2_CANDIDATE",
      verifyingKeyId: "sha256:b01da9b079abf9063d7b5b096c57dc715be2fa7323f8dc0df79ac7605ed65f74"
    }) + "\\n");
  `;

  const result = await verifySpendZkProof({
    ...fixture,
    backend: createHalo2CliBackend({
      command: process.execPath,
      argsPrefix: ["--eval", verifierScript],
      k: 14
    })
  });

  assert.equal(result.ok, true);
  assert.equal(result.reason, "ok");
});

async function loadPublishedFixture() {
  const [proof, spendToken, manifest] = await Promise.all([
    readJson("valid-proof.json"),
    readJson("spend-token.json"),
    readJson("manifest.json")
  ]);

  return {
    proof,
    spendToken,
    manifest,
    hashStatement: (candidate) => hash(canonicalJson(candidate))
  };
}

async function readJson(fileName) {
  return JSON.parse(await readFile(new URL(fileName, fixtureDir), "utf8"));
}

async function getRealHalo2Fixture(t) {
  if (!cargoManifestPath) {
    t.skip("set CRNKL_ZK_DEMO_MANIFEST_PATH to run the real Halo2 backend test");
    return {};
  }

  realFixturePromise ??= makeRealHalo2Fixture();
  const fixture = await realFixturePromise;
  return {
    proof: structuredClone(fixture.proof),
    spendToken: structuredClone(fixture.spendToken),
    manifest: structuredClone(fixture.manifest),
    hashStatement: fixture.hashStatement
  };
}

async function makeRealHalo2Fixture() {
  const totalCents = 1500;
  const dayIndex = 20100;
  const thresholdCents = 1000;
  const minDayIndex = 20000;
  const spendId = "spend-real-halo2-open-min";
  const headEventHashRaw = rawHash("real-head-event");
  const headEventHash = `sha256:${headEventHashRaw}`;
  const storeHash = hash("real-store");
  const spendTokenHash = hash("real-spend-token");
  const statement = {
    domain: "crinkl:statement:v1",
    schemaVersion: 1,
    type: "SPEND_STOREHASH_EQ_AND_DAYINDEX_GTE_AND_TOTAL_GTE",
    protocolVersion: "1.0.0-rc.2",
    expectedStoreHash: storeHash,
    minDayIndex,
    thresholdCents,
    currency: "USD"
  };
  const statementId = hash(JSON.stringify(statement));
  const scopeId = hash("real-scope");
  const nullifier = hash("real-nullifier");

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
    headEventHashRaw,
    "--seed-hex",
    rawHash("real-seed")
  ]);

  const prove = await runZkDemo([
    "prove-promo-open-min",
    "--total-cents",
    String(totalCents),
    "--day-index",
    String(dayIndex),
    "--store-hash",
    storeHash,
    "--expected-store-hash",
    storeHash,
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
    "14"
  ]);

  const proof = {
    schemaVersion: 1,
    protocolVersion: "1.0.0-rc.2",
    spendId,
    spendTokenHash,
    binding: { headEventHash },
    statement,
    statementId,
    scopeId,
    nullifier,
    proofSystem: "HALO2_IPA",
    circuitId: "H2_PROMO_OPEN_MIN_V1",
    verifyingKeyId: prove.verifyingKeyId,
    publicInputs: prove.publicInputs,
    proof: prove.proof,
    issuedBy: "crinkl-zk-verifier-real-test",
    createdAt: "2026-06-02T00:00:00.000Z",
    k: 14
  };

  return {
    proof,
    spendToken: {
      lineage: { headEventHash },
      protocol: { protocolVersion: "1.0.0-rc.2" },
      signatures: { tokenHash: spendTokenHash }
    },
    manifest: {
      schemaVersion: 1,
      protocolVersion: "1.0.0-rc.2",
      entries: [
        {
          schemaVersion: 1,
          protocolVersion: "1.0.0-rc.2",
          proofSystem: "HALO2_IPA",
          circuitId: "H2_PROMO_OPEN_MIN_V1",
          verifyingKeyId: prove.verifyingKeyId,
          publicInputOrder: [...H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER],
          verifierKeyIdProfile: "halo2_pinned_debug_v1",
          verifierParams: { k: 14 },
          status: "alpha_current_business"
        }
      ]
    },
    hashStatement: (candidate) => hash(JSON.stringify(candidate))
  };
}

function makeAtomicPurchaseV2Fixture() {
  const spendId = "spend-atomic-cli-contract";
  const headEventHash = hash("atomic-cli-head");
  const spendTokenHash = hash("atomic-cli-token");
  const statement = {
    domain: "crinkl:statement:v1",
    schemaVersion: 1,
    type: "PRIVATE_COMMERCE_ATOMIC_PURCHASE",
    protocolVersion: "1.0.0-rc.2",
    storeSetRoot: poseidon("atomic-cli-store-set"),
    minDayIndex: 20_000,
    maxDayIndex: 20_200,
    minimumAmountCents: 1_000,
    currency: "USD"
  };
  const statementId = hash(JSON.stringify(statement));
  const scopeId = hash("atomic-cli-scope");
  const nullifier = hash("atomic-cli-nullifier");
  const commitments = {
    C_store: poseidon("atomic-cli-store"),
    C_dayIndex: poseidon("atomic-cli-day"),
    C_total: poseidon("atomic-cli-total"),
    C_currency: poseidon("atomic-cli-currency")
  };
  const verifyingKeyId =
    "sha256:b01da9b079abf9063d7b5b096c57dc715be2fa7323f8dc0df79ac7605ed65f74";

  return {
    proof: {
      schemaVersion: 1,
      protocolVersion: "1.0.0-rc.2",
      spendId,
      spendTokenHash,
      binding: { headEventHash },
      statement,
      statementId,
      scopeId,
      nullifier,
      proofSystem: "HALO2_IPA",
      circuitId: "H2_ATOMIC_PURCHASE_V2_CANDIDATE",
      verifyingKeyId,
      publicInputs: {
        spendIdHash: hash(spendId),
        headEventHash,
        spendTokenHash,
        statementId,
        scopeId,
        nullifier,
        storeSetRoot: statement.storeSetRoot,
        minDayIndex: statement.minDayIndex,
        minimumAmountCents: statement.minimumAmountCents,
        commitmentStore: commitments.C_store,
        commitmentDayIndex: commitments.C_dayIndex,
        commitmentTotal: commitments.C_total,
        maxDayIndex: statement.maxDayIndex,
        expectedCurrencyCode: 5_591_876,
        commitmentCurrency: commitments.C_currency
      },
      proof: "cHJvb2Y=",
      issuedBy: "crinkl-zk-verifier-cli-contract-test",
      createdAt: "2026-07-27T00:00:00.000Z",
      k: 14
    },
    spendToken: {
      lineage: { headEventHash },
      protocol: { protocolVersion: "1.0.0-rc.2" },
      signatures: { tokenHash: spendTokenHash },
      zk: { commitments }
    },
    manifest: {
      schemaVersion: 1,
      protocolVersion: "1.0.0-rc.2",
      entries: [
        {
          schemaVersion: 1,
          protocolVersion: "1.0.0-rc.2",
          proofSystem: "HALO2_IPA",
          circuitId: "H2_ATOMIC_PURCHASE_V2_CANDIDATE",
          verifyingKeyId,
          publicInputOrder: [...H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER],
          verifierKeyIdProfile: "halo2_atomic_purchase_v2_candidate",
          verifierParams: { k: 14 },
          status: "LAB_CANDIDATE_NOT_ADOPTED"
        }
      ]
    },
    hashStatement: (candidate) => hash(JSON.stringify(candidate))
  };
}

function runZkDemo(args) {
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

function hash(value) {
  return `sha256:${rawHash(value)}`;
}

function rawHash(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function poseidon(value) {
  return `poseidon:${rawHash(value)}`;
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
