import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { test } from "node:test";

import {
  H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER,
  createHalo2CliBackend,
  verifySpendZkProof
} from "../src/index.mjs";

const cargoManifestPath = process.env.CRNKL_ZK_DEMO_MANIFEST_PATH;
let realFixturePromise;

test("real Halo2 CLI backend verifies a generated open-min proof", async (t) => {
  const fixture = await getRealHalo2Fixture(t);
  const result = await verifySpendZkProof({
    ...fixture,
    backend: createHalo2CliBackend({ cargoManifestPath })
  });

  assert.equal(result.ok, true);
  assert.equal(result.reason, "ok");
});

test("real Halo2 CLI backend rejects changed commitment public input", async (t) => {
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
  const fixture = await getRealHalo2Fixture(t);
  fixture.proof.proof = "Y2hhbmdlZA==";

  const result = await verifySpendZkProof({
    ...fixture,
    backend: createHalo2CliBackend({ cargoManifestPath })
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "cryptographic_verification_failed");
});

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
