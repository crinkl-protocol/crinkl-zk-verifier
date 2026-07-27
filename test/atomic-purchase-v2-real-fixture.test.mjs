import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER,
  createHalo2CliBackend,
  verifySpendZkProof
} from "../src/index.mjs";

const fixtureDir = new URL("../fixtures/h2-atomic-purchase-v2-candidate/", import.meta.url);

test("atomic purchase v2 real fixture hashes and public package are stable", async () => {
  const fixture = await loadFixture();

  assert.deepEqual(fixture.proof.statement, fixture.statement);
  assert.deepEqual(
    fixture.manifest.entries[0].publicInputOrder,
    [...H2_ATOMIC_PURCHASE_V2_CANDIDATE_PUBLIC_INPUT_ORDER]
  );
  assert.equal(fixture.metadata.proofBytes, 3_072);
  assert.equal(fixture.metadata.productionZk, false);
  assert.equal(fixture.metadata.privateWitnessPersisted, false);

  for (const [fileName, expectedHash] of Object.entries(fixture.metadata.fileHashes)) {
    assert.equal(await fileHash(fileName), expectedHash);
  }
});

test("atomic purchase v2 real fixture is accepted by the direct CLI and independent verifier", async () => {
  const fixture = await loadFixture();
  const recordingBackend = createRecordingCliBackend();

  const result = await independentVerify(fixture, recordingBackend.backend);
  assert.equal(recordingBackend.observed()?.ok, true);
  assert.equal(result.ok, true);
  assert.equal(result.reason, "ok");
});

for (const caseId of [
  "PROOF_BYTES_CHANGED",
  "BOUND_MINIMUM_AMOUNT_CHANGED",
  "BOUND_STORE_SET_ROOT_CHANGED",
  "BOUND_CURRENCY_COMMITMENT_CHANGED"
]) {
  test(`atomic purchase v2 real fixture parity rejects ${caseId}`, async () => {
    const fixture = await loadFixture();
    const declaredCase = fixture.verificationCases.rejectCases.find(
      (candidate) => candidate.id === caseId
    );
    assert.ok(declaredCase);
    assert.equal(declaredCase.expected, "REJECT");

    mutateFixture(fixture, caseId);
    const recordingBackend = createRecordingCliBackend();

    const result = await independentVerify(fixture, recordingBackend.backend);
    assert.equal(recordingBackend.observed()?.ok, false);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "cryptographic_verification_failed");
  });
}

async function independentVerify(fixture, backend) {
  return verifySpendZkProof({
    proof: fixture.proof,
    spendToken: fixture.spendToken,
    manifest: fixture.manifest,
    hashStatement: (statement) => hash(canonicalJson(statement)),
    backend
  });
}

function createRecordingCliBackend() {
  const cliBackend = createHalo2CliBackend();
  let result;
  return {
    backend: {
      async verify(input) {
        result = await cliBackend.verify(input);
        return result;
      }
    },
    observed: () => result
  };
}

function mutateFixture(fixture, caseId) {
  if (caseId === "PROOF_BYTES_CHANGED") {
    fixture.proof.proof = flipBase64Character(fixture.proof.proof);
    return;
  }

  if (caseId === "BOUND_MINIMUM_AMOUNT_CHANGED") {
    fixture.proof.statement.minimumAmountCents += 1;
    fixture.proof.statementId = hash(canonicalJson(fixture.proof.statement));
    fixture.proof.publicInputs.statementId = fixture.proof.statementId;
    fixture.proof.publicInputs.minimumAmountCents =
      fixture.proof.statement.minimumAmountCents;
    return;
  }

  if (caseId === "BOUND_STORE_SET_ROOT_CHANGED") {
    fixture.proof.statement.storeSetRoot = changedPoseidon("store-set-root");
    fixture.proof.statementId = hash(canonicalJson(fixture.proof.statement));
    fixture.proof.publicInputs.statementId = fixture.proof.statementId;
    fixture.proof.publicInputs.storeSetRoot = fixture.proof.statement.storeSetRoot;
    return;
  }

  if (caseId === "BOUND_CURRENCY_COMMITMENT_CHANGED") {
    const commitment = changedPoseidon("currency-commitment");
    fixture.proof.publicInputs.commitmentCurrency = commitment;
    fixture.spendToken.zk.commitments.C_currency = commitment;
    return;
  }

  throw new Error(`unknown verification case ${caseId}`);
}

async function loadFixture() {
  const [proof, statement, spendToken, manifest, verificationCases, metadata] =
    await Promise.all([
      readJson("valid-proof.json"),
      readJson("statement.json"),
      readJson("spend-token.json"),
      readJson("manifest.json"),
      readJson("verification-cases.json"),
      readJson("fixture-metadata.json")
    ]);

  return { proof, statement, spendToken, manifest, verificationCases, metadata };
}

async function readJson(fileName) {
  return JSON.parse(await readFile(new URL(fileName, fixtureDir), "utf8"));
}

async function fileHash(fileName) {
  const bytes = await readFile(new URL(fileName, fixtureDir));
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function flipBase64Character(value) {
  const index = Math.floor(value.length / 2);
  const replacement = value[index] === "A" ? "B" : "A";
  return `${value.slice(0, index)}${replacement}${value.slice(index + 1)}`;
}

function changedPoseidon(label) {
  return `poseidon:${createHash("sha256").update(label, "utf8").digest("hex")}`;
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
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
