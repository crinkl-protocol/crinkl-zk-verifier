import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { createHalo2CliBackend, verifySpendZkProof } from "../src/index.mjs";

const fixtureDir = new URL("../fixtures/h2-promo-open-min-v1/", import.meta.url);
const binaryPath = new URL("../bin/crnkl-zk-demo-linux-x64", import.meta.url);

test("release binary checksum matches pinned checksum", async () => {
  const checksums = await readFile(new URL("../bin/checksums.sha256", import.meta.url), "utf8");
  const expectedLine = checksums.trim().split("\n").find((line) => line.endsWith("bin/crnkl-zk-demo-linux-x64"));
  assert.ok(expectedLine);

  const expectedHash = expectedLine.split(/\s+/)[0];
  const bytes = await readFile(binaryPath);
  const actualHash = createHash("sha256").update(bytes).digest("hex");
  assert.equal(actualHash, expectedHash);
});

test("release binary backend verifies the published open-min fixture", async () => {
  const fixture = await loadPublishedFixture();
  const result = await verifySpendZkProof({
    ...fixture,
    backend: createHalo2CliBackend()
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
    hashStatement: (statement) => hash(canonicalJson(statement))
  };
}

async function readJson(fileName) {
  return JSON.parse(await readFile(new URL(fileName, fixtureDir), "utf8"));
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
