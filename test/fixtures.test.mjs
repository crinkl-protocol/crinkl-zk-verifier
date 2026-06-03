import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER,
  verifySpendZkProof
} from "../src/index.mjs";

const fixtureDir = new URL("../fixtures/h2-promo-open-min-v1/", import.meta.url);

test("published H2_PROMO_OPEN_MIN_V1 fixture file hashes are stable", async () => {
  const metadata = await readJson("fixture-metadata.json");

  for (const [fileName, expectedHash] of Object.entries(metadata.fileHashes)) {
    assert.equal(await fileHash(fileName), expectedHash);
  }
});

test("published H2_PROMO_OPEN_MIN_V1 fixture verifies through package contract", async () => {
  const fixture = await loadFixture();
  const result = await verifySpendZkProof({
    ...fixture,
    backend: {
      verify: ({ proof, registryEntry, publicInputOrder }) => {
        assert.equal(proof.proofSystem, "HALO2_IPA");
        assert.equal(proof.circuitId, "H2_PROMO_OPEN_MIN_V1");
        assert.equal(registryEntry.artifactHash, fixture.metadata.artifactHash);
        assert.deepEqual(publicInputOrder, H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER);
        assert.deepEqual(registryEntry.publicInputOrder, [...H2_PROMO_OPEN_MIN_V1_PUBLIC_INPUT_ORDER]);
        return { ok: true };
      }
    }
  });

  assert.equal(result.ok, true);
  assert.equal(result.reason, "ok");
});

test("published H2_PROMO_OPEN_MIN_V1 fixture rejects artifact hash drift", async () => {
  const fixture = await loadFixture();
  fixture.manifest.entries[0].artifactHash = hash("changed-verifier-artifact-profile");

  const result = await verifySpendZkProof({
    ...fixture,
    backend: {
      verify: ({ registryEntry }) => ({
        ok: registryEntry.artifactHash === fixture.metadata.artifactHash
      })
    }
  });

  assert.equal(result.ok, false);
  assert.equal(result.reason, "cryptographic_verification_failed");
});

async function loadFixture() {
  const [proof, spendToken, manifest, metadata] = await Promise.all([
    readJson("valid-proof.json"),
    readJson("spend-token.json"),
    readJson("manifest.json"),
    readJson("fixture-metadata.json")
  ]);

  return {
    proof,
    spendToken,
    manifest,
    metadata,
    hashStatement: (statement) => hash(canonicalJson(statement))
  };
}

async function readJson(fileName) {
  return JSON.parse(await readFile(new URL(fileName, fixtureDir), "utf8"));
}

async function fileHash(fileName) {
  const bytes = await readFile(new URL(fileName, fixtureDir));
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
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
