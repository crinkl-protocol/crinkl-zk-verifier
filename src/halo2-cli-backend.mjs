import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const DEFAULT_K = 14;

export function createHalo2CliBackend(options = {}) {
  const cargoManifestPath = options.cargoManifestPath ?? process.env.CRNKL_ZK_DEMO_MANIFEST_PATH;
  const envBinary = process.env.CRNKL_ZK_DEMO_BIN;
  const packagedBinary = resolvePackagedBinary();
  const usesCargoManifest = !options.command && !envBinary && Boolean(cargoManifestPath);
  const command = options.command ?? envBinary ?? (usesCargoManifest ? "cargo" : packagedBinary ?? "crnkl-zk-demo");
  const argsPrefix =
    options.argsPrefix ??
    (usesCargoManifest ? ["run", "--quiet", "--manifest-path", cargoManifestPath, "--"] : []);

  return {
    async verify({ proof, registryEntry }) {
      const k = resolveK({ options, proof, registryEntry });
      const args = [
        ...argsPrefix,
        "verify-promo-open-min",
        "--commitment-store",
        stringField(proof.publicInputs, "commitmentStore"),
        "--commitment-day-index",
        stringField(proof.publicInputs, "commitmentDayIndex"),
        "--commitment-total",
        stringField(proof.publicInputs, "commitmentTotal"),
        "--expected-store-hash",
        stringField(proof.publicInputs, "expectedStoreHash"),
        "--threshold-cents",
        String(integerField(proof.publicInputs, "thresholdCents")),
        "--min-day-index",
        String(integerField(proof.publicInputs, "minDayIndex")),
        "--spend-id",
        stringField(proof, "spendId"),
        "--head-event-hash",
        stringField(proof.binding, "headEventHash"),
        "--spend-token-hash",
        stringField(proof, "spendTokenHash"),
        "--statement-id",
        stringField(proof, "statementId"),
        "--scope-id",
        stringField(proof, "scopeId"),
        "--nullifier",
        stringField(proof, "nullifier"),
        "--k",
        String(k),
        "--proof",
        stringField(proof, "proof")
      ];

      const result = await runCommand({ command, args, cwd: options.cwd });
      if (!result.ok) {
        return { ok: false, reason: result.reason };
      }

      const parsed = parseJsonLine(result.stdout);
      if (!parsed || parsed.ok !== true) {
        return { ok: false, reason: "halo2_cli_rejected" };
      }

      return { ok: true };
    }
  };
}


function resolvePackagedBinary() {
  if (process.platform !== "linux" || process.arch !== "x64") {
    return null;
  }

  const binaryPath = fileURLToPath(new URL("../bin/crnkl-zk-demo-linux-x64", import.meta.url));
  return existsSync(binaryPath) ? binaryPath : null;
}

function resolveK({ options, proof, registryEntry }) {
  const candidates = [
    options.k,
    proof.k,
    registryEntry.defaultK,
    registryEntry.verifierParams?.k,
    registryEntry.verifierParams?.defaultK
  ];

  for (const candidate of candidates) {
    if (Number.isInteger(candidate) && candidate > 0) {
      return candidate;
    }
  }

  return DEFAULT_K;
}

function runCommand({ command, args, cwd }) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
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
    child.on("error", (error) => {
      resolve({ ok: false, reason: error.message, stdout, stderr });
    });
    child.on("close", (code) => {
      resolve({
        ok: code === 0,
        reason: code === 0 ? "ok" : stderr.trim() || `process exited with code ${code}`,
        stdout,
        stderr
      });
    });
  });
}

function parseJsonLine(stdout) {
  const lines = stdout.trim().split("\n").filter(Boolean);
  const line = lines.at(-1);
  if (!line) {
    return null;
  }

  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

function stringField(record, field) {
  if (!isRecord(record) || typeof record[field] !== "string") {
    throw new Error(`missing string field ${field}`);
  }

  return record[field];
}

function integerField(record, field) {
  if (!isRecord(record) || !Number.isInteger(record[field])) {
    throw new Error(`missing integer field ${field}`);
  }

  return record[field];
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
