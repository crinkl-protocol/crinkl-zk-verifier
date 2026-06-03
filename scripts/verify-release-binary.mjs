import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const checksumPath = new URL("../bin/checksums.sha256", import.meta.url);
const binaryPath = new URL("../bin/crnkl-zk-demo-linux-x64", import.meta.url);

const checksums = await readFile(checksumPath, "utf8");
const expectedLine = checksums.trim().split("\n").find((line) => line.endsWith("bin/crnkl-zk-demo-linux-x64"));
if (!expectedLine) {
  throw new Error("missing crnkl-zk-demo-linux-x64 checksum");
}

const expectedHash = expectedLine.split(/\s+/)[0];
const bytes = await readFile(binaryPath);
const actualHash = createHash("sha256").update(bytes).digest("hex");
if (actualHash !== expectedHash) {
  throw new Error(`release binary checksum mismatch: expected ${expectedHash}, got ${actualHash}`);
}

const help = await runBinary(["--help"]);
if (!help.stdout.includes("verify-promo-open-min")) {
  throw new Error("release binary help output does not include verify-promo-open-min");
}

console.log(JSON.stringify({ ok: true, binary: "bin/crnkl-zk-demo-linux-x64", sha256: actualHash }));

function runBinary(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(binaryPath.pathname, args, { stdio: ["ignore", "pipe", "pipe"] });
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
        reject(new Error(stderr.trim() || `release binary exited with code ${code}`));
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}
