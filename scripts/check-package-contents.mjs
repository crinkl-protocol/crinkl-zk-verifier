import { execFile } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile
} from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const EXPECTED_PACKAGE_FILES = Object.freeze([
  "LICENSE",
  "README.md",
  "bin/checksums.sha256",
  "bin/crnkl-zk-demo-linux-x64",
  "package.json",
  "src/campaign-proof-authorization.mjs",
  "src/campaign-proof-job-authorization.mjs",
  "src/campaign-server-proved-completion.mjs",
  "src/halo2-cli-backend.mjs",
  "src/index.d.ts",
  "src/index.mjs",
  "src/spend-holder-control.mjs",
  "src/spend-token-admission.mjs"
]);

const REQUIRED_RUNTIME_EXPORTS = Object.freeze([
  "claimCampaignProofJobAuthorizationGrantV1",
  "createCampaignProofJobAuthorizer",
  "hashCampaignHolderProofAuthorizationRequestContextV1",
  "hashCampaignHolderProofAuthorizationRequestContextV2",
  "hashCampaignProofJobAuthorizationGrantV1",
  "hashCampaignServerProvedCompletionPackageV1",
  "verifyCampaignServerProvedCompletionV1"
]);

export async function checkPackageContents({
  cwd = new URL("../", import.meta.url)
} = {}) {
  const root = cwd instanceof URL ? cwd : pathToFileURL(`${cwd}/`);
  const packageJson = JSON.parse(
    await readFile(new URL("package.json", root), "utf8")
  );
  if (
    packageJson.name !== "@crnkl/zk-verifier" ||
    packageJson.license !== "Apache-2.0" ||
    packageJson.publishConfig?.access !== "public" ||
    JSON.stringify(packageJson.files) !== JSON.stringify(["src", "bin"]) ||
    packageJson.exports?.["."]?.import !== "./src/index.mjs" ||
    packageJson.exports?.["."]?.types !== "./src/index.d.ts" ||
    packageJson.bin?.["crnkl-zk-demo-linux-x64"] !==
      "./bin/crnkl-zk-demo-linux-x64"
  ) {
    throw new Error("package metadata is not release-locked");
  }

  const runtime = await import(new URL("src/index.mjs", root));
  for (const exportName of REQUIRED_RUNTIME_EXPORTS) {
    if (typeof runtime[exportName] !== "function") {
      throw new Error(`missing runtime export: ${exportName}`);
    }
  }

  const declarations = await readFile(
    new URL("src/index.d.ts", root),
    "utf8"
  );
  for (const exportName of REQUIRED_RUNTIME_EXPORTS) {
    if (
      !new RegExp(
        `export (?:declare )?(?:const|function) ${exportName}\\b`,
        "u"
      ).test(declarations)
    ) {
      throw new Error(`missing type declaration: ${exportName}`);
    }
  }

  const { stdout } = await execFileAsync(
    "npm",
    ["pack", "--dry-run", "--json", "--ignore-scripts"],
    {
      cwd: new URL(".", root),
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024
    }
  );
  const packResult = JSON.parse(stdout);
  if (!Array.isArray(packResult) || packResult.length !== 1) {
    throw new Error("npm pack dry-run returned an unexpected result");
  }
  const packedFiles = packResult[0].files
    .map(({ path }) => path)
    .sort();
  const expectedFiles = [...EXPECTED_PACKAGE_FILES].sort();
  if (JSON.stringify(packedFiles) !== JSON.stringify(expectedFiles)) {
    const unexpected = packedFiles.filter(
      (path) => !expectedFiles.includes(path)
    );
    const missing = expectedFiles.filter(
      (path) => !packedFiles.includes(path)
    );
    throw new Error(
      `package file surface mismatch: missing=${missing.join(",") || "none"} ` +
        `unexpected=${unexpected.join(",") || "none"}`
    );
  }

  const installRoot = await mkdtemp(
    new URL(".package-install-check-", root)
  );
  const installRootUrl = pathToFileURL(`${installRoot}/`);
  let installedRuntimeExports;
  try {
    const { stdout: packedOutput } = await execFileAsync(
      "npm",
      [
        "pack",
        "--json",
        "--ignore-scripts",
        "--pack-destination",
        installRoot
      ],
      {
        cwd: new URL(".", root),
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024
      }
    );
    const packed = JSON.parse(packedOutput);
    const tarball = new URL(packed[0].filename, installRootUrl);
    const consumerRoot = new URL("consumer/", installRootUrl);
    await mkdir(consumerRoot);
    await writeFile(
      new URL("package.json", consumerRoot),
      JSON.stringify({
        name: "crnkl-zk-verifier-package-check",
        private: true,
        type: "module"
      })
    );
    await execFileAsync(
      "npm",
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--package-lock=false",
        tarball.pathname
      ],
      {
        cwd: consumerRoot,
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024
      }
    );
    const expression = [
      `const required=${JSON.stringify(REQUIRED_RUNTIME_EXPORTS)};`,
      "const module = await import('@crnkl/zk-verifier');",
      "const missing = required.filter((name) => typeof module[name] !== 'function');",
      "if (missing.length) throw new Error(`missing installed exports: ${missing.join(',')}`);",
      "console.log(JSON.stringify(required));"
    ].join("");
    const { stdout: importOutput } = await execFileAsync(
      process.execPath,
      ["--input-type=module", "--eval", expression],
      {
        cwd: consumerRoot,
        encoding: "utf8",
        maxBuffer: 1024 * 1024
      }
    );
    installedRuntimeExports = JSON.parse(importOutput);
  } finally {
    await rm(installRoot, { recursive: true, force: true });
  }

  return {
    ok: true,
    name: packResult[0].name,
    version: packResult[0].version,
    filename: packResult[0].filename,
    fileCount: packedFiles.length,
    packageSize: packResult[0].size,
    unpackedSize: packResult[0].unpackedSize,
    requiredRuntimeExports: [...REQUIRED_RUNTIME_EXPORTS],
    installedRuntimeExports
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  console.log(JSON.stringify(await checkPackageContents()));
}
