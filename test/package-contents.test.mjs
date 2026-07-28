import assert from "node:assert/strict";
import { test } from "node:test";

import { checkPackageContents } from "../scripts/check-package-contents.mjs";

test("installable package has one locked runtime and legal surface", async () => {
  const result = await checkPackageContents();

  assert.equal(result.ok, true);
  assert.equal(result.name, "@crnkl/zk-verifier");
  assert.equal(result.version, "0.1.0-alpha.0");
  assert.equal(result.fileCount, 13);
  assert.ok(result.packageSize > 0);
  assert.ok(result.unpackedSize > result.packageSize);
  assert.deepEqual(result.requiredRuntimeExports, [
    "claimCampaignProofJobAuthorizationGrantV1",
    "createCampaignProofJobAuthorizer",
    "hashCampaignProofJobAuthorizationGrantV1",
    "hashCampaignServerProvedCompletionPackageV1",
    "verifyCampaignServerProvedCompletionV1"
  ]);
  assert.deepEqual(
    result.installedRuntimeExports,
    result.requiredRuntimeExports
  );
});
