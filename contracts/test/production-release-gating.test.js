import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { PRODUCTION_LAUNCH_SLUGS, bindReleaseMode, releaseBoardIdentity, validateProductionReleaseSlate, validateProductionSlatePreflight, validateVerifierImageReleaseDossier } from "../scripts/multiboard-ceremony-helper.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const fixture = JSON.parse(readFileSync(resolve(ROOT, "contracts/test/fixtures/multiboard-ceremony-10.json"), "utf8"));
const fixtureProblems = fixture.problems.map((problem, index) => ({ ...problem, problemId: String(index + 1) }));
const canonical = (value) => value === null || typeof value !== "object" ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
const digest = (label) => `sha256:${createHash("sha256").update(label).digest("hex")}`;
const reseal = (slate) => { const { slateDigest: _, ...body } = slate; return { ...body, slateDigest: digest(canonical(body)) }; };
const syntheticSlate = () => reseal({
  schema: "p42-prizes/production-release-slate/v1", mode: "production", status: "ready",
  generatedAt: "2026-07-11T00:00:00.000Z", sourceCommit: "b".repeat(40),
  imageRegistry: { path: "release/image-registry.json", digest: digest("registry") },
  boards: Array.from({ length: 10 }, (_, index) => ({
    problemId: String(index + 1), problemSlug: PRODUCTION_LAUNCH_SLUGS[index],
    problemPath: `problems/${PRODUCTION_LAUNCH_SLUGS[index]}`, problemPackageDigest: digest(`package-${index}`),
    verifierVersion: "1.0.0", specHash: `0x${createHash("sha256").update(`spec-${index}`).digest("hex")}`,
    verifierSourceDigest: digest(`source-${index}`), verifierImageDigest: digest(`image-${index}`),
    admissionMatrixPath: `release/matrix-${index + 1}.json`, admissionMatrixDigest: digest(`matrix-${index}`),
  })),
});
const clone = structuredClone;
const imageDossier = (slate) => {
  const body = {
    schema_version: "p42-verifier-image-release/v1",
    published_at_utc: "2026-07-11T00:00:00Z",
    source_commit: slate.sourceCommit,
    source_archive_digest: digest("archive"),
    registry_base: "registry.example/p42/verifiers",
    platforms: ["linux/amd64", "linux/arm64"],
    boards: slate.boards.map((board) => ({
      slug: board.problemSlug,
      problem_id: board.problemSlug,
      version: board.verifierVersion,
      source_hash: board.verifierSourceDigest,
      repository: `registry.example/p42/verifiers/${board.problemSlug}`,
      index_digest: board.verifierImageDigest,
      immutable_reference: `registry.example/p42/verifiers/${board.problemSlug}@${board.verifierImageDigest}`,
      platform_manifests: ["linux/amd64", "linux/arm64"].map((platform, index) => ({
        platform,
        manifest_digest: digest(`${board.problemSlug}-manifest-${index}`),
        manifest_size: 100 + index,
        config_digest: digest(`${board.problemSlug}-config-${index}`),
        config_size: 200 + index,
        layer_count: 1,
        labels: {
          "org.opencontainers.image.revision": slate.sourceCommit,
          "io.projectforty2.verifier.source-sha256": board.verifierSourceDigest,
          "io.projectforty2.verifier.source-algorithm": "p42-source-tree-sha256/v2",
          "io.projectforty2.verifier.problem-id": board.problemSlug,
          "io.projectforty2.verifier.version": board.verifierVersion,
        },
        runtime: { user: "65534:65534", workdir: `/repo/problems/${board.problemSlug}`, entrypoint: null, cmd: [] },
      })),
    })),
    manifest_mutation: "none",
    publication_journal_hash: digest("journal"),
  };
  return { ...body, dossier_hash: digest(canonical(body)) };
};

describe("exact-ten production release slate", () => {
  it("accepts only a status-ready closed ordered ten-board identity", () => {
    const slate = syntheticSlate(); const problems = slate.boards.map((board) => releaseBoardIdentity(board, Number(board.problemId) - 1));
    assert.equal(validateProductionReleaseSlate(slate, problems).slateDigest, slate.slateDigest);
    assert.equal(bindReleaseMode({ problems: fixtureProblems }, { releaseMode: "fixture" }).releaseSlateDigest, null);
    assert.throws(() => bindReleaseMode({ problems: fixtureProblems }, { releaseMode: "production", slate }), /closed release slate/);
  });

  for (const count of [0, 1, 9, 11]) it(`rejects production cardinality ${count}`, () => {
    const slate = syntheticSlate(); const problems = slate.boards.slice(0, count).map(releaseBoardIdentity);
    if (count === 11) problems.push({ ...problems[9], problemId: "11" });
    assert.throws(() => validateProductionReleaseSlate(slate, problems), /exactly 10/);
  });

  for (const [name, mutate] of [
    ["reordered", (value) => [value[1], value[0], ...value.slice(2)]],
    ["substituted", (value) => value.map((item, i) => i === 4 ? { ...item, problemSlug: "substitute" } : item)],
    ["duplicated", (value) => value.map((item, i) => i === 4 ? { ...value[3], problemId: "5" } : item)],
  ]) it(`rejects a ${name} board identity`, () => {
    const slate = syntheticSlate(); const problems = slate.boards.map(releaseBoardIdentity);
    assert.throws(() => validateProductionReleaseSlate(slate, mutate(clone(problems))), /closed release slate/);
  });

  it("rejects forged, non-ready, placeholder, and repeated provenance", () => {
    for (const mutate of [
      (s) => { s.slateDigest = digest("forged"); },
      (s) => { s.status = "draft"; return reseal(s); },
      (s) => { s.boards[0].verifierImageDigest = `sha256:${"0".repeat(64)}`; return reseal(s); },
      (s) => { s.boards[1].admissionMatrixDigest = s.boards[0].admissionMatrixDigest; return reseal(s); },
    ]) { let slate = syntheticSlate(); slate = mutate(slate) ?? slate; assert.throws(() => validateProductionReleaseSlate(slate), /digest|ready|placeholder|distinct/); }
  });

  it("preflights only temp status-ready registry, package, and certified matrix evidence", async () => {
    const root = await mkdtemp(join(tmpdir(), "p42-production-slate-"));
    try {
      const slate = syntheticSlate();
      slate.boards.forEach((board) => { board.problemPackageDigest = board.verifierSourceDigest; });
      await mkdir(join(root, "release"), { recursive: true });
      const registry = imageDossier(slate);
      const registryBytes = Buffer.from(JSON.stringify(registry));
      await writeFile(join(root, slate.imageRegistry.path), registryBytes);
      slate.imageRegistry.digest = `sha256:${createHash("sha256").update(registryBytes).digest("hex")}`;
      for (const board of slate.boards) {
        await writeFile(join(root, board.admissionMatrixPath), JSON.stringify({ matrix_hash: board.admissionMatrixDigest, problem_id: board.problemSlug, verifier_version: board.verifierVersion, verifier_image: board.verifierImageDigest, source: { tree_hash: board.verifierSourceDigest } }));
      }
      const ready = reseal(slate); const config = { problems: ready.boards.map(releaseBoardIdentity) };
      assert.equal(validateProductionSlatePreflight({}, ready, config, { repoRoot: root, runAdmitReady: () => {} }).length, 10);
      assert.throws(() => validateProductionSlatePreflight({}, ready, config, { repoRoot: root, runAdmitReady: ({ matrixPath }) => { if (matrixPath.endsWith("matrix-10.json")) throw new Error("not certified"); } }), /not certified/);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("binds the slate to the canonical multi-platform image release dossier", () => {
    const slate = syntheticSlate();
    const problems = slate.boards.map(releaseBoardIdentity);
    const dossier = imageDossier(slate);
    assert.equal(validateVerifierImageReleaseDossier(dossier, { sourceCommit: slate.sourceCommit, problems }), dossier);
    for (const mutate of [
      (value) => { value.source_commit = "c".repeat(40); },
      (value) => { value.boards[2].index_digest = digest("substitute"); },
      (value) => { value.boards[4].platform_manifests[1].labels["io.projectforty2.verifier.version"] = "9.9.9"; },
      (value) => { value.boards[6].platform_manifests.reverse(); },
      (value) => { value.boards[7].repository = "registry.example/p42/verifiers/substitute"; },
      (value) => { value.dossier_hash = digest("forged"); },
    ]) {
      const forged = clone(dossier); mutate(forged);
      assert.throws(() => validateVerifierImageReleaseDossier(forged, { sourceCommit: slate.sourceCommit, problems }), /mismatch|invalid|hash/);
    }
    for (const published_at_utc of ["2026-02-30T00:00:00Z", "2026-07-11T24:00:00Z", "2026-07-13T00:00:00Z"]) {
      const forged = clone(dossier); forged.published_at_utc = published_at_utc;
      const { dossier_hash: _, ...body } = forged; forged.dossier_hash = digest(canonical(body));
      assert.throws(() => validateVerifierImageReleaseDossier(forged, { sourceCommit: slate.sourceCommit, problems, now: Date.parse("2026-07-12T00:00:00Z") }), /timestamp/);
    }
    for (const registry_base of ["registry..example/p42/verifiers", "registry.example/p42//verifiers", "registry.example/p42/verifiers/", `r/${"a".repeat(253)}`]) {
      const forged = clone(dossier); forged.registry_base = registry_base;
      forged.boards.forEach((board) => {
        board.repository = `${registry_base}/${board.slug}`;
        board.immutable_reference = `${board.repository}@${board.index_digest}`;
      });
      const { dossier_hash: _, ...body } = forged; forged.dossier_hash = digest(canonical(body));
      assert.throws(() => validateVerifierImageReleaseDossier(forged, { sourceCommit: slate.sourceCommit, problems }), /registry|canonical identity/);
    }
  });
});
