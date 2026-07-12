import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { chmod, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { PRODUCTION_LAUNCH_SLUGS, bindReleaseMode, createProductionReleaseIndex, createProductionReleaseSlate, publishProductionReleaseIndex, publishProductionReleaseSlate, releaseBoardIdentity, validateProductionReleaseIndex, validateProductionReleaseSlate, validateProductionSlatePreflight, validateVerifierImageReleaseDossier } from "../scripts/multiboard-ceremony-helper.js";

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
      const repoRoot = join(root, "repo"); const evidenceRoot = join(root, "evidence");
      await mkdir(repoRoot); await mkdir(evidenceRoot);
      const slate = syntheticSlate();
      slate.boards.forEach((board) => { board.problemPackageDigest = board.verifierSourceDigest; });
      await mkdir(join(evidenceRoot, "release"), { recursive: true });
      const registry = imageDossier(slate);
      const registryBytes = Buffer.from(`${canonical(registry)}\n`);
      await writeFile(join(evidenceRoot, slate.imageRegistry.path), registryBytes);
      await chmod(join(evidenceRoot, slate.imageRegistry.path), 0o600);
      slate.imageRegistry.digest = `sha256:${createHash("sha256").update(registryBytes).digest("hex")}`;
      for (const board of slate.boards) {
        await writeFile(join(evidenceRoot, board.admissionMatrixPath), JSON.stringify({ matrix_hash: board.admissionMatrixDigest, problem_id: board.problemSlug, verifier_version: board.verifierVersion, verifier_image: board.verifierImageDigest, source: { tree_hash: board.verifierSourceDigest } }));
      }
      const ready = reseal(slate); const config = { problems: ready.boards.map(releaseBoardIdentity) };
      assert.equal(validateProductionSlatePreflight({}, ready, config, { repoRoot, evidenceRoot, runAdmitReady: () => {} }).length, 10);
      assert.throws(() => validateProductionSlatePreflight({}, ready, config, { repoRoot, evidenceRoot, runAdmitReady: ({ matrixPath }) => { if (matrixPath.endsWith("matrix-10.json")) throw new Error("not certified"); } }), /not certified/);
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

  it("constructs a ready slate only from exact image bytes and ceremony identities", () => {
    const source = syntheticSlate();
    const problems = source.boards.map((board) => ({ ...releaseBoardIdentity(board), admissionMatrixPath: board.admissionMatrixPath }));
    const dossier = imageDossier(source);
    const bytes = Buffer.from(`${canonical(dossier)}\n`);
    const slate = createProductionReleaseSlate({
      generatedAt: "2026-07-11T00:00:01Z",
      sourceCommit: source.sourceCommit,
      imageRegistryPath: "release/verifier-images.json",
      imageRegistryBytes: bytes,
      imageDossier: dossier,
      problems,
      now: Date.parse("2026-07-12T00:00:00Z"),
    });
    assert.equal(slate.status, "ready");
    assert.equal(slate.imageRegistry.digest, `sha256:${createHash("sha256").update(bytes).digest("hex")}`);
    assert.deepEqual(slate.boards.map(({ problemSlug }) => problemSlug), PRODUCTION_LAUNCH_SLUGS);
    for (const overrides of [
      { generatedAt: "2026-07-10T23:59:59Z" },
      { generatedAt: "2026-07-13T00:00:00Z" },
      { generatedAt: "2026-07-11T00:00:01.000Z" },
      { imageRegistryPath: "../escape.json" },
      { imageRegistryBytes: "not bytes" },
    ]) assert.throws(() => createProductionReleaseSlate({
      generatedAt: "2026-07-11T00:00:01Z", sourceCommit: source.sourceCommit,
      imageRegistryPath: "release/verifier-images.json", imageRegistryBytes: bytes,
      imageDossier: dossier, problems, now: Date.parse("2026-07-12T00:00:00Z"), ...overrides,
    }), /generatedAt|path|bytes/);
  });

  it("publishes the ready slate immutably at its content address", async () => {
    const source = syntheticSlate();
    const problems = source.boards.map((board) => ({ ...releaseBoardIdentity(board), admissionMatrixPath: board.admissionMatrixPath }));
    const dossier = imageDossier(source); const bytes = Buffer.from(`${canonical(dossier)}\n`);
    const slate = createProductionReleaseSlate({ generatedAt: "2026-07-11T00:00:01Z", sourceCommit: source.sourceCommit, imageRegistryPath: "release/verifier-images.json", imageRegistryBytes: bytes, imageDossier: dossier, problems, now: Date.parse("2026-07-12T00:00:00Z") });
    const directory = await mkdtemp(join(tmpdir(), "p42-production-slate-publish-"));
    try {
      const first = await publishProductionReleaseSlate(slate, directory, { trustedRoot: directory });
      const second = await publishProductionReleaseSlate(slate, directory, { trustedRoot: directory });
      assert.deepEqual(first, second);
      assert.equal((await readFile(first.path, "utf8")), `${canonical(slate)}\n`);
      const linkedDirectory = join(directory, "linked"); await mkdir(linkedDirectory);
      const target = join(linkedDirectory, `${slate.slateDigest.slice(7)}.slate.json`);
      await symlink("missing", target);
      await assert.rejects(() => publishProductionReleaseSlate(slate, linkedDirectory, { trustedRoot: directory }), /ELOOP|metadata|different bytes|regular/i);
      const mutationDirectory = join(directory, "mutation"); await mkdir(mutationDirectory);
      await assert.rejects(() => publishProductionReleaseSlate(slate, mutationDirectory, {
        trustedRoot: directory,
        async beforeDirectoryFsync({ target: publishedTarget, bytes: publishedBytes }) {
          await chmod(publishedTarget, 0o644);
          const changed = Buffer.from(publishedBytes); changed[0] ^= 1;
          await writeFile(publishedTarget, changed);
          await chmod(publishedTarget, 0o444);
        },
      }), /bytes changed/);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("publishes a final index only for an exact capsule/slate pair", async () => {
    const capsule = { digest: digest("capsule"), uri: `sha256://${digest("capsule").slice(7)}` };
    const slate = { digest: digest("slate"), uri: `sha256://${digest("slate").slice(7)}` };
    const index = createProductionReleaseIndex({ sourceCommit: "b".repeat(40), generatedAt: "2026-07-11T00:00:01Z", capsule, slate });
    assert.equal(validateProductionReleaseIndex(index), index);
    assert.throws(() => createProductionReleaseIndex({ sourceCommit: "b".repeat(40), generatedAt: "2026-07-11T00:00:01.000Z", capsule, slate }), /noncanonical/);
    const directory = await mkdtemp(join(tmpdir(), "p42-production-index-publish-"));
    try {
      const first = await publishProductionReleaseIndex(index, directory, { trustedRoot: directory });
      const second = await publishProductionReleaseIndex(index, directory, { trustedRoot: directory });
      assert.deepEqual(first, second);
      assert.equal(await readFile(first.path, "utf8"), `${canonical(index)}\n`);
      const forged = clone(index); forged.slate.digest = digest("substitute");
      assert.throws(() => validateProductionReleaseIndex(forged), /publication|uri|digest/);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});
