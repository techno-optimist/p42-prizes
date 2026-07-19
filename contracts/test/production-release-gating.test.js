import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { chmod, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { keccak256, toUtf8Bytes } from "ethers";

import { PRODUCTION_LAUNCH_SLUGS, bindReleaseMode, createProductionReleaseIndex, createProductionReleaseSlate, publishProductionReleaseIndex, publishProductionReleaseSlate, releaseBoardIdentity, runAdmitReleaseReadyCommand, validateProductionBoardEvidence, validateProductionReleaseIndex, validateProductionReleaseSlate, validateProductionSlatePreflight, validateVerifierImageReleaseDossier } from "../scripts/multiboard-ceremony-helper.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const fixture = JSON.parse(readFileSync(resolve(ROOT, "contracts/test/fixtures/multiboard-ceremony-10.json"), "utf8"));
const fixtureProblems = fixture.problems.map((problem, index) => ({ ...problem, problemId: String(index + 1) }));
const canonical = (value) => value === null || typeof value !== "object" ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
const digest = (label) => `sha256:${createHash("sha256").update(label).digest("hex")}`;
const hostSetBundles = Array.from({ length: 4 }, (_, index) => ({
  path: `release/host-set-${index + 1}`,
  hostSetHash: digest(`host-set-${index + 1}`),
}));
const objectiveVerifierArtifact = { contractName: "P42ObjectiveVerifierGateway", deployedBytecode: "0x600160005260206000f3" };
const objectiveVerifierArtifactBytes = Buffer.from(`${JSON.stringify(objectiveVerifierArtifact)}\n`);
const objectiveVerifierRuntimeCodehash = keccak256(objectiveVerifierArtifact.deployedBytecode);
const objectiveVerifierInput = {
  objectiveVerifierArtifactPath: "release/objective-verifier.json",
  objectiveVerifierArtifactBytes,
  objectiveVerifierArtifact,
};
const reseal = (slate) => { const { slateDigest: _, ...body } = slate; return { ...body, slateDigest: digest(canonical(body)) }; };
const syntheticSlate = () => reseal({
  schema: "p42-prizes/production-release-slate/v2", mode: "production", status: "ready",
  generatedAt: "2026-07-11T00:00:00.000Z", sourceCommit: "b".repeat(40),
  imageRegistry: { path: "release/image-registry.json", digest: digest("registry") },
  objectiveVerifier: {
    artifactPath: objectiveVerifierInput.objectiveVerifierArtifactPath,
    artifactDigest: `sha256:${createHash("sha256").update(objectiveVerifierArtifactBytes).digest("hex")}`,
    runtimeCodehash: objectiveVerifierRuntimeCodehash,
    proofsActive: false,
  },
  boards: Array.from({ length: 10 }, (_, index) => ({
    problemId: String(index + 1), problemSlug: PRODUCTION_LAUNCH_SLUGS[index],
    problemPath: `problems/${PRODUCTION_LAUNCH_SLUGS[index]}`, problemPackageDigest: digest(`package-${index}`),
    verifierVersion: "1.0.0", specHash: `0x${createHash("sha256").update(`spec-${index}`).digest("hex")}`,
    verifierSourceDigest: digest(`source-${index}`), verifierImageDigest: digest(`image-${index}`),
    admissionMatrixPath: `release/matrix-${index + 1}.json`, admissionMatrixDigest: digest(`matrix-${index}`),
    objectiveGuestElfPath: `release/objective-program-${index + 1}.bin`,
    objectiveGuestElfDigest: digest(`objective-program-bytes-${index}`),
    objectiveGuestElfSha256: `0x${digest(`objective-program-bytes-${index}`).slice("sha256:".length)}`,
    objectiveProgramVKey: keccak256(toUtf8Bytes(`objective-program-bytes-${index}`)),
  })),
});
const clone = structuredClone;
const imageDossier = (slate) => {
  const verifierSourceCommit = "a".repeat(40);
  const body = {
    schema_version: "p42-verifier-image-release/v3",
    published_at_utc: "2026-07-11T00:00:00Z",
    identity_model: "p42-verifier-source-release-config/v2",
    verifier_source_commit: verifierSourceCommit,
    verifier_source_archive_digest: digest("source-archive"),
    release_config_commit: slate.sourceCommit,
    release_config_archive_digest: digest("release-archive"),
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
          "org.opencontainers.image.revision": verifierSourceCommit,
          "io.projectforty2.verifier.source-sha256": board.verifierSourceDigest,
          "io.projectforty2.verifier.source-algorithm": "p42-source-tree-sha256/v2",
          "io.projectforty2.verifier.problem-id": board.problemSlug,
          "io.projectforty2.verifier.version": board.verifierVersion,
        },
        runtime: { user: "65534:65534", workdir: `/repo/problems/${board.problemSlug}`, entrypoint: null, cmd: [] },
      })),
      release_manifest_path: `problems/${board.problemSlug}/problem.yaml`,
      release_manifest_sha256: digest(`${board.problemSlug}-problem-yaml`),
    })),
    publication_journal_hash: digest("journal"),
  };
  const script = [
    "import importlib.util,json,sys",
    `spec=importlib.util.spec_from_file_location('release_verifier_images',${JSON.stringify(resolve(ROOT, "scripts/release_verifier_images.py"))})`,
    "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)",
    "print(module.canonical_json(module._finalize_dossier(json.load(sys.stdin))))",
  ].join(";");
  return JSON.parse(execFileSync("python3", ["-c", script], {
    cwd: ROOT,
    encoding: "utf8",
    input: JSON.stringify(body),
    env: { ...process.env, PYTHONPATH: resolve(ROOT, "src") },
  }));
};
const publicationJournal = (dossier) => ({
  schema_version: "p42-verifier-image-publish-journal/v3",
  verifier_source_commit: dossier.verifier_source_commit,
  journal_hash: dossier.publication_journal_hash,
});

describe("exact-ten production release slate", () => {
  it("loads the one frozen source-cohort authority", () => {
    const authority = JSON.parse(readFileSync(resolve(ROOT, "protocol/production-board-set-v1.json"), "utf8"));
    assert.equal(authority.schema, "p42-prizes/production-board-set/v1");
    assert.equal(authority.status, "frozen-source-cohort");
    assert.deepEqual(PRODUCTION_LAUNCH_SLUGS, authority.boards);
    const evidenceBytes = readFileSync(resolve(ROOT, authority.evidence.path));
    assert.equal(`sha256:${createHash("sha256").update(evidenceBytes).digest("hex")}`, authority.evidence.sha256);
    const evidenceSchemaBytes = readFileSync(resolve(ROOT, authority.evidence.schema_path));
    assert.equal(`sha256:${createHash("sha256").update(evidenceSchemaBytes).digest("hex")}`, authority.evidence.schema_sha256);
    const evidence = JSON.parse(evidenceBytes);
    assert.equal(validateProductionBoardEvidence(evidence), evidence);
    const missingSources = structuredClone(evidence); delete missingSources.boards[0].sources;
    assert.throws(() => validateProductionBoardEvidence(missingSources), /fails schema validation/);
    const approvedWithoutReview = structuredClone(evidence); approvedWithoutReview.boards[1].funding_review = "APPROVED";
    assert.throws(() => validateProductionBoardEvidence(approvedWithoutReview), /fails schema validation/);
  });

  it("accepts only a status-ready closed ordered ten-board identity", () => {
    const slate = syntheticSlate(); const problems = slate.boards.map((board) => releaseBoardIdentity(board, Number(board.problemId) - 1));
    assert.equal(validateProductionReleaseSlate(slate, problems).slateDigest, slate.slateDigest);
    assert.equal(bindReleaseMode({ problems: fixtureProblems }, { releaseMode: "fixture" }).releaseSlateDigest, null);
    assert.throws(() => bindReleaseMode({ problems: fixtureProblems }, { releaseMode: "production", slate }), /closed release slate/);
  });

  it("rejects an active objective verifier in the current production slate version", () => {
    const slate = syntheticSlate();
    slate.objectiveVerifier.proofsActive = true;
    assert.throws(() => validateProductionReleaseSlate(reseal(slate)), /objective verifier artifact is placeholder, active, or invalid/);
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
      const journalPath = "release/publication-journal.json";
      const journalBytes = Buffer.from(`${canonical(publicationJournal(registry))}\n`);
      await writeFile(join(evidenceRoot, journalPath), journalBytes);
      await chmod(join(evidenceRoot, journalPath), 0o600);
      await writeFile(join(evidenceRoot, slate.objectiveVerifier.artifactPath), objectiveVerifierArtifactBytes);
      await chmod(join(evidenceRoot, slate.objectiveVerifier.artifactPath), 0o600);
      for (const board of slate.boards) {
        await writeFile(join(evidenceRoot, board.admissionMatrixPath), JSON.stringify({ matrix_hash: board.admissionMatrixDigest, problem_id: board.problemSlug, verifier_version: board.verifierVersion, verifier_image: board.verifierImageDigest, source: { tree_hash: board.verifierSourceDigest } }));
        await chmod(join(evidenceRoot, board.admissionMatrixPath), 0o600);
        const programBytes = Buffer.from(`objective-program-bytes-${Number(board.problemId) - 1}`);
        await writeFile(join(evidenceRoot, board.objectiveGuestElfPath), programBytes);
        await chmod(join(evidenceRoot, board.objectiveGuestElfPath), 0o600);
      }
      const ready = reseal(slate); const config = { roles: { objectiveVerifierCodehash: objectiveVerifierRuntimeCodehash }, problems: ready.boards.map(releaseBoardIdentity) };
      const preflightOptions = {
        repoRoot,
        evidenceRoot,
        imageDossierSha256: slate.imageRegistry.digest,
        publicationJournalPath: journalPath,
        publicationJournalSha256: `sha256:${createHash("sha256").update(journalBytes).digest("hex")}`,
        hostSetBundles,
      };
      assert.equal(validateProductionSlatePreflight({}, ready, config, { ...preflightOptions, runAdmitReleaseReady: () => {} }).length, 10);
      assert.throws(
        () => validateProductionSlatePreflight({}, ready, config, { ...preflightOptions, hostSetBundles: undefined, runAdmitReleaseReady: () => {} }),
        /host-set bundles are required/,
      );
      await writeFile(join(evidenceRoot, ready.boards[0].objectiveGuestElfPath), "substituted-program");
      assert.throws(() => validateProductionSlatePreflight({}, ready, config, { ...preflightOptions, runAdmitReleaseReady: () => {} }), /guest ELF digest mismatch/);
      await writeFile(join(evidenceRoot, ready.boards[0].objectiveGuestElfPath), "objective-program-bytes-0");
      await writeFile(join(evidenceRoot, ready.objectiveVerifier.artifactPath), '{"deployedBytecode":"0x6001"}\n');
      assert.throws(() => validateProductionSlatePreflight({}, ready, config, { ...preflightOptions, runAdmitReleaseReady: () => {} }), /objective verifier artifact digest mismatch/);
      const unrelatedGatewayBytes = Buffer.from('{"deployedBytecode":"0x6001"}\n');
      const unrelatedGatewaySlate = structuredClone(ready);
      unrelatedGatewaySlate.objectiveVerifier.artifactDigest = `sha256:${createHash("sha256").update(unrelatedGatewayBytes).digest("hex")}`;
      assert.throws(() => validateProductionSlatePreflight({}, reseal(unrelatedGatewaySlate), config, { ...preflightOptions, runAdmitReleaseReady: () => {} }), /runtime codehash is not derived/);
      await writeFile(join(evidenceRoot, ready.objectiveVerifier.artifactPath), objectiveVerifierArtifactBytes);
      const unrelatedProgramSlate = structuredClone(ready);
      unrelatedProgramSlate.boards[0].objectiveProgramVKey = keccak256(toUtf8Bytes("unrelated-program-id"));
      const unrelatedProgramConfig = structuredClone(config);
      unrelatedProgramConfig.problems[0].objectiveProgramVKey = unrelatedProgramSlate.boards[0].objectiveProgramVKey;
      assert.equal(
        validateProductionSlatePreflight({}, reseal(unrelatedProgramSlate), unrelatedProgramConfig, { ...preflightOptions, runAdmitReleaseReady: () => {} }).length,
        10,
      );
      assert.throws(() => validateProductionSlatePreflight({}, ready, config, { ...preflightOptions, runAdmitReleaseReady: ({ matrixPath }) => { if (matrixPath.endsWith("matrix-10.json")) throw new Error("not certified"); } }), /not certified/);
      assert.equal(validateProductionSlatePreflight({}, ready, config, {
        ...preflightOptions,
        runAdmitReleaseReady: ({ matrixPath, matrixBytes, imageDossierSha256, publicationJournalSha256 }) => {
          assert.ok(matrixBytes.length > 0);
          assert.equal(imageDossierSha256, preflightOptions.imageDossierSha256);
          assert.equal(publicationJournalSha256, preflightOptions.publicationJournalSha256);
          if (matrixPath.endsWith("matrix-10.json")) writeFileSync(matrixPath, JSON.stringify({ forged: true }), { mode: 0o600 });
        },
      }).length, 10);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("binds the slate to the canonical multi-platform image release dossier", () => {
    const slate = syntheticSlate();
    const problems = slate.boards.map(releaseBoardIdentity);
    const dossier = imageDossier(slate);
    assert.equal(validateVerifierImageReleaseDossier(dossier, { releaseCommit: slate.sourceCommit, problems }), dossier);
    assert.throws(
      () => validateVerifierImageReleaseDossier({ schema_version: "p42-verifier-image-release/v1" }),
      /keys mismatch|schema is invalid/,
    );
    const legacy = clone(dossier);
    legacy.schema_version = "p42-verifier-image-release/v2";
    legacy.identity_model = "p42-verifier-source-release-config/v1";
    assert.throws(() => validateVerifierImageReleaseDossier(legacy), /schema is invalid/);
    for (const mutate of [
      (value) => { value.release_config_commit = "c".repeat(40); },
      (value) => { value.boards[0].platform_manifests[0].labels["org.opencontainers.image.revision"] = value.release_config_commit; },
      (value) => { value.boards[2].index_digest = digest("substitute"); },
      (value) => { value.boards[4].platform_manifests[1].labels["io.projectforty2.verifier.version"] = "9.9.9"; },
      (value) => { value.boards[6].platform_manifests.reverse(); },
      (value) => { value.boards[7].repository = "registry.example/p42/verifiers/substitute"; },
      (value) => { value.dossier_hash = digest("forged"); },
    ]) {
      const forged = clone(dossier); mutate(forged);
      assert.throws(() => validateVerifierImageReleaseDossier(forged, { releaseCommit: slate.sourceCommit, problems }), /mismatch|invalid|hash/);
    }
    for (const published_at_utc of ["2026-02-30T00:00:00Z", "2026-07-11T24:00:00Z", "2026-07-13T00:00:00Z"]) {
      const forged = clone(dossier); forged.published_at_utc = published_at_utc;
      const { dossier_hash: _, ...body } = forged; forged.dossier_hash = digest(canonical(body));
      assert.throws(() => validateVerifierImageReleaseDossier(forged, { releaseCommit: slate.sourceCommit, problems, now: Date.parse("2026-07-12T00:00:00Z") }), /timestamp/);
    }
    for (const registry_base of ["registry..example/p42/verifiers", "registry.example/p42//verifiers", "registry.example/p42/verifiers/", `r/${"a".repeat(253)}`]) {
      const forged = clone(dossier); forged.registry_base = registry_base;
      forged.boards.forEach((board) => {
        board.repository = `${registry_base}/${board.slug}`;
        board.immutable_reference = `${board.repository}@${board.index_digest}`;
      });
      const { dossier_hash: _, ...body } = forged; forged.dossier_hash = digest(canonical(body));
      assert.throws(() => validateVerifierImageReleaseDossier(forged, { releaseCommit: slate.sourceCommit, problems }), /registry|canonical identity/);
    }
  });

  it("invokes release-bound admission with every independently pinned input", () => {
    let invocation;
    runAdmitReleaseReadyCommand({
      repoRoot: "/repo",
      problemPath: "/repo/problems/q6-intersecting-hypergraph",
      matrixPath: "/evidence/matrix.json",
      matrixBytes: Buffer.from("{}\n"),
      imageDossierPath: "/evidence/dossier.json",
      imageDossierSha256: digest("dossier-file"),
      publicationJournalPath: "/evidence/journal.json",
      publicationJournalSha256: digest("journal-file"),
      hostSetBundles: hostSetBundles.map((item) => ({ ...item, path: `/evidence/${item.path}` })),
      pythonExecutable: "python-exact",
      run(program, args, options) { invocation = { program, args, options }; },
    });
    assert.equal(invocation.program, "python-exact");
    assert.deepEqual(invocation.args.slice(0, 3), ["-m", "p42_prizes.cli", "admit-release-ready"]);
    assert.equal(invocation.args.includes("admit-ready"), false);
    for (const flag of ["--matrix-stdin", "--image-dossier", "--image-dossier-sha256", "--publication-journal", "--publication-journal-sha256", "--host-set-bundle", "--host-set-hash"]) assert.equal(invocation.args.includes(flag), true);
    assert.equal(invocation.args.filter((value) => value === "--host-set-bundle").length, 4);
    assert.deepEqual(invocation.options.input, Buffer.from("{}\n"));
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
      ...objectiveVerifierInput,
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
      imageDossier: dossier, ...objectiveVerifierInput, problems, now: Date.parse("2026-07-12T00:00:00Z"), ...overrides,
    }), /generatedAt|path|bytes/);
  });

  it("publishes the ready slate immutably at its content address", async () => {
    const source = syntheticSlate();
    const problems = source.boards.map((board) => ({ ...releaseBoardIdentity(board), admissionMatrixPath: board.admissionMatrixPath }));
    const dossier = imageDossier(source); const bytes = Buffer.from(`${canonical(dossier)}\n`);
    const slate = createProductionReleaseSlate({ generatedAt: "2026-07-11T00:00:01Z", sourceCommit: source.sourceCommit, imageRegistryPath: "release/verifier-images.json", imageRegistryBytes: bytes, imageDossier: dossier, ...objectiveVerifierInput, problems, now: Date.parse("2026-07-12T00:00:00Z") });
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
