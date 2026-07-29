PYTHON ?= python3
CARGO ?= $(if $(wildcard $(HOME)/.cargo/bin/cargo),$(HOME)/.cargo/bin/cargo,cargo)
RUST_TOOLCHAIN ?= 1.91.1
PINNED_CARGO = $(CARGO) +$(RUST_TOOLCHAIN)
PYTHONPATH := $(CURDIR)/src
P42_GIT_REMOTE ?= origin
# Per-problem tests invoke `make verify` while the root test target is itself a
# Make recipe. Suppress recursive directory banners so verifier stdout stays a
# single canonical JSON report across GNU Make versions and CI hosts.
MAKEFLAGS += --no-print-directory
PRODUCTION_BOARD_SET ?= protocol/production-board-set-v1.json
BOARD_SET_RESULT := $(shell $(PYTHON) -c 'import hashlib,json,re,sys; d=json.load(open(sys.argv[1])); b=d.get("boards"); e=d.get("evidence"); assert set(d) == {"schema","status","evidence","boards"} and d.get("schema") == "p42-prizes/production-board-set/v1" and d.get("status") == "frozen-source-cohort" and isinstance(b,list) and len(b) == len(set(b)) == 10 and all(isinstance(s,str) and re.fullmatch(r"[a-z0-9][a-z0-9-]*",s) for s in b) and isinstance(e,dict) and set(e) == {"path","sha256","schema_path","schema_sha256"} and e.get("path") == "docs/provenance/production-board-evidence-v1.json" and e.get("schema_path") == "schemas/production-board-evidence.schema.json" and e.get("sha256") == "sha256:" + hashlib.sha256(open(e["path"],"rb").read()).hexdigest() and e.get("schema_sha256") == "sha256:" + hashlib.sha256(open(e["schema_path"],"rb").read()).hexdigest(); print(" ".join(b))' "$(PRODUCTION_BOARD_SET)" 2>/dev/null || printf '__P42_INVALID_BOARD_SET__')
ifneq ($(filter __P42_INVALID_BOARD_SET__,$(BOARD_SET_RESULT)),)
$(error invalid canonical production board set: $(PRODUCTION_BOARD_SET))
endif
LAUNCH_SLUGS := $(BOARD_SET_RESULT)
LAUNCH_PROBLEMS := $(addprefix problems/,$(LAUNCH_SLUGS))
RESEARCH_PROBLEMS := problems/hadamard-mini problems/signed-autoconvolution-c3-upper problems/b3-ruler-11-marks problems/b3-subset-first-jump-9 problems/edp-c3-longest-sequence problems/c4-star-ramsey-a17 problems/hypercube-q7-c4-free
PROBLEMS := $(LAUNCH_PROBLEMS) $(RESEARCH_PROBLEMS)

.PHONY: install-verifier-deps test validate validate-source-release-evidence verify-production-board-bindings refresh-production-board-bindings verify-source-release-evidence-online capture-sp1-runtime-evidence verify-sp1-runtime-evidence test-sp1-runtime-attestation lint verify-seed verify-open-witness-release verify-hadamard-seed verify-erdos-seed verify-edges-seed verify-arithmetic-kakeya-seed verify-autoconvolution-c1-seed verify-autoconvolution-c2-seed verify-signed-c3-seed verify-mertens-k12000-seed verify-pnt-sparse-seed verify-hadamard-668-seed admit-host-seed admit-host-ten-board admit-host-q6 admit-host-distinct-subset-sums admit-host-erdos admit-host-edges admit-host-arithmetic-kakeya admit-host-autoconvolution-c1 admit-host-autoconvolution-c2 admit-host-signed-c3 admit-host-mertens-k12000 admit-host-pnt-sparse admit-host-hadamard-668 contracts-test node-gates web-static-gates local-source-gates objective-core-test candidate-objective-python-gates candidate-objective-host-gates candidate-objective-program-gates objective-program-gates objective-dependency-security-gate objective-dependency-security-posture reproduce-sp1-challenger-collision verify-sp1-objective-artifact verify-sp1-objective-resource-profile verify-render-release all

# Historical Python/verifier aggregate. Use local-source-gates for the complete
# non-network source regression surface.
all: validate lint test verify-seed

install-verifier-deps:
	@PIP_DISABLE_PIP_VERSION_CHECK=1 $(PYTHON) -m pip install --require-hashes -r requirements.runtime.lock
	@for requirements in $(PROBLEMS:%=%/requirements.lock); do \
		PIP_DISABLE_PIP_VERSION_CHECK=1 $(PYTHON) -m pip install --require-hashes -r $$requirements || exit $$?; \
	done

validate: validate-source-release-evidence
	@for problem in $(PROBLEMS); do \
		PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli validate --problem $$problem || exit $$?; \
	done

validate-source-release-evidence:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli source-release-evidence-validate \
		--report docs/evidence/source-release-current.json \
		--repo-root . >/dev/null

verify-production-board-bindings:
	@PYTHONPATH=$(PYTHONPATH):$(CURDIR) $(PYTHON) scripts/verify_production_board_bindings.py

refresh-production-board-bindings:
	@PYTHONPATH=$(PYTHONPATH):$(CURDIR) $(PYTHON) scripts/verify_production_board_bindings.py --refresh-source-digests

verify-source-release-evidence-online:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli source-release-evidence-validate \
		--report docs/evidence/source-release-current.json \
		--repo-root . --online >/dev/null

capture-sp1-runtime-evidence:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.sp1_runtime_attestation capture \
		--output docs/evidence/sp1-external-runtime-current.json

verify-sp1-runtime-evidence:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.sp1_runtime_attestation verify \
		--evidence docs/evidence/sp1-external-runtime-current.json

test-sp1-runtime-attestation:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q tests/test_sp1_runtime_attestation.py

lint:
	@for problem in $(PROBLEMS); do \
		PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli lint --problem $$problem || exit $$?; \
	done

test: install-verifier-deps
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q

verify-seed: install-verifier-deps
	@PYTHONPATH=$(PYTHONPATH):$(CURDIR) $(PYTHON) scripts/verify_production_board_bindings.py
	@status=0; \
	for problem in $(PROBLEMS); do \
		$(MAKE) -C $$problem verify-seed || status=1; \
		sleep 1; \
	done; \
	exit $$status

verify-open-witness-release: install-verifier-deps
	@status=0; \
	for problem in $(PROBLEMS); do \
		$(MAKE) -C $$problem verify-open-witness || status=1; \
		sleep 1; \
	done; \
	exit $$status

verify-hadamard-seed:
	@$(MAKE) -C problems/hadamard-mini verify-seed

verify-erdos-seed:
	@$(MAKE) -C problems/erdos-min-overlap verify-seed

verify-edges-seed:
	@$(MAKE) -C problems/edges-vs-triangles verify-seed

verify-arithmetic-kakeya-seed:
	@$(MAKE) -C problems/arithmetic-kakeya verify-seed

verify-autoconvolution-c1-seed:
	@$(MAKE) -C problems/autoconvolution-c1-upper verify-seed

verify-autoconvolution-c2-seed:
	@$(MAKE) -C problems/autoconvolution-c2-lower verify-seed

verify-signed-c3-seed:
	@$(MAKE) -C problems/signed-autoconvolution-c3-upper verify-seed

verify-mertens-k12000-seed:
	@$(MAKE) -C problems/mertens-lp-ceiling-k12000 verify-seed

verify-pnt-sparse-seed:
	@$(MAKE) -C problems/pnt-sparse-mertens-construction verify-seed

verify-hadamard-668-seed:
	@$(MAKE) -C problems/hadamard-668-defect verify-seed

admit-host-seed:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/hadamard-mini \
		--solution problems/hadamard-mini/examples/valid-4.json \
		--runs 2

admit-host-ten-board:
	@status=0; \
	for target in admit-host-q6 admit-host-erdos admit-host-edges admit-host-arithmetic-kakeya admit-host-autoconvolution-c1 admit-host-autoconvolution-c2 admit-host-distinct-subset-sums admit-host-mertens-k12000 admit-host-pnt-sparse admit-host-hadamard-668; do \
		$(MAKE) $$target || status=1; \
		sleep 1; \
	done; \
	exit $$status

admit-host-q6:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/q6-intersecting-hypergraph \
		--solution problems/q6-intersecting-hypergraph/tests/seed-pg25.json \
		--runs 2

admit-host-distinct-subset-sums:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/distinct-subset-sums-a11 \
		--solution problems/distinct-subset-sums-a11/tests/conway-guy-594.json \
		--runs 2

admit-host-erdos:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/erdos-min-overlap \
		--solution problems/erdos-min-overlap/examples/hyra-upper.json \
		--runs 2

admit-host-edges:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/edges-vs-triangles \
		--solution problems/edges-vs-triangles/examples/rational-curve-sample.json \
		--runs 2

admit-host-arithmetic-kakeya:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/arithmetic-kakeya \
		--solution problems/arithmetic-kakeya/examples/kt-2x2-forcing.json \
		--runs 2

admit-host-autoconvolution-c1:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/autoconvolution-c1-upper \
		--solution problems/autoconvolution-c1-upper/examples/hyra-upper.json \
		--runs 2

admit-host-autoconvolution-c2:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/autoconvolution-c2-lower \
		--solution problems/autoconvolution-c2-lower/examples/hyra-lower.json \
		--runs 2

admit-host-signed-c3:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/signed-autoconvolution-c3-upper \
		--solution problems/signed-autoconvolution-c3-upper/examples/organon-upper.json \
		--runs 2

admit-host-mertens-k12000:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/mertens-lp-ceiling-k12000 \
		--solution problems/mertens-lp-ceiling-k12000/examples/certificate-k12000.json \
		--runs 2

admit-host-pnt-sparse:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/pnt-sparse-mertens-construction \
		--solution problems/pnt-sparse-mertens-construction/examples/chronos-96000.json \
		--runs 2

admit-host-hadamard-668:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/hadamard-668-defect \
		--solution problems/hadamard-668-defect/examples/sylvester-prefix.json \
		--runs 2

contracts-test:
	@npm ci
	@npm run contracts:build
	@npm run contracts:test
	@npm run audit

node-gates:
	@npm ci
	@npm run contracts:build
	@npm run contracts:test
	@npm run agent:test
	@npm run audit

web-static-gates:
	@bash scripts/run-local-web-static-gates.sh

# Necessary source evidence only. This excludes hosted dual-Linux SP1 builds,
# PostgreSQL integrations, live chain/RPC evidence, and external attestations.
# Funding eligibility additionally requires objective-dependency-security-gate
# and every published Gate 1/2 artifact.
local-source-gates: all node-gates web-static-gates objective-core-test candidate-objective-host-gates objective-dependency-security-posture

objective-core-test:
	@$(PINNED_CARGO) --version | grep -q '^cargo 1\.91\.1 '
	@cd objective-programs && $(PINNED_CARGO) test --locked -p p42-objective-core

candidate-objective-python-gates:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q \
		problems/q6-intersecting-hypergraph/tests/test_q6_intersecting_hypergraph.py \
		problems/arithmetic-kakeya/tests/test_arithmetic_kakeya.py \
		tests/test_arithmetic_kakeya_sp1_differential.py \
		tests/test_edges_sp1_differential.py \
		tests/test_sp1_host_observation.py \
		tests/test_sp1_objective_reproduction.py
	@$(PYTHON) objective-programs/erdos-min-overlap/objective-shared/tests/test_python_authority.py \
		--canonical-root . --source-mode current

candidate-objective-program-gates: candidate-objective-python-gates
	@CARGO="$(CARGO)" RUST_TOOLCHAIN="$(RUST_TOOLCHAIN)" bash scripts/verify-candidate-objective-programs.sh

# Non-authorizing native-host execution. The strict target above retains the
# canonical x86 Q6 transcript and remains part of objective-program-gates.
candidate-objective-host-gates: candidate-objective-python-gates
	@CARGO="$(CARGO)" RUST_TOOLCHAIN="$(RUST_TOOLCHAIN)" bash scripts/verify-candidate-objective-programs.sh --host-observation

objective-program-gates: objective-core-test \
	candidate-objective-program-gates \
	verify-sp1-objective-artifact \
	verify-sp1-a11-objective-artifact \
	verify-sp1-objective-resource-profile

# Activation gate. It intentionally fails while an objective lockfile retains
# a known vulnerable proof-system dependency.
objective-dependency-security-gate:
	@$(PYTHON) scripts/check_sp1_dependency_security.py --report docs/evidence/sp1-dependency-security-current.json

objective-dependency-security-posture:
	@$(PYTHON) scripts/check_sp1_dependency_security.py \
		--report docs/evidence/sp1-dependency-security-current.json \
		--expect blocked

reproduce-sp1-challenger-collision:
	@cd security/reproducers/sp1-v610-challenger-transcript-collision && \
		$(PINNED_CARGO) run --locked
	@cd security/reproducers/sp1-challenger-transcript-collision && \
		$(PINNED_CARGO) run --locked

verify-sp1-objective-artifact:
	@test -n "$(P42_CARGO_PROVE)" || (echo "P42_CARGO_PROVE must name the pinned SP1 v6.1 cargo-prove binary" >&2; exit 2)
	@$(PYTHON) scripts/verify-sp1-objective-artifact.py --cargo-prove "$(P42_CARGO_PROVE)"

verify-sp1-a11-objective-artifact:
	@test -n "$(P42_CARGO_PROVE)" || (echo "P42_CARGO_PROVE must name the pinned SP1 v6.1 cargo-prove binary" >&2; exit 2)
	@$(PYTHON) scripts/verify-sp1-a11-objective-artifact.py --cargo-prove "$(P42_CARGO_PROVE)"

verify-sp1-objective-resource-profile:
	@$(PYTHON) scripts/verify-sp1-objective-resource-profile.py

verify-render-release:
	@node scripts/verify-render-release.mjs --git-remote "$(P42_GIT_REMOTE)"
