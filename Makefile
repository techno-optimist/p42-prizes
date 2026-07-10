PYTHON ?= python3
PYTHONPATH := $(CURDIR)/src
P42_GIT_REMOTE ?= origin
# Per-problem tests invoke `make verify` while the root test target is itself a
# Make recipe. Suppress recursive directory banners so verifier stdout stays a
# single canonical JSON report across GNU Make versions and CI hosts.
MAKEFLAGS += --no-print-directory
PROBLEMS := problems/hadamard-mini problems/erdos-min-overlap problems/edges-vs-triangles problems/arithmetic-kakeya problems/autoconvolution-c1-upper problems/autoconvolution-c2-lower problems/signed-autoconvolution-c3-upper problems/mertens-lp-ceiling-k12000 problems/pnt-sparse-mertens-construction problems/hadamard-668-defect

.PHONY: install-verifier-deps test validate lint verify-seed verify-open-witness-release verify-hadamard-seed verify-erdos-seed verify-edges-seed verify-arithmetic-kakeya-seed verify-autoconvolution-c1-seed verify-autoconvolution-c2-seed verify-signed-c3-seed verify-mertens-k12000-seed verify-pnt-sparse-seed verify-hadamard-668-seed admit-host-seed admit-host-ten-board admit-host-erdos admit-host-edges admit-host-arithmetic-kakeya admit-host-autoconvolution-c1 admit-host-autoconvolution-c2 admit-host-signed-c3 admit-host-mertens-k12000 admit-host-pnt-sparse admit-host-hadamard-668 contracts-test verify-render-release all

all: validate lint test verify-seed

install-verifier-deps:
	@for requirements in $(PROBLEMS:%=%/requirements.lock); do \
		PIP_DISABLE_PIP_VERSION_CHECK=1 $(PYTHON) -m pip install --require-hashes -r $$requirements || exit $$?; \
	done

validate:
	@for problem in $(PROBLEMS); do \
		PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli validate --problem $$problem || exit $$?; \
	done

lint:
	@for problem in $(PROBLEMS); do \
		PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli lint --problem $$problem || exit $$?; \
	done

test: install-verifier-deps
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q

verify-seed: install-verifier-deps
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
	for target in admit-host-seed admit-host-erdos admit-host-edges admit-host-arithmetic-kakeya admit-host-autoconvolution-c1 admit-host-autoconvolution-c2 admit-host-signed-c3 admit-host-mertens-k12000 admit-host-pnt-sparse admit-host-hadamard-668; do \
		$(MAKE) $$target || status=1; \
		sleep 1; \
	done; \
	exit $$status

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
	@cd contracts && npm run build && npm run test && npm audit --audit-level=moderate

verify-render-release:
	@node scripts/verify-render-release.mjs --git-remote "$(P42_GIT_REMOTE)"
