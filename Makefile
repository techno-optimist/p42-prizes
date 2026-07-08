PYTHON ?= python3
PYTHONPATH := $(CURDIR)/src
PROBLEMS := problems/hadamard-mini problems/erdos-min-overlap problems/arithmetic-kakeya problems/autoconvolution-c2-lower problems/signed-autoconvolution-c3-upper problems/mertens-lp-ceiling-k12000

.PHONY: test validate lint verify-seed verify-hadamard-seed verify-erdos-seed verify-arithmetic-kakeya-seed verify-autoconvolution-c2-seed verify-signed-c3-seed verify-mertens-k12000-seed admit-host-seed admit-host-erdos admit-host-arithmetic-kakeya admit-host-autoconvolution-c2 admit-host-signed-c3 admit-host-mertens-k12000 contracts-test all

all: validate lint test verify-seed

validate:
	@for problem in $(PROBLEMS); do \
		PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli validate --problem $$problem || exit $$?; \
	done

lint:
	@for problem in $(PROBLEMS); do \
		PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli lint --problem $$problem || exit $$?; \
	done

test:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q

verify-seed: verify-hadamard-seed verify-erdos-seed verify-arithmetic-kakeya-seed verify-autoconvolution-c2-seed verify-signed-c3-seed verify-mertens-k12000-seed

verify-hadamard-seed:
	@$(MAKE) -C problems/hadamard-mini verify

verify-erdos-seed:
	@$(MAKE) -C problems/erdos-min-overlap verify

verify-arithmetic-kakeya-seed:
	@$(MAKE) -C problems/arithmetic-kakeya verify

verify-autoconvolution-c2-seed:
	@$(MAKE) -C problems/autoconvolution-c2-lower verify

verify-signed-c3-seed:
	@$(MAKE) -C problems/signed-autoconvolution-c3-upper verify

verify-mertens-k12000-seed:
	@$(MAKE) -C problems/mertens-lp-ceiling-k12000 verify

admit-host-seed:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/hadamard-mini \
		--solution problems/hadamard-mini/examples/valid-4.json \
		--runs 2

admit-host-erdos:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/erdos-min-overlap \
		--solution problems/erdos-min-overlap/examples/hyra-upper.json \
		--runs 2

admit-host-arithmetic-kakeya:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/arithmetic-kakeya \
		--solution problems/arithmetic-kakeya/examples/kt-2x2-forcing.json \
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

contracts-test:
	@cd contracts && npm run build && npm run test && npm audit --audit-level=moderate
