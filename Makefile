PYTHON ?= python3
PYTHONPATH := $(CURDIR)/src
PROBLEMS := problems/hadamard-mini problems/erdos-min-overlap problems/signed-autoconvolution-c3-upper

.PHONY: test validate lint verify-seed verify-hadamard-seed verify-erdos-seed verify-signed-c3-seed admit-host-seed admit-host-erdos admit-host-signed-c3 contracts-test all

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

verify-seed: verify-hadamard-seed verify-erdos-seed verify-signed-c3-seed

verify-hadamard-seed:
	@$(MAKE) -C problems/hadamard-mini verify

verify-erdos-seed:
	@$(MAKE) -C problems/erdos-min-overlap verify

verify-signed-c3-seed:
	@$(MAKE) -C problems/signed-autoconvolution-c3-upper verify

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

admit-host-signed-c3:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/signed-autoconvolution-c3-upper \
		--solution problems/signed-autoconvolution-c3-upper/examples/organon-upper.json \
		--runs 2

contracts-test:
	@cd contracts && npm run build && npm run test && npm audit --audit-level=moderate
