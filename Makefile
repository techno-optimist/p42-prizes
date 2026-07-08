PYTHON ?= python3
PYTHONPATH := $(CURDIR)/src

.PHONY: test validate lint verify-seed admit-host-seed contracts-test all

all: validate lint test verify-seed

validate:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli validate --problem problems/hadamard-mini

lint:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli lint --problem problems/hadamard-mini

test:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q

verify-seed:
	@$(MAKE) -C problems/hadamard-mini verify

admit-host-seed:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli admit-host \
		--problem problems/hadamard-mini \
		--solution problems/hadamard-mini/examples/valid-4.json \
		--runs 2

contracts-test:
	@cd contracts && npm run build && npm run test && npm audit --audit-level=moderate
