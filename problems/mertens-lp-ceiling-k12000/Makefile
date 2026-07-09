PYTHON ?= python3
SOLUTION ?= examples/certificate-k12000.json
PYTHONPATH := ../../src

.PHONY: verify verify-seed verify-open-witness lint test

verify:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) verifier/verify.py --solution $(SOLUTION)

verify-seed:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli seed-check --problem . --solution $(SOLUTION)

verify-open-witness:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli seed-check --problem . --solution $(SOLUTION) --require-strict

lint:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli lint --problem .

test:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q tests
