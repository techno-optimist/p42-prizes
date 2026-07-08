PYTHON ?= python3
SOLUTION ?= examples/kt-2x2-forcing.json
PYTHONPATH := ../../src

.PHONY: verify lint test

verify:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) verifier/verify.py --solution $(SOLUTION)

lint:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli lint --problem .

test:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q tests
