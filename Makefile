PYTHON ?= python3
PYTHONPATH := $(CURDIR)/src

.PHONY: test validate lint verify-seed all

all: validate lint test verify-seed

validate:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli validate --problem problems/hadamard-mini

lint:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m p42_prizes.cli lint --problem problems/hadamard-mini

test:
	@PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q

verify-seed:
	@$(MAKE) -C problems/hadamard-mini verify
