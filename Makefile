PYTHON ?= python3
VENV ?= .venv
SCIENCE_VENV ?= .venv-science

REPRO ?= reruns/admission-study

.PHONY: install install-science check check-full reproduce-admission verify-science clean

install:
	$(PYTHON) scripts/install_local.py $(VENV)

install-science:
	$(PYTHON) scripts/install_local.py $(SCIENCE_VENV) --with-system-science

check:
	$(VENV)/bin/python -B scripts/validate.py --suite quick

# Needs the separate evidence object attached with scripts/import_evidence.py;
# without it the run stops with "complete evidence is not attached".
check-full:
	$(SCIENCE_VENV)/bin/python -B scripts/validate.py --suite full --timeout 7200

# Rederive the admission-study tables (supplement: 18,900-row accounting,
# 1,242/1,296 exposed units, rerun agreement, bootstrap) from the retained
# compressed matrices. Pure Python; no compiler needed. Output goes to $(REPRO).
reproduce-admission:
	mkdir -p $(REPRO)
	$(PYTHON) -B -c "import gzip,sys; [open(sys.argv[2*i+2],'wb').write(gzip.decompress(open(sys.argv[2*i+1],'rb').read())) for i in range(2)]" \
	  results/admission-study/matrix.csv.gz $(REPRO)/matrix.csv results/admission-study/rerun.csv.gz $(REPRO)/rerun.csv
	PYTHONPATH=src:. $(PYTHON) -B scripts/derive_admission_study.py --matrix $(REPRO)/matrix.csv \
	  --rerun $(REPRO)/rerun.csv --mutants specs/mutants.json --out $(REPRO)/derived

# Read-only accounting checks on the retained admission and utility rows.
verify-science:
	PYTHONPATH=src:scripts $(PYTHON) -B scripts/verify_science.py

clean:
	rm -rf $(VENV) $(SCIENCE_VENV) validation-logs .validation .pytest_cache reruns
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
