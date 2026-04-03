.PHONY: install test red-team test-all demo-basic demo-disaster demo-verify witness arc-tests log-server lint clean website paper

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=arc --cov-report=term-missing

red-team:
	pytest tests/red_team/ -v

red-team-verbose:
	pytest tests/red_team/ -v -s

red-team-live:
	pytest tests/red_team/test_live_scenario.py -v -s

test-all:
	pytest tests/ tests/red_team/ -v --cov=arc --cov-report=term-missing

demo-basic:
	python demo/demo_basic.py

demo-disaster:
	python demo/demo_disaster.py

witness:
	python demo/arc_witness.py

arc-tests:
	python demo/arc_tests.py

log-server:
	python -m uvicorn arc_log.server:app --host 0.0.0.0 --port 8080 --reload

demo-verify:
	@echo "Usage: make demo-verify RECEIPT_ID=arc_..."
	python demo/demo_verify.py $(RECEIPT_ID)

lint:
	ruff check src/ tests/ demo/
	ruff format --check src/ tests/ demo/

lint-fix:
	ruff check --fix src/ tests/ demo/
	ruff format src/ tests/ demo/

type-check:
	mypy src/arc/

website:
	@echo "Open website/index.html in a browser (no build step needed)"
	@echo "Or serve locally: python -m http.server 3000 --directory website"

paper:
	@echo "Compiling LaTeX paper..."
	cd paper && bash compile.sh

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .coverage htmlcov/ .mypy_cache/ .ruff_cache/ dist/ build/ *.egg-info/
	rm -f paper/*.aux paper/*.log paper/*.out paper/*.bbl paper/*.blg paper/*.toc paper/*.fls paper/*.fdb_latexmk paper/*.synctex.gz
