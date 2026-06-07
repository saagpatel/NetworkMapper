.PHONY: install test lint clean run

install:
	python -m pip install -r backend/requirements.txt

test:
	python -m pytest backend/tests/ -v

lint:
	ruff check backend/

run:
	./scripts/run.sh

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; rm -rf .pytest_cache
