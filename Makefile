.PHONY: install dev lint format typecheck test check clean

install:
	python -m pip install -e .

dev:
	python -m pip install -e ".[dev]"

lint:
	ruff check src tests examples
	ruff format --check src tests examples

format:
	ruff check --fix src tests examples
	ruff format src tests examples

typecheck:
	mypy

test:
	pytest -v

check: lint typecheck test

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info .pytest_cache .ruff_cache .mypy_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
