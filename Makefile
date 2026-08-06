.PHONY: install run gui cui test lint fmt typecheck clean docs-dev docs-build

install:
	uv sync --group dev

run: gui

gui:
	uv run python -m pypproxy --mode gui

cui:
	uv run python -m pypproxy --mode cui

test:
	uv run pytest tests/ -v

lint:
	uv run ruff check pypproxy tests

fmt:
	uv run ruff format pypproxy tests
	uv run ruff check --fix pypproxy tests

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache site/

docs-dev:
	uv run --group docs mkdocs serve

docs-build:
	uv run --group docs mkdocs build
