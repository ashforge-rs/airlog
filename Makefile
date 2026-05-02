.PHONY: help install lint format test build release clean

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  install   Install all dependencies (uv sync)"
	@echo "  lint      Check formatting and lint rules"
	@echo "  format    Auto-format and fix lint issues"
	@echo "  test      Run test suite with coverage"
	@echo "  build     Build wheel + sdist and validate with twine"
	@echo "  release   Run tests, then build and validate"
	@echo "  clean     Remove build artifacts and coverage output"

install:
	uv sync

lint:
	uv run ruff format --check src/ tests/
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

test:
	uv run pytest --cov-report=xml

build:
	uv build
	uvx twine check dist/*

release: test build

clean:
	rm -rf dist/ coverage.xml .coverage .coverage_html
