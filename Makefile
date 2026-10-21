.PHONY: install dev test lint docs screenshots docker clean

install:
	pip install -e ".[dev]"

dev:
	ssokit-dev

test:
	pytest

lint:
	ruff check src tests scripts
	python scripts/gen_error_docs.py --check

docs:
	python scripts/gen_error_docs.py

screenshots:
	python scripts/screenshots.py docs/screenshots

docker:
	docker compose up --build

clean:
	rm -rf keys .pytest_cache .ruff_cache build dist src/*.egg-info examples/node/node_modules examples/php/vendor
