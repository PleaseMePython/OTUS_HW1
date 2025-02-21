setup:
	pip install poetry
	poetry lock
	poetry install
lint:
	poetry run ruff check src
format:
	poetry run ruff format src
typing:
	poetry run mypy src --follow-untyped-imports
test:
	coverage run --source=otus_hw1 -m pytest -v .\tests\test.py
	coverage report -m
