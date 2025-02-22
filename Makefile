setup:
	pip install poetry
	poetry env activate
	poetry lock
	poetry install
run:
	python -m otus_hw1.log_analyzer
lint:
	poetry run ruff check src
format:
	poetry run ruff format src
typing:
	poetry run mypy src --follow-untyped-imports
test:
	coverage run --source=otus_hw1 -m pytest -v .\tests\test.py
	coverage report -m
