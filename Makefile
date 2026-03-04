.PHONY: install install-dev test test-cov lint build deploy clean simulate

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

test:
	python -m pytest tests/ -v

test-cov:
	python -m pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html

build:
	sam build

deploy:
	sam deploy --guided

deploy-prod:
	sam deploy --config-env prod

validate:
	sam validate --lint

clean:
	rm -rf .aws-sam/ .pytest_cache/ __pycache__/ htmlcov/ .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

simulate:
	python scripts/simulate_events.py
