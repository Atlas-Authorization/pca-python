# `make test` runs the suite without the framework-dependent tests (no framework needed).
# `make test-real` runs the end-to-end tests against the real framework in the active environment
# (pip install -e ../python-pca pydantic-ai-slim pytest).
test:
	python -m pytest -q --ignore=test_real_pydantic_ai.py
test-real:
	python -m pytest -q test_real_pydantic_ai.py
