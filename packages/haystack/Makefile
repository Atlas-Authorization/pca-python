# `make test` runs the duck-typed suite (no framework needed).
# `make test-real` runs the end-to-end tests against the real framework in the active environment
# (pip install -e ../python-pca haystack-ai pytest). Works on haystack-ai 2.x (ToolInvoker + Agent)
# and 3.x (Agent).
test:
	python -m pytest -q --ignore=test_real_haystack.py
test-real:
	python -m pytest -q test_real_haystack.py
