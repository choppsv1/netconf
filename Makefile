#
# December 16, 2014 Christian E. Hopps <chopps@gmail.com>
#
PIP=pip
PYLINT=pylint
PYTEST=py.test
PYTHON=python

TSFILE=.lint-timestamp

check:
	@echo Running lint on changes with PYLINT=$(PYLINT)
	@OK=YES; for f in $$(git status | awk '/^[ \t]+(modified|new file): +.*.py$$/{print $$2}'); do if [[ $$f -nt $(TSFILE) ]]; then echo "=== $$f"; if ! $(PYLINT) -r n --rcfile=pylintrc $$f; then OK=NO; fi; fi; done; if [[ $$OK = YES ]]; then touch $(TSFILE); fi

clean:
	find . -name '*.pyc' -exec rm {} +
	$(PYTHON) setup.py clean
	rm -rf bulid

install:
	$(PIP) install -e .

uninstall:
	$(PIP) uninstall -y netconf

lint:
	@for f in $$(find netconf tests -name '*.py'); do \
		echo "=== Linting $$f"; \
		$(PYLINT) -r n --rcfile=pylintrc $$f; \
	done

test:	lint run-test

run-test:
	@echo "Running python tests"
	$(PYTEST) -v --doctest-modules

pypi-upload:
	python setup.py sdist upload
