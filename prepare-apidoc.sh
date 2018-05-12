#!/bin/bash

pipenv install sphinx sphinx_rtd_theme

pipenv run sphinx-apidoc -F -e -o docs/api/ bbc1
cd docs/api

rm -f bbc1.core.libbbcsig.test_ecdsa.rst bbc1.core.libbbcsig.test_pybbcsig.rst

pipenv run make html
