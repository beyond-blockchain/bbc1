#!/bin/bash

source venv/bin/activate

pip install sphinx sphinx_rtd_theme

sphinx-apidoc -F -e -o docs/api/ bbc1
cd docs/api

rm -f bbc1.core.libbbcsig.test_ecdsa.rst bbc1.core.libbbcsig.test_pybbcsig.rst

make html

deactivate
