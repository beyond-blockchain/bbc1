#!/bin/bash

. venv/bin/activate

pip install -r requirements.txt
pip install sphinx sphinx_rtd_theme

sphinx-apidoc -F -e -o docs/api/ bbc1
cd docs/api

rm -f bbc1.core.libbbcsig.test_ecdsa.rst

make html
