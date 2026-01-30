#!/bin/bash
# Code quality: format, lint, security scan.
# Uses .flake8 for flake8 config (max-line-length 120).

autopep8 -r --in-place pymdoccbor
autoflake -r --in-place --remove-unused-variables --expand-star-imports --remove-all-unused-imports pymdoccbor

flake8 pymdoccbor

bandit -r -x pymdoccbor/tests pymdoccbor
