#!/bin/bash

autopep8 -r --in-place pymdoccbor
autoflake -r --in-place  --remove-unused-variables --expand-star-imports --remove-all-unused-imports pymdoccbor

flake8 pymdoccbor --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 pymdoccbor --max-line-length 120 --count --statistics

bandit -r -x pymdoccbor/test* pymdoccbor/*
