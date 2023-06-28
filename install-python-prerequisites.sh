#!/usr/bin/env bash
PYTHON=python3
[[ -n "$COMSPEC" ]] && PYTHON="py -3"
$PYTHON -m pip install --user -U -r requirements.txt
