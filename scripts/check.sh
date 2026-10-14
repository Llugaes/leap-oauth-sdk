#!/usr/bin/env bash
set -euo pipefail
uv run --extra dev ruff check src tests
uv run --extra dev ruff format --check src tests
uv run --extra dev pyright src
uv run --extra dev pytest --cov=leap_oauth_sdk --cov-report=term --cov-fail-under=90
node --test tests/js/leap-sso.test.mjs
rm -rf dist
uv build
uv run --extra dev python scripts/check_artifacts.py
echo "all gates passed"
