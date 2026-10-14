#!/usr/bin/env bash
set -euo pipefail
uv run ruff check src tests
uv run ruff format --check src tests
uv run pyright src
uv run pytest --cov=leap_oauth_sdk --cov-report=term --cov-fail-under=90
rm -rf dist
uv build
uv run python scripts/check_artifacts.py
echo "all gates passed"
