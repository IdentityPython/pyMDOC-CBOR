#!/usr/bin/env bash
# Build pymdoccbor and publish to PyPI (or TestPyPI).
#
# Usage (from repo root):
#   ./scripts/publish_pypi.sh              # build + upload to PyPI (asks confirm)
#   ./scripts/publish_pypi.sh --test       # build + upload to TestPyPI
#   ./scripts/publish_pypi.sh --dry-run    # build + twine check only (no upload)
#   ./scripts/publish_pypi.sh --build-only # build only
#
# Auth (API token only):
#   export PYPI_TOKEN=pypi-...             # PyPI token (or TestPyPI token with --test)
#
# Optional:
#   PYTHON=python3.12 ./scripts/publish_pypi.sh --test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PYTHON="${PYTHON:-python3}"
MODE="pypi" # pypi | test | dry-run | build-only

usage() {
  sed -n '2,15p' "$0"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --test) MODE="test"; shift ;;
    --dry-run) MODE="dry-run"; shift ;;
    --build-only) MODE="build-only"; shift ;;
    -h|--help) usage 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage 1
      ;;
  esac
done

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python not found: $PYTHON" >&2
  exit 1
fi

VERSION="$("$PYTHON" -c "import re; print(re.search(r'^__version__\s*=\s*[\'\"]([^\'\"]*)[\'\"]', open('pymdoccbor/__init__.py').read(), re.M).group(1))")"
echo "Package: pymdoccbor==${VERSION}"
echo "Mode:    ${MODE}"
echo "Python:  $("$PYTHON" -V)"

echo "Installing build tooling..."
# packaging>=24.2 + twine>=6.2 are required to accept Metadata 2.4 License-File
# fields emitted by modern setuptools (otherwise: malformed field 'license-file').
"$PYTHON" -m pip install --upgrade \
  "pip" \
  "build>=1.2" \
  "twine>=6.2" \
  "packaging>=24.2" >/dev/null
"$PYTHON" -c "from importlib.metadata import version; print(f\"  twine {version('twine')}, packaging {version('packaging')}\")"

echo "Cleaning previous dist/ and build artifacts..."
rm -rf dist/ build/ ./*.egg-info pymdoccbor.egg-info

echo "Building sdist and wheel..."
"$PYTHON" -m build

echo "Artifacts:"
ls -la dist/

echo "Checking distributions with twine..."
"$PYTHON" -m twine check dist/*

if [[ "$MODE" == "build-only" || "$MODE" == "dry-run" ]]; then
  echo "Done (${MODE}): nothing uploaded."
  exit 0
fi

if [[ -z "${PYPI_TOKEN:-}" ]]; then
  echo "Set PYPI_TOKEN to a PyPI API token before publishing." >&2
  echo "Example:" >&2
  echo "  export PYPI_TOKEN=pypi-<your-api-token>" >&2
  exit 1
fi

if [[ "$PYPI_TOKEN" != pypi-* ]]; then
  echo "PYPI_TOKEN does not look like a PyPI API token (expected prefix 'pypi-')." >&2
  exit 1
fi

# Twine token auth: username is always __token__, password is the API token.
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="$PYPI_TOKEN"

if [[ "$MODE" == "test" ]]; then
  REPOSITORY_ARGS=(--repository testpypi)
  TARGET="TestPyPI (https://test.pypi.org/project/pymdoccbor/)"
else
  REPOSITORY_ARGS=()
  TARGET="PyPI (https://pypi.org/project/pymdoccbor/)"
fi

echo
echo "About to upload pymdoccbor==${VERSION} to ${TARGET}"
read -r -p "Type 'yes' to continue: " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Aborted."
  exit 1
fi

"$PYTHON" -m twine upload "${REPOSITORY_ARGS[@]}" dist/*
echo "Published pymdoccbor==${VERSION} to ${TARGET}"
