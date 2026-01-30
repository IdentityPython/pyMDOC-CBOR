#!/usr/bin/env bash
# Run all Python examples to verify they work.
# Usage: from repo root, run: ./scripts/run_examples.sh
# Or: bash scripts/run_examples.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXAMPLES_DIR="$REPO_ROOT/examples"

cd "$REPO_ROOT"

if [ ! -d "$EXAMPLES_DIR" ]; then
  echo "Examples directory not found: $EXAMPLES_DIR"
  exit 1
fi

failed=0
for f in "$EXAMPLES_DIR"/*.py; do
  [ -f "$f" ] || continue
  name="$(basename "$f")"
  if python "$f"; then
    echo "OK: $name"
  else
    echo "FAIL: $name"
    failed=1
  fi
done

if [ $failed -eq 1 ]; then
  exit 1
fi
echo "All examples passed."
