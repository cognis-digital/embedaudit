#!/usr/bin/env bash
# Run + test every language port against the bundled demo snapshot.
# Each port loads JSONL, audits it, and exits non-zero on a critical finding.
set -u
SNAP="demos/01-basic/store_snapshot.jsonl"

echo "== node =="
if command -v node >/dev/null; then
  node --test ports/javascript/test.js && \
  node ports/javascript/index.js audit "$SNAP" >/dev/null; echo "  node exit: $?"
else echo "  node: skipped (not installed)"; fi

echo "== go =="
if command -v go >/dev/null; then
  ( cd ports/go && go test ./... && go run . audit ../../"$SNAP" >/dev/null ); echo "  go exit: $?"
else echo "  go: skipped (not installed)"; fi

echo "== rust =="
if command -v cargo >/dev/null; then
  ( cd ports/rust && cargo test && cargo run -q -- audit ../../"$SNAP" >/dev/null ); echo "  rust exit: $?"
else echo "  rust: skipped (not installed)"; fi
