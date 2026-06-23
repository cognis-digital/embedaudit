# Ports of embedaudit

The same **audit** logic, ported across languages so you can drop embedaudit
into any stack or ship a single static binary. All ports load a JSONL embedding
snapshot, run the integrity + poisoning checks, print the findings as JSON, and
exit non-zero when a `critical` finding is present — same rule IDs and output
shape as the Python reference.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../embedaudit/` | `embedaudit audit snapshot.jsonl` | `python -m pytest` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js audit snapshot.jsonl` | `node --test ports/javascript/test.js` |
| Go | `go/` | `cd ports/go && go run . audit ../../demos/01-basic/store_snapshot.jsonl` | `cd ports/go && go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- audit ../../demos/01-basic/store_snapshot.jsonl` | `cd ports/rust && cargo test` |

## Shared finding codes

`DIM_MISMATCH` · `INVALID_VALUE` · `ZERO_VECTOR` · `DUPLICATE_VECTOR` ·
`RETRIEVAL_DOMINATION` (and, in the Python reference, `NORM_OUTLIER`,
`OUTLIER_VECTOR`, `DRIFT`, `RECORD_LOSS`, and feed-enriched `KNOWN_BAD_CONTENT`).

Each port emits a JSON object:

```json
{ "ok": false, "record_count": 11, "dimension": 4,
  "findings": [ { "severity": "critical", "code": "ZERO_VECTOR", "message": "…" } ] }
```

## CI

`go test`, `cargo test`, and `node --test` for the ports run on every push via
[`.github/workflows/ports.yml`](../.github/workflows/ports.yml) — so the ports
stay real and verified even though the reference implementation is Python.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md.
