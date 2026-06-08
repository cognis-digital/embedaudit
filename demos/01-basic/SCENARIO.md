# Demo 01 - Basic poisoning + duplicate audit

This demo runs EMBEDAUDIT against a small embedding snapshot that mimics a
RAG vector store after a poisoning attempt.

## Input

`store_snapshot.jsonl` contains 10 records (4-dimensional vectors for
readability). It deliberately includes the kinds of problems EMBEDAUDIT is
built to catch:

- **A zero-norm vector** (`broken-1`) - a record that failed to embed and was
  written as all zeros. Un-retrievable garbage that corrupts centroid stats.
- **A duplicate pair** (`dup-a` / `dup-b`) - the same vector indexed twice,
  causing retrieval flooding and index bloat.
- **A retrieval-domination cluster** (`poison-1..poison-5`) - five
  near-identical "universal" poison documents that together form 50% of the
  store. In a real RAG pipeline these would dominate top-k retrieval for
  almost any query - the classic embedding-poisoning attack.

## Run it

```sh
python -m embedaudit audit demos/01-basic/store_snapshot.jsonl
python -m embedaudit --format json audit demos/01-basic/store_snapshot.jsonl
```

## Expected outcome

The tool exits **non-zero** (critical findings present) and reports:

- `ZERO_VECTOR` (critical) for `broken-1`
- `DUPLICATE_VECTOR` (warning) for the `dup-a`/`dup-b` pair
- `RETRIEVAL_DOMINATION` (critical) for the poison cluster (~50% share)

A clean, healthy store would exit 0 with `findings: none`.
