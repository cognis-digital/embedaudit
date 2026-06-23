# embedaudit — Advanced usage

## CI gate (fail the build on a poisoned / drifted store)
`embedaudit` exits non-zero when any `critical` finding is present, so the exit
code *is* the gate — no extra flag needed.
```yaml
- run: pip install cognis-embedaudit
- run: embedaudit audit snapshot.jsonl --format sarif > embedaudit.sarif
  # exits 1 on a critical finding -> the step (and build) fails
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: embedaudit.sarif }
```

Gate on drift against a committed baseline instead:
```yaml
- run: embedaudit drift baseline.jsonl current.jsonl --format json
```

## Pipe into a SIEM / webhook
```bash
embedaudit audit snapshot.jsonl --format json | python integrations/webhook.py --url "$COGNIS_WEBHOOK_URL"
# or forward to STIX / MISP / Sigma / Splunk / Elastic / Slack via cognis-connect:
embedaudit audit snapshot.jsonl --format json | embedaudit-emit --to sigma
```

## Offline / air-gap threat-intel enrichment
```bash
python -m embedaudit.feeds.datafeeds update urlhaus threatfox   # cache (connected host)
python -m embedaudit.feeds.datafeeds snapshot-export feeds.tar.gz
# ... sneakernet feeds.tar.gz into the enclave ...
python -m embedaudit.feeds.datafeeds snapshot-import feeds.tar.gz
embedaudit audit snapshot.jsonl --enrich-feeds                  # offline, adds KNOWN_BAD_CONTENT
```

## Drive it from an AI agent (MCP)
```jsonc
// claude_desktop_config.json
{ "mcpServers": { "embedaudit": { "command": "embedaudit", "args": ["mcp"] } } }
```
Exposed tools: `embedaudit_audit(snapshot_path, …)` and
`embedaudit_drift(baseline_path, current_path, …)` — both return JSON findings.

## Run a language port instead of Python
```bash
node ports/javascript/index.js audit snapshot.jsonl       # Node
( cd ports/go   && go run . audit ../../snapshot.jsonl )  # Go single binary
( cd ports/rust && cargo run -- audit ../../snapshot.jsonl ) # Rust
```
All ports share the rule IDs and JSON shape and exit 1 on a critical finding.

## Output formats
`--format table` (default, human) · `json` · `sarif` (GitHub code-scanning) ·
`csv` (one row per finding, for spreadsheets / SIEM ingest).
