# Sample security logs

Fixtures for exercising ingestion. Every address is from a documentation range
(RFC 5737 / RFC 3849) except `185.220.101.34`, which is a real published Tor
entry node and appears only as text in a blocked-connection message.

Upload one with:

```bash
curl -X POST http://localhost:8000/api/v1/log-sources/$SOURCE_ID/ingest \
     -H "Authorization: Bearer $TOKEN" \
     -F file=@sample_data/firewall_logs.csv
```

| File | Format | Records | Shows |
| --- | --- | --- | --- |
| `firewall_logs.csv` | CSV | 12 | Snake-case headers, ISO 8601 timestamps, the common path |
| `auth_logs.json` | JSON | 8 | Events wrapped in an `events` envelope; nested `metadata` merged into `attributes` |
| `endpoint_logs.jsonl` | NDJSON | 10 | One object per line, and vendor spellings (`@timestamp`, `srcip`, `dstip`, `msg`, `eventtype`) resolved by the alias table |
| `malformed_logs.csv` | CSV | 7 | Partial ingestion: 4 accepted, 3 rejected |

## What `malformed_logs.csv` demonstrates

Three rows are rejected and reported with their line numbers, while the rest are
stored:

- **line 3** — `unparseable timestamp 'not-a-timestamp'`
- **line 4** — `timestamp is empty`
- **line 7** — `row has more fields than the 6-column header`

Line 5 is *accepted* on purpose. Its source address (`999.999.999.999`) is not a
valid IP, so the column is left null and the original value is preserved under
`attributes.source_ip`. A field that fails to parse costs you that field, not
the whole event.
