# Reading any product's log: `killchain/schema`

Stage 1 of "any security product": format detection, schema mapping and the generic parser. The result
is the same Parquet layout and columns the FortiGate parser writes, so `db --prepare`, detect, correlate,
chain and everything after run unchanged.

```
python -m killchain schema --input <file> --name <run> [--no-llm] [--force] [--parse]
```

writes `data/runs/<run>/schema.yaml` (the mapping), `data/runs/<run>/schema_report.json` and
`config/schemas/<fingerprint>.yaml`, and prints the report. `--parse` also parses the whole file into
`data/parsed/<run>/`. Other options: `--assume-tz +05:30` (zone for times without one, default UTC),
`--workers`, `--data-dir`, `--schemas-dir`.

## API for the pipeline

```python
from killchain import schema

fmt, mapping, report = schema.prepare(input, run_dir, no_llm=False, force=False)
stats = schema.parse(input, parsed_dir, mapping)        # parsed_dir/firewall/part-*.parquet + _stats.json
```

- `prepare` detects, samples, maps, validates and reports. It returns the format label (`csv`,
  `ndjson (gzip)`, `syslog/cef`, `fortigate` ...), the mapping (the schema.yaml document) and the report
  (the schema_report.json document). It raises `schema.SchemaError` when no record can be read.
- `parse` sends FortiGate input (`mapping["format"] == "fortigate"`) to the existing parser
  (`killchain.parser`, unchanged) and everything else to the generic parser. Its return value has the
  same keys as the FortiGate parser's `_stats.json` (`bytes`, `lines`, `streams.firewall.rows`,
  `lines_by_class` ...), plus `parser: generic`, `format` and `schema_fingerprint`.
- A file that matches no format is treated as FortiGate, as before: the FortiGate parser reads it and
  rejects the lines it cannot parse (`mapping["detected"] == "unknown"`).
- `.gz` and `.zip` input is decompressed once to `data/tmp/decompressed/<hash>/<name>`; `source`,
  `line` and `byte_offset` refer to that copy.

## Formats

| format | detected by | records |
|---|---|---|
| fortigate | most sample lines start with `date=` | existing parser |
| kv | most lines are 3+ `key=value` / `key:"value"` pairs | one per line |
| ndjson | most lines are JSON objects | one per line |
| json | starts with `[`, or one object holding arrays of objects (`{"value": [...]}`), or pretty-printed objects | one per object |
| csv | a header and the same field count on most lines; `,` tab `;` or `\|` | one per row |
| syslog | RFC 5424 / 3164 envelope, CEF or LEEF (via `connectors/syslog_parser.py`) | one per line |
| xml | Windows `<Event>` records | one per event |

Nested JSON is flattened to dotted keys. A list of objects is flattened too: each key gets the values of
every element joined by `,` (`Entities.Address = "1.2.3.4,10.0.0.1"`). A text field that carries a
key=value or CEF payload in most records (`message`) is expanded (`expand` in the mapping).

The sample is about 2,000 records from the start and 2,000 from the middle (the middle read seeks and
resyncs to a line start). JSON documents and XML are sampled from a bounded prefix (the first 4,000
records).

## Canonical columns

The FortiGate parser's columns (`killchain/parser/fortigate.py` FIELDS), plus these optional ones
(null when the source has none; `killchain/schema/canonical.py`):

| column | meaning |
|---|---|
| category | network, endpoint, auth, vendor_alert or other |
| product | product or provider that wrote the record |
| host, host_ip | machine the record is about |
| src_host | name of the source machine (Windows WorkstationName, CEF shost) |
| event_id | vendor event id or type (Windows EventID, PAN Event ID, Okta eventType) |
| process_name, command_line, parent_process | process |
| file_path, file_hash | file |
| logon_type | Windows logon type |
| alert_name | name of a detection another product raised |
| vendor_severity | severity normalised to 1-5 (int) |
| alert_confidence | 0-1 (float) |
| mitre_technique, mitre_tactic | ATT&CK labels the vendor gave |

Mappable but not output columns: `ts`, `tz`, `date` + `time_of_day` (a split time), `dns_query` (fills
`hostname` and sets `log_subtype = dns`), `alert_entities` (kept in `extra`).

## Mapping

1. **Synonyms** (`config/schema_synonyms.yaml`, method `synonym`): names are compared lower case with only
   letters and digits, so `Source address` = `source_address` = `sourceAddress`. Full names match first;
   a nested field is also tried on its last one or two parts against names without a dot. Up to three
   fields per column, first non-empty value wins. A field feeds one column only, except the
   `shared_fields` pairs (`event.dataset` gives both log_type and log_subtype). Entries can be limited to
   formats or to the exact spelling (`rule.name` is an ECS signature, Check Point `rule_name` is not).
2. **LLM for the leftovers** (method `llm`, `killchain/schema/llm_map.py`): one call with the column list
   and meanings, the columns already mapped, and each unmatched field with 3-5 sample values; a second
   call only for action/status/log_type/log_subtype values the first answer did not map. It answers
   `field_map`, `value_maps`, `category`, `ts_field`, `ts_format`. Temperature 0, through
   `agents.llm.LLMClient` (fallback chain). The answer is cached in `data/cache/schema_llm/<hash>.json`,
   keyed on a hash of the sorted field set. Skipped with `--no-llm`, when `LLM_ENABLED` is not true or when
   no `LLM_*_API_KEY` is set; the report says why. Unknown fields, unknown columns and value maps to a
   value no rule uses are rejected and listed.
3. **Validation** (`killchain/schema/validate.py`), at least 90% of the non-empty sample values must pass:
   IP columns parse as addresses, ports are integers 0-65535, bytes/packets/duration are non-negative
   integers, other number columns are integers, time parses in one format (epoch s/ms/µs/ns, ISO 8601 or
   a strptime format, years 2000-2100), severity fits a scale. A field that fails is dropped and reported
   (`validation.dropped`); its values stay in `extra`. `-` counts as no value.

Value maps turn each product's words into the ones the rules compare: `allow/permit/allowed -> accept`,
`deny/drop/reject/denied -> deny`, `block/block-url -> blocked`, `alert -> detected`, `TRAFFIC -> traffic`,
`THREAT -> utm`, `vulnerability -> ips`, `url -> webfilter`, `firewall.ha -> ha` (dotted values use their
last part) ... `value_maps_by` applies FortiGate's subtype-specific words (an allowed web request is
`passthrough`, a blocked IPS hit `dropped`). `derive` fills columns from others: PAN `Event ID
auth-fail` -> `action login, status failed`; a device's own login event (`log_type event, action login`)
-> `log_desc 'Admin login failed' / 'Admin login successful'`; virus subtype -> `virus` from the threat
name. Values not in any map keep their text in lower case and are listed in the report
(`validation.unknown_values`).

Category: records are grouped by the first event-type field present (`Type`, `event.dataset`,
`EventID` ...). Each record gets a category from its columns (vendor_alert > endpoint > auth > network
> other); a group whose records agree for at least 80% gets that category for all its records.

## schema.yaml

```yaml
version: 1
fingerprint: a4a2c80ecd20cc39       # hash of format + sorted field set
format: csv                          # delimiter, payload, compressed, multiline, wrappers, expand
assume_tz: '+00:00'
time: {field: Generate Time, format: '%Y/%m/%d %H:%M:%S', tz_field: null, zoned: false}
columns:
  src_ip: {fields: [Source address], method: synonym}     # synonym | pattern | llm
value_maps: {action: {allow: accept, drop: deny, ...}}    # values seen; the synonym defaults apply too
value_maps_by: {...}
derive: [...]
severity_scale: text                 # text | 1-5 | 0-10 | 0-15 | 0-100
category: {field: Type, map: {TRAFFIC: network, SYSTEM: per_record}}
```

Edit it freely; `parse` applies it as-is. A mapping saved under `config/schemas/<fingerprint>.yaml` is
reused for any file with the same format and field set (`--force` builds a new one).

## schema_report.json

`format`, `sample`, `time`, `categories` and `groups`, `columns` (each canonical column with its source
fields, method `fortigate | synonym | pattern | llm | derived | unmapped` and coverage on the sample),
`validation` (`checks`, `dropped`, `unknown_values`), `llm`, `rules` and `unmapped_fields` (kept in
`extra`).

`rules.can_run` / `rules.skipped` (with `missing`): each rule's required columns come from the text of its
`where`, `group_by`, `field`, `sql` and `steps` (string literals removed; db.py's derived columns count as
their source, `src_internal -> src_ip`, `ist_hour -> ts`); `entities` columns are optional. A column is
available when it is mapped, has sample coverage, or a derive rule can fill it. A skipped rule still runs
in detect; it can only find nothing.

## Generic parser output

`<parsed>/firewall/part-*.parquet` with `canonical.SCHEMA`: the FortiGate parser's columns in the same
order and types, the optional columns, then `parse_issue` and `extra`. Every record type goes to the
`firewall` stream for now (stage 2 decides about endpoint data).

- `ts` is UTC. `ts_quality` as in the FortiGate parser: `ok`, `tz_assumed` (a time without a zone, read
  in `assume_tz`), `missing`, `stuck`, `backwards`.
- `source` is the file name, `line` the 1-based line number, `byte_offset` the byte where the record
  starts. For a JSON document `line` is the line of the record's opening brace and `byte_offset` that
  brace's byte; for a CSV row spanning lines, its first line.
- Lines that are no record are rejected and counted (`lines_by_class`: `rejected:bad_json`,
  `rejected:binary`, `rejected:unknown_format`), as in the FortiGate parser.
- A value that does not fit its column: `parse_issue` `bad_number` or `bad_time`, the text in
  `extra._bad_<column>` / `extra._bad_ts`. A CSV row with the wrong number of fields: `stray_text`.
- Fields mapped to no column are kept in `extra` (a JSON object).

Speed (14 workers, this laptop): PAN CSV 334 MB in 3.5 s (95 MB/s, 405,000 lines/s); ECS NDJSON 1.04 GB
in 13.4 s (78 MB/s, 106,000 lines/s). Line formats and CSV are split into byte ranges parsed in worker
processes; CSV ranges go through pyarrow's CSV reader. JSON documents, XML and CSV with quoted newlines
are read in one process.

## Test data

`tools/convert_firewall.py` converts a slice of a FortiGate log (around a truth incident) into PAN-style
CSV and ECS NDJSON with each product's field names and value words, plus a line map and remapped truth
files, so the same slice can be scored in all three forms.

## Known limits

- Rules that compare FortiGate vocabulary (`log_desc` strings, `log_type`/`log_subtype`) only run on other
  products when a value map or derive rule supplies those words; `rules.skipped` names what is missing.
  CEF and Check Point key=value logs have no record type field, so traffic rules are skipped for them.
- A01 (rare events) counts rare `log_desc`, `log_id` and `action` values; other products have other
  vocabularies, so its alert keys (not its lines) differ from FortiGate's.
- CSV with quoted newlines is parsed in one process (slower).
- Messages of plain-text syslog are only parsed by the `message_patterns` regexes (Cisco ASA, sshd).
