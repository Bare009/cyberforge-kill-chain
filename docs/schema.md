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
> other); a group whose records agree for at least 80% gets that category for all its records, except
that a record which is itself a detection (an alert name or MITRE fields) stays `vendor_alert` (an EDR's
alert-tagged process events among its plain process events).

Confidence words (`malicious` 0.9, `suspicious` 0.6, `high` / `medium` / `low` ...) become numbers. When
an export has no product field, `product_hints` in the synonyms file names the product from marker fields
(SentinelOne `threatInfo.threatName` + `agentRealtimeInfo.agentComputerName`, Wazuh `rule.level` +
`rule.description` + `agent.name` ...).

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
order and types, the optional columns, then `parse_issue` and `extra`. Every record type (network,
endpoint, auth, vendor alert) goes to the `firewall` stream; `category` tells them apart.

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

## After the parse (stage 2)

- `db.py` adds every optional column the source lacks as NULL (`db.with_optional`), in the views and in a
  prepared `events.duckdb`; a run prepared before these columns existed is opened read-only through
  views that add them. So rules over `command_line`, `event_id` ... bind on every run, and on a FortiGate
  run they match nothing.
- `rules/endpoint/` and `rules/auth/` (rules/README.md) read the host columns. A rule may list
  `requires_any: [[event_id, user], [category, status, user]]`: the coverage report counts it as runnable
  when every column of one group is available (its `where` has alternatives).
- Rules never read `vendor_alert` records; `python -m killchain detect` turns those into alerts of layer
  `vendor` (`killchain/detect/vendor.py`, docs/contracts.md).
- The auth rules AU01-AU04 leave out a firewall's own admin logins (`log_desc` 'Admin login ...', which the
  derive rules also set for PAN and ECS exports): those are R01/R06/R07's. Without that, AU02 (password
  spray) raised 183 background alerts on the PAN and ECS conversions of the firex slice (false alarms 97%).

## In `python -m killchain run` (stage 3)

`run` starts with a `schema` stage (`python -m killchain schema --input <file> --name <run> --data-dir
<data> [--no-llm]`, also with `--offline`), timed like the others. Then:

- FortiGate input (`schema.yaml` `format: fortigate`, which includes a file of no recognised format)
  takes the parse stage as before: `python -m killchain parse <file> --out <parsed> --overwrite`. The schema
  stage costs under 1 s on firex-10G (its FortiGate sample no longer counts the lines before the middle of
  the file). A file of no recognised format adds the warning `schema: no supported format recognised`.
- Any other format: the parse stage is `python -m killchain schema ... --mapping <run>/schema.yaml --out
  <parsed>` (parse only, with the mapping the schema stage wrote). The generic parser prints the FortiGate
  parser's progress lines, so the Dashboard's parse bar works for it too.
- detect gets `--no-llm` with `--no-llm` or `--offline`. When the LLM is skipped for want of a key (or
  because of the flag), the run's notes say so for the field mapping and the vendor alert labels.
- `schema` failing for another reason is a warning: the FortiGate parser then reads the file.
- No record (an empty file, binary, `[]`): exit 3 with the reason, and the run and parsed folders the run
  created are removed (folders that existed before are kept, with the record).
- `KILLCHAIN_SCHEMAS_DIR` moves the saved mappings out of `config/schemas` (the tests use it).

`run_summary.json` `schema` (also `pipeline.schema` in the record):

| key | value |
|---|---|
| `format`, `detected`, `fallback`, `parser`, `fingerprint`, `schema_source` | what was read and how (`fallback: fortigate` for an unrecognised file) |
| `products` | {product: rows} over the whole parse (FortiGate: `{"FortiGate": rows}`) |
| `categories`, `categories_from` | {category: rows} over the parsed events; for FortiGate the sample's (the FortiGate parser writes no category) |
| `sample_records` | records in the schema sample |
| `mapping` | `methods` (columns per method: fortigate, synonym, pattern, llm, derived, unmapped), `mapped`, `unmapped`, `time_coverage`, `dropped` |
| `llm` | `used`, `reason` it was not, `added` (columns the LLM mapped) |
| `rules` | `can_run` (ids) and `skipped` ({id, missing}) |
| `alerts_by_layer` | detect's layers |
| `vendor_alerts` | `records`, `alerts`, `technique_sources` (vendor, keyword, llm, unknown), `llm_skipped` |
| `network` | `source` (configured or inferred), `reason`, `internal_ips`, `configured_share`, `zones` ({zone/role: {ips, rows}}), `servers`, `named_hosts` |
| `secs`, `prepare_secs` | schema stage wall time, and the time `schema.prepare` took inside it |

### Network zones per run

`killchain/netzones.py`, called by `python -m killchain db --prepare` (`--network config` turns it off),
writes `<run>/network_zones.json` and, when the zones are inferred, `<run>/network.inferred.yaml`
(network.yaml layout, editable; rerun `--from prepare` after editing). `db.run_network(run)` returns it, else
`config/network.yaml`; db prepare, correlate, chain, reach and score use it.

- The run's internal addresses are the RFC 1918 and loopback ones in `src_ip`, `dst_ip` and `host_ip`. When at
  least half of them (distinct) are in a configured zone other than the catch-all `internal` ranges, the run
  uses `config/network.yaml` unchanged. firex-10G: 99.9% of 1,388 (0.8 s); the PAN and ECS conversions of
  its slice: the same.
- Otherwise: hosts whose name has a `dc` / `domaincontroller` part are zone server, role domain-controller
  (importance 1.0); `srv`, `server`, `sql`, `db`, `web`, `mail` names are servers (0.75), each a /32 from its
  `host_ip`; a /24 whose hosts take connections on 22, 25, 53, 80, 88, 135, 139, 389, 443, 445, 1433, 3306,
  3389, 5432 or 5985 from 3 or more internal sources is a server subnet; every other internal address is a
  desktop (0.25). No fixed hubs (correlate still finds hubs from the alerts), and only RFC 1918, loopback and
  link-local are internal.
- Why config/network.yaml lists 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 as private: the list is
  also threat intel's never-send list (the documentation ranges are not real addresses), and db.py uses it
  for `src_internal` / `dst_internal`. firex depends on it: its firewall's public address 203.0.113.5
  (140,307 rows as a destination) is "internal" there, zone public. That file is unchanged; in an inferred
  network those ranges are outside addresses (threat intel still never sends them).

Inferred on the test inputs: SentinelOne export, 9 internal addresses, desktop 8, server 1 (SRV-WEB-01
10.10.0.30 by name); Wazuh, 10 addresses, desktop 7, server 3 (web-01, web-02, db-01 by name); EDR sample,
28 addresses, desktop 24, server 3 (SRV-WEB-01, SRV-FILE-01, SRV-DB-01) and domain controller 1 (SRV-DC-01
10.10.0.10); Sentinel SecurityAlert export, none (its addresses are only in the alert entities), so no
zones and no fixed hubs. None of these has flows on server ports, so no server /24 was found.

## Known limits

- Network zones are inferred from columns only: a Sentinel export's hosts and addresses live in the alert
  entities (`extra`), so it gets no zones. A server subnet needs flows (`dst_port`); EDR and SIEM alert
  exports have none, so servers there come from host names only.
- Rules that compare FortiGate vocabulary (`log_desc` strings, `log_type`/`log_subtype`) only run on other
  products when a value map or derive rule supplies those words; `rules.skipped` names what is missing.
  CEF and Check Point key=value logs have no record type field, so traffic rules are skipped for them.
- A01 (rare events) counts rare `log_desc`, `log_id` and `action` values; other products have other
  vocabularies, so its alert keys (not its lines) differ from FortiGate's.
- CSV with quoted newlines is parsed in one process (slower).
- Messages of plain-text syslog are only parsed by the `message_patterns` regexes (Cisco ASA, sshd).
