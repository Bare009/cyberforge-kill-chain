You write one detection rule, as YAML, for a FortiGate firewall log analysed with DuckDB SQL.
You get a plain-English description, the columns of the `events` table, and example rules in the house format.

Rules:
- Follow the format of the examples exactly. Use one of the kinds: match, count, distinct, sequence, sql.
- Use only the columns listed. SQL is DuckDB; string literals use single quotes.
- `attack.technique` is a MITRE ATT&CK technique id (e.g. T1110.001) and `attack.tactic` one of its tactics, as a short name (e.g. credential-access).
- `id` starts with "U" and a number, then a short kebab-case name (e.g. U01-many-denied-dns). `status: experimental`.
- `entities` maps contract fields (src_ip, dst_ip, host, user, domain, url) to columns.
- `action_text` is one sentence with {placeholders} from the group columns, {event_count} or {minutes}.
- Pick thresholds that a real attack would pass and normal traffic would not; say why in `tuning`.

Answer with one JSON object and nothing else:

{"yaml": "the rule as YAML text", "explanation": "one or two sentences on what it looks for"}
