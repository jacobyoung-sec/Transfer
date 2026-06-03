# XQL Syntax Reference

Cortex XSIAM Query Language (XQL) — pipe-delimited stages that transform security data.
Authoritative source: Palo Alto Networks official documentation (URLs below). The patterns
here are validated against working XSIAM content.

- XQL Language Structure: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/XQL-Language-Structure
- Cortex Query Language (XQL): https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Cortex-Query-Language-XQL
- Get started with XQL: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Get-started-with-XQL

> Always confirm field names against the `datasets/<category>/` samples — never invent fields.

## 1. Query structure

```
<data_source> | <stage1> | <stage2> | ... | <final_stage>
```

```xql
dataset = xdr_data
| filter action_type = "process_launch"
| fields agent_hostname, action_process_image_name, _time
| comp count() as event_count by agent_hostname
| sort event_count desc
| limit 10
```

Comments: `// single line` and `/* multi-line */`.

Non-default time window: prepend `config timeframe = Nd` (e.g. `config timeframe = 7d`)
before the data-source stage.

## 2. Data selection (first, mandatory stage)

| Form | Use |
|---|---|
| `dataset = <name>` | Raw vendor fields from one dataset (e.g. `dataset = xdr_data`) |
| `datamodel dataset = <name>` | XDM-normalized fields (`xdm.*`) for one dataset |
| `datamodel` | Cross-source unified XDM model (`filter _event_type = "..."`) |
| `preset = <name>` | Predefined dataset grouping (e.g. `preset = xdr_event`) |

Use `datamodel dataset =` when you want normalized `xdm.*` names that work across vendors
(ideal for SOAR-bound output); use plain `dataset =` for raw field access.

## 3. Core stages

| Stage | Purpose |
|---|---|
| `filter` | Keep matching records (push left, make selective) |
| `fields` | Select / rename / project (`a as b`); use early before joins |
| `alter` | Create or transform fields |
| `comp` | Aggregate by group (`comp count() by host`) |
| `windowcomp` | Window functions (rank, row_number, lag, running totals) |
| `dedup` | Remove duplicates (numbers/strings only — not arrays/objects) |
| `sort` | Order results (`sort desc _time`) |
| `limit` | Cap rows |
| `join` | Correlate across queries (`inner`/`left`/`right`/`cross`, always `as alias`) |
| `union` | Combine datasets |
| `bin` | Bucket by time/quantity (`bin _time span = 1h`) |

Recommended order: `config` → data-source → `filter` → `alter` → `comp` →
post-`comp` `filter` → `fields` → `sort` → `limit` → `dedup`.

## 4. Operators & matching

- `=` exact match, **case-sensitive** for strings. For case-insensitive exact match, normalize
  first: `alter h = lowercase(name) | filter h = "value"`.
- `contains` — case-insensitive substring (no `lowercase()` needed). Avoid a leading wildcard.
- `~=` — regex match.
- `in (...)` — membership; ENUM values are **unquoted** (`ENUM.EVENT_LOG`, not the quoted form).
- `incidr(field, "10.0.0.0/8")` — IP/CIDR range match (prefer over string IP matching).
- Combine with `and` / `or`; group with parentheses.

## 5. Common functions

- Strings: `lowercase`, `uppercase`, `concat`, `split`, `replace`, `len`, `trim`,
  `format_string`.
- Conditional: `if(cond, then, else)`, `coalesce(a, b, ...)`.
- Time: `_time`, `timestamp_diff`, `format_timestamp`, `current_time`.
- Type: `to_string`, `to_number`, `to_integer`, `to_boolean`, `to_json_string`.
- Aggregates (in `comp`): `count()`, `count_distinct(f)`, `values(f)`, `sum`, `avg`, `min`,
  `max`, `earliest`, `latest`. Always include a `by` clause unless a single global row is
  intended.

## 6. JSON / nested-field navigation (arrow notation)

- Dot-path form for nested reads: `field -> a.b.c` — **never** chain `field -> a -> b -> c`.
- Bracket only reserved/special keys: `field -> ["@odata.type"]` (`@`-prefix, hyphens,
  keywords).
- Arrow walks JSON in *string* columns. Wrap array-function results with `to_json_string(...)`
  before reading leaves.
- Use `json_extract_scalar(field, "$.path")` / `json_extract_array(...)` only when the path
  needs JSONPath features the arrow grammar can't express.

## 7. Performance (Detection-Engineer perspective)

- Strict left-filtering: most selective `filter` first, on native/indexed fields.
- Avoid leading wildcards (`contains "*x"`, `~= ".*x$"`) — they force full scans.
- `fields` before `join` on wide datasets to reduce columns.
- Bound `comp` cardinality and constrain both sides of a `join` with filters/`fields`.
- Use `filter _time` / `config timeframe` rather than over-broad windows.

## 8. XDM mapping for custom log parsing & normalization

When normalizing a raw custom log into XDM, build the mapping in `alter` stages from the raw
fields observed in the dataset sample, then project the `xdm.*` entities SOAR needs. Pattern:

```xql
// Normalize raw custom collector events into XDM entity fields
dataset = <custom_dataset>
| alter
    xdm.source.ipv4            = to_string(src_ip),          // raw -> XDM source IP
    xdm.target.user.username   = lowercase(user),            // normalize case for matching
    xdm.target.process.command_line = cmdline,
    xdm.event.type             = event_action
| fields xdm.source.ipv4, xdm.target.user.username,
         xdm.target.process.command_line, xdm.event.type
```

For tenant-level parsing/normalization (parsing rules applied at ingest), follow the official
parsing-rules documentation; the XQL above is the query-time normalization form used for
detections and SOAR field exposure.

## 9. Quality checklist before delivering a query

1. Data source valid and appropriate for intent.
2. Field names verified against the relevant `datasets/<category>/` sample.
3. Correct operators per type (ENUM unquoted, strings quoted, regex `~=`, IP `incidr()`).
4. Every `comp` has a `by` clause (unless a single-row result is intended).
5. Time window set (`config timeframe`, `filter _time`, or context).
6. Strict left-filtering; no accidental leading wildcards.
7. `fields` early when joining wide datasets.
8. `dedup` only on numbers/strings.
9. No placeholder text (TODO/TBD/`<placeholder>`).
10. SOAR-bound output exposes the intended `xdm.*` entities.
