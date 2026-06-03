# Correlation Rule JSON Specification

XSIAM imports/exports correlation rules as a **JSON array** of rule objects — even a single
rule is `[{...}]`. Field order below matches real exports; keep it for clean diffs and reliable
round-trip import/export. Newlines inside `xql_query` are encoded as `\n`.

Official references:
- What's a correlation rule: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/What-s-a-correlation-rule
- Create a correlation rule: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Create-a-correlation-rule
- Correlation rule details: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Correlation-rule-details

## Canonical field order (29 fields)

```
rule_id, name, severity, xql_query, is_enabled, description, alert_name, alert_category,
alert_type, alert_description, alert_domain, alert_fields, execution_mode, search_window,
simple_schedule, timezone, crontab, suppression_enabled, suppression_duration,
suppression_fields, dataset, user_defined_severity, user_defined_category, mitre_defs,
investigation_query_link, drilldown_query_timeframe, mapping_strategy, action, lookup_mapping
```

## Field reference

| Field | Type | Notes |
|---|---|---|
| `rule_id` | int | Unique per tenant. Prompt the user if not supplied. |
| `name` | string | Display name in the correlations list. |
| `severity` | string | Enum (see below) or `"User Defined"` for dynamic severity. |
| `xql_query` | string | Detection logic ONLY, `\n`-escaped. No alert metadata inside. |
| `is_enabled` | bool | `true` by default. |
| `description` | string\|null | What it detects and why. |
| `alert_name` | string | Name on generated alerts; supports `$field` references. |
| `alert_category` | string | Fixed value like `"OTHER"`, or `"User Defined"` for dynamic. |
| `alert_type` | null | Reserved — always `null`. |
| `alert_description` | string\|null | Alert description; supports `$field`. |
| `alert_domain` | string | Domain classification (e.g. `"DOMAIN_SECURITY"`). |
| `alert_fields` | object\|null | `{"display": "xdm.field.path"}` mappings surfaced on the alert. |
| `execution_mode` | string | `"REAL_TIME"` or `"SCHEDULED"`. |
| `search_window` | string\|null | SCHEDULED only (e.g. `"1 hours"`); `null` for REAL_TIME. |
| `simple_schedule` | string\|null | SCHEDULED only; mirrors crontab; `null` for REAL_TIME. |
| `timezone` | string\|null | SCHEDULED only (e.g. `"UTC"`); `null` for REAL_TIME. |
| `crontab` | string\|null | SCHEDULED only, 5-field cron; `null` for REAL_TIME. |
| `suppression_enabled` | bool | Enable duplicate suppression. |
| `suppression_duration` | string\|null | Required when enabled (e.g. `"1 hours"`); else `null`. |
| `suppression_fields` | array\|null | Fields defining a "duplicate"; `null` when disabled. |
| `dataset` | string | Always `"alerts"`. |
| `user_defined_severity` | string\|null | XDM field ref; required when severity is `"User Defined"`. |
| `user_defined_category` | string\|null | XDM field ref; required when category is `"User Defined"`. |
| `mitre_defs` | object | Labeled MITRE map (see below); `{}` if none. |
| `investigation_query_link` | string\|null | Optional investigation link; often `""`. |
| `drilldown_query_timeframe` | string | Usually `"ALERT"`. |
| `mapping_strategy` | string | Usually `"AUTO"`. |
| `action` | string | Always `"ALERTS"`. |
| `lookup_mapping` | array\|null | Usually `null`. |

## Severity enum

`SEV_010_CRITICAL`, `SEV_020_HIGH`, `SEV_030_MEDIUM`, `SEV_040_LOW`,
`SEV_060_INFORMATIONAL` — **there is no `SEV_050`** (intentional). Or `"User Defined"`.

- Static: `"severity": "SEV_030_MEDIUM"`, `"user_defined_severity": null`.
- Dynamic: `"severity": "User Defined"`, `"user_defined_severity": "<xdm.field>"`, and compute
  that field in the XQL with `if()`.

## Execution mode

| Mode | When | Schedule fields | Allowed XQL stages |
|---|---|---|---|
| `REAL_TIME` | Each matching event is independently alertable | all four `null` | `dataset`/`datamodel`, `filter`, `alter`, `fields`, `config` only |
| `SCHEDULED` | Counting/grouping/comparing across events | all four required | full XQL incl. `comp`, `join`, `sort`, `dedup` |

- REAL_TIME: no `comp`/`sort`/`dedup`/`join`.
- SCHEDULED: set `search_window` to ≥ 2× the cron interval to avoid coverage gaps.

## MITRE mapping (labeled format)

```json
"mitre_defs": {
  "TA0006 - Credential Access": ["T1110 - Brute Force", "T1110.001 - Password Guessing"]
}
```

Tactic keys `"TA#### - Name"`; technique values `"T#### - Name"` / `"T####.### - Sub Name"`.
Map to the most specific technique; `{}` when none.

## Suppression guidance

- Enable for most detections to curb alert fatigue.
- `suppression_duration` human-readable: `"15 minutes"`, `"30 minutes"`, `"1 hours"`.
- `suppression_fields` = what defines a duplicate (e.g. `["source_ip"]`, `["user_name"]`).
- Disabled → both `suppression_duration` and `suppression_fields` are `null`.

## Worked template (SCHEDULED threshold detection)

```json
[
  {
    "rule_id": 1001,
    "name": "Windows Failed Logon Burst (Brute Force)",
    "severity": "SEV_020_HIGH",
    "xql_query": "dataset = xdr_data\n| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id = 4625\n| alter src_ip = action_remote_ip, user_name = lowercase(action_username)\n| comp count() as failed_count by src_ip, user_name\n| filter failed_count >= 20\n| alter xdm.source.ipv4 = src_ip, xdm.target.user.username = user_name\n| fields src_ip, user_name, failed_count, xdm.source.ipv4, xdm.target.user.username",
    "is_enabled": true,
    "description": "Detects 20+ failed Windows logons (Event ID 4625) for a single source IP / user pair within the search window, indicating password brute force.",
    "alert_name": "Failed Logon Burst from $src_ip",
    "alert_category": "OTHER",
    "alert_type": null,
    "alert_description": "$failed_count failed logons for $user_name from $src_ip.",
    "alert_domain": "DOMAIN_SECURITY",
    "alert_fields": {
      "Source IP": "xdm.source.ipv4",
      "Username": "xdm.target.user.username"
    },
    "execution_mode": "SCHEDULED",
    "search_window": "1 hours",
    "simple_schedule": "Every 30 minutes",
    "timezone": "UTC",
    "crontab": "*/30 * * * *",
    "suppression_enabled": true,
    "suppression_duration": "1 hours",
    "suppression_fields": ["src_ip", "user_name"],
    "dataset": "alerts",
    "user_defined_severity": null,
    "user_defined_category": null,
    "mitre_defs": {
      "TA0006 - Credential Access": ["T1110 - Brute Force"]
    },
    "investigation_query_link": "",
    "drilldown_query_timeframe": "ALERT",
    "mapping_strategy": "AUTO",
    "action": "ALERTS",
    "lookup_mapping": null
  }
]
```

## Pre-delivery checklist

1. Valid JSON, wrapped in an array, no trailing commas.
2. All 29 fields present in canonical order (including `null`s).
3. `rule_id` is an integer (prompted if unknown).
4. Severity enum valid (no `SEV_050`).
5. `dataset` = `"alerts"`, `action` = `"ALERTS"`, `alert_type` = `null`.
6. REAL_TIME → schedule fields all `null` and XQL uses only allowed stages.
7. SCHEDULED → all four schedule fields set; `search_window` ≥ 2× interval.
8. Durations human-readable (`"1 hours"`, `"15 minutes"`).
9. `mitre_defs` labeled format; most specific technique.
10. Suppression fields match what defines a duplicate for THIS detection.
11. XQL is detection logic only; SOAR entity fields exposed via `alter`/`fields`.
