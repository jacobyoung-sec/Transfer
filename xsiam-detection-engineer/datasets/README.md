# datasets/ — tenant sample events (user-supplied)

Drop ~30 representative sample events from each of your XSIAM datasets into the matching
category folder. These are the **source of truth for available field names** — the skill reads
them before writing any detection so it never invents fields.

| Folder | Put here |
|---|---|
| `cloud/` | Cloud audit / control-plane / IAM events (AWS CloudTrail, Azure Activity, GCP) |
| `edr/` | Endpoint telemetry (process, file, registry, network) e.g. `xdr_data` |
| `email/` | Email / phishing / mail-gateway / O365 events |
| `firewall/` | Firewall traffic, threat, URL, decryption logs (PAN-OS) |
| `network/` | Network flow / DNS / lateral-movement telemetry |

Accepted formats: `.json`, `.ndjson`, `.csv`, or `.txt`. One file per dataset is fine; name it
after the dataset (e.g. `xdr_data.json`).
