# SOAR Automation & Playbooks

XSIAM/XSOAR automations are imported as **unified YAML** files with Python embedded in a
`script: |-` field, or as **playbook YAML** that orchestrates tasks. The platform injects
`CommonServerPython`, `CommonServerUserPython`, and the `demisto` object at runtime — do NOT
add `from CommonServerPython import *` or `import demistomock as demisto` to the embedded code.

## Python automation script

`CommonServerPython` provides: `BaseClient`, `CommandResults`, `DemistoException`,
`tableToMarkdown`, `return_results`, `return_error`, `argToList`, `argToBoolean`,
`arg_to_number`, `arg_to_datetime`, `assign_params`, `DBotScore`, `Common.*` indicator types,
`EntityRelationship`, `ScheduledCommand`, `fileResult`, and more.

### Standard output

```python
return CommandResults(
    readable_output=tableToMarkdown('Results', items, headers=['ID', 'Name', 'Status']),
    outputs_prefix='Vendor.Object',   # context path prefix
    outputs_key_field='id',           # dedup key
    outputs=items                     # list/dict stored in context
)
```

Return several at once by passing a list to `return_results([...])`.

### Containment script skeleton (host isolation)

```yaml
commonfields:
  id: IsolateEndpointOnHighSeverity
  version: -1
name: IsolateEndpointOnHighSeverity
script: |-
  def main():
      try:
          endpoint_id = demisto.args().get('endpoint_id')
          if not endpoint_id:
              return_error('endpoint_id is required')

          # Chain to the Cortex XDR integration to isolate the host
          res = demisto.executeCommand('xdr-isolate-endpoint', {'endpoint_id': endpoint_id})

          return_results(CommandResults(
              readable_output=tableToMarkdown(
                  'Isolation', [{'endpoint_id': endpoint_id, 'action': 'isolate', 'status': 'requested'}]),
              outputs_prefix='Containment.Isolation',
              outputs_key_field='endpoint_id',
              outputs={'endpoint_id': endpoint_id, 'action': 'isolate', 'status': 'requested'}
          ))
      except Exception as e:
          return_error(f'Failed to isolate endpoint: {e}')

  if __name__ in ('__builtin__', 'builtins', '__main__'):
      main()
type: python
subtype: python3
tags:
- containment
comment: Isolates an endpoint via Cortex XDR when triggered on a high-severity alert.
enabled: true
args:
- name: endpoint_id
  required: true
  description: The Cortex XDR endpoint ID to isolate.
outputs:
- contextPath: Containment.Isolation.endpoint_id
  description: Isolated endpoint ID.
  type: String
- contextPath: Containment.Isolation.status
  description: Isolation request status.
  type: String
scripttarget: 0
runonce: false
```

Use `execute_command()` / `demisto.executeCommand()` to chain integration commands rather than
re-implementing API clients. Wrap actions in try/except and surface failures with
`return_error`.

## Playbook YAML

Top-level field order (from real exports — keep exactly):

```
id, version, vcShouldKeepItemLegacyProdMachine, name, description, tags, starttaskid,
tasks, view, inputs, inputSections, outputSections, outputs
```

- `version` is always `-1`; `vcShouldKeepItemLegacyProdMachine` always `false`;
  `starttaskid` always `"0"`.
- `tasks` is a dict keyed by string IDs; `view` is a JSON string with
  `linkLabelsPosition` and `paper.dimensions`.
- Never include `fromversion`, `tests`, `marketplaces`, or `timeout` (CI-only fields).

Skeleton:

```yaml
id: contain-bruteforce-source
version: -1
vcShouldKeepItemLegacyProdMachine: false
name: Contain Brute Force Source
description: Blocks the source IP and disables the targeted account on a confirmed brute-force alert.
tags:
- Remediation
starttaskid: "0"
tasks:
  "0":
    id: "0"
    taskid: 00000000-0000-0000-0000-000000000000
    type: start
    task:
      id: 00000000-0000-0000-0000-000000000000
      version: -1
      name: ""
      iscommand: false
      brand: ""
    nexttasks:
      '#none#':
      - "1"
    separatecontext: false
view: |-
  {
    "linkLabelsPosition": {},
    "paper": {"dimensions": {"height": 1120, "width": 660, "x": 450, "y": 220}}
  }
inputs:
- key: SourceIP
  value: {}
  required: true
  description: The source IP from the correlation alert.
inputSections: []
outputSections: []
outputs: []
```

## XDM entity fields a playbook expects on the alert

Expose these from the detection so containment binds cleanly:

- `xdm.source.ipv4` / `xdm.source.ipv6` — IPs to block.
- `xdm.target.user.username` / `xdm.source.user.upn` — accounts to disable/reset.
- `xdm.target.host.hostname` / `xdm.source.host.hostname` — hosts to isolate.
- `xdm.target.process.command_line`, `xdm.target.process.executable.path` — forensic context.

## Output (per the § Automation contract)

Deliver the script/playbook block, then:
- **Inputs/Outputs:** args consumed and context outputs produced.
- **Operational Impact:** 1–2 sentences on the containment actions taken.
