# AttackIQ Detection-Validation Packages

Generate standalone attack-**simulation** packages used to validate that a detection fires.
This is defensive purple-team work: emulate adversary *behavior* with native utilities to
generate the exact telemetry a detection depends on, in an **authorized test environment**.

## Hard guardrails (non-negotiable)

- **No real malware, no working exploit payloads, no destructive actions.** Emulate behavior
  (spawn a process, touch a registry value, make a DNS query, write/read a benign file), do not
  weaponize.
- **Authorized environments only.** The package assumes the operator has authorization to run
  it on the target.
- **Always clean up** what the test created, and **never scrub the security logs** the test
  generated — those logs are the evidence the detection is validated against.
- Keep effects local, reversible, and clearly labeled as a test.

## Package layout

```
<technique-id>-<short-name>/
├── manifest.json
└── execute.py        (or execute.ps1 / execute.sh per target platform)
```

## manifest.json

Maps a stable UUIDv4, the target platform, the executor, and the MITRE ATT&CK
Tactic/Technique the test exercises.

```json
{
  "uuid": "f1e2d3c4-b5a6-4789-9abc-0123456789ab",
  "name": "T1059.001 - PowerShell Encoded Command Execution",
  "description": "Emulates encoded PowerShell command execution to validate the encoded-command detection. Decodes and prints a benign string; takes no malicious action.",
  "platform": "windows",
  "executor": "powershell",
  "entry": "execute.ps1",
  "mitre": {
    "tactic": "TA0002 - Execution",
    "technique": "T1059.001 - Command and Scripting Interpreter: PowerShell"
  },
  "cleanup": true,
  "elevation_required": false
}
```

Pick `platform` ∈ `windows|linux|macos`, `executor` ∈ `powershell|cmd|sh|bash|python`, and set
`entry` to the matching `execute.*` filename.

## execute.* (behavioral emulation + cleanup)

Structure every executor in three phases: **setup → emulate → cleanup**. Cleanup removes
artifacts the test created (files, registry values, scheduled items) but leaves the OS security
/ EDR logs intact.

### Example — execute.ps1 (Windows, encoded PowerShell emulation)

```powershell
# T1059.001 validation: encoded PowerShell command execution (benign).
# Generates the telemetry an "encoded command" detection relies on; takes no harmful action.

$ErrorActionPreference = 'Stop'
$marker = "$env:TEMP\aiq_t1059_001_marker.txt"

try {
    # --- EMULATE: run a benign EncodedCommand so the engine logs a -enc invocation ---
    $benign = 'Write-Output "AIQ-VALIDATION-T1059.001"'
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($benign))
    powershell.exe -NoProfile -EncodedCommand $enc | Out-File -FilePath $marker -Encoding utf8

    Write-Output "Emulation complete. Telemetry generated (Event ID 4104 / process create)."
}
finally {
    # --- CLEANUP: remove only the artifact this test created ---
    if (Test-Path $marker) { Remove-Item $marker -Force }
    # NOTE: do NOT clear Security/PowerShell Operational/EDR logs — they are the evidence.
}
```

### Example — execute.sh (Linux, suspicious-process emulation)

```sh
#!/bin/sh
# T1059.004 validation: shell exec pattern (benign). Generates process-launch telemetry.
set -e
MARKER="/tmp/aiq_t1059_004_marker"

# --- EMULATE ---
sh -c 'echo AIQ-VALIDATION-T1059.004' > "$MARKER"
echo "Emulation complete. Telemetry generated (process launch)."

# --- CLEANUP (artifact only; logs left intact) ---
rm -f "$MARKER"
```

## Output (per the § AttackIQ Test contract)

1. `manifest.json` code block.
2. `execute.{py|ps1|sh}` code block.
3. Then exactly two lines on packaging, e.g.:

```
# From the package root, zip both files at the top level (no parent folder):
zip -j T1059.001-encoded-powershell.zip manifest.json execute.ps1
```

The resulting zip drops directly into the AttackIQ interface for a drop-and-run scenario.
