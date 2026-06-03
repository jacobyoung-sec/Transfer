# references/

Skill reference material. Two files here are **user-supplied**:

- `analytics.md` — **(you supply this)** A list of all analytics/detections currently enabled
  in your XSIAM tenant. The skill reads it first on every detection request to avoid building
  duplicates, and to advise verifying with AttackIQ whether a new detection is actually needed.
  If absent, the skill notes the dedup check could not run and proceeds.

The remaining files ship with the skill:

- `detection-matrix.md` — the Four-Perspective design philosophy.
- `xql-syntax.md` — XQL syntax grounded in official PANW docs.
- `correlation-rule-spec.md` — the 29-field correlation rule JSON schema + template.
- `soar-automation.md` — embedded-YAML Python scripts and playbook YAML structure.
- `attackiq-validation.md` — detection-validation package structure and guardrails.
