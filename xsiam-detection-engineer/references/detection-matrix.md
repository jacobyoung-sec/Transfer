# The Four-Perspective Detection Matrix

Every detection is designed at the intersection of four roles. A detection that satisfies only
one or two is fragile, noisy, or un-automatable. Walk all four before finalizing logic.

## 1. The Adversary (Red Team) — durability

Anchor detection on **behavioral choke points** an attacker cannot avoid without abandoning
the technique, not on cosmetic indicators they can trivially change.

- **Prefer:** the mechanic itself — e.g., a non-`lsass.exe` process opening a handle to
  `lsass.exe` with `PROCESS_VM_READ`; a service binary spawning `cmd.exe`/`powershell.exe`;
  OAuth token reuse from a new ASN; eBPF program loads from a non-baseline path.
- **Reject (brittle):** specific hashes, single static IPs, exact file paths, exact tool
  names, exact command-line strings. These cost the attacker one edit to bypass.
- **Test of durability:** "What must the attacker change to evade this?" If the answer is
  "rename a file" or "swap an IP," redesign around the underlying behavior.

## 2. The Consumer (SOC Analyst) — fidelity & actionability

The alert lands on a human under time pressure.

- High signal-to-noise: pre-aggregate, threshold, and suppress so the alert means something.
- Carry forensic context in the output: who, what process/parent, where (host/IP), when, and
  the exact evidence that tripped the rule.
- The alert name and description should let an analyst start triage without re-querying.
- Favor a slightly tighter rule that an analyst trusts over a broad one they learn to ignore.

## 3. The Orchestrator (SOAR Engineer) — automation-readiness

The alert may feed an automated containment playbook. Outputs must bind cleanly.

- Expose **standardized XDM entity fields**, not raw vendor fields, wherever a playbook will
  consume them. Core entities:
  - `xdm.source.ipv4` / `xdm.source.ipv6`
  - `xdm.target.user.username` / `xdm.source.user.username` / `xdm.source.user.upn`
  - `xdm.target.process.command_line` / `xdm.source.process.command_line`
  - `xdm.target.host.hostname` / `xdm.source.host.hostname`
  - `xdm.target.process.executable.path`, `xdm.network.dns.dns_question.name`
- Keep entity fields populated (avoid nulls a playbook would branch on unexpectedly).
- Stable field names across related detections so one playbook can serve many rules.

## 4. The Detection Engineer (DaC) — code quality & performance

Detections are code: modular, version-controlled, idempotent, reviewable, and fast.

- **Strict left-filtering:** push the most selective `filter` as early and as far left as
  possible so the engine scans the least data. Filter on indexed/native fields before derived
  ones.
- **Avoid unindexed leading wildcards:** `field contains "*x"` and `field ~= ".*x$"` force
  expensive scans. Prefer prefix matches, equality, `in (...)`, or `incidr()`.
- **Order of operations:** `filter` (reduce) → `alter` (derive) → `comp` (aggregate) →
  post-`comp` `filter` (threshold) → `fields` (project) → `sort`/`limit`. Project with
  `fields` *before* a `join` on wide datasets to cut columns early.
- **Minimize heavy stages:** keep `comp` group cardinality bounded; constrain `join` inputs
  with filters/`fields` on both sides; avoid `join` when a `comp` + `array` approach works.
- **Idempotent & modular:** one behavior per rule, deterministic output, no side effects in
  detection logic, MITRE-mapped, suppression configured.

## Applying the matrix

When you present a detection, you have implicitly answered:
- Adversary: what behavior is the choke point, and what would it cost to evade?
- Consumer: is the alert self-explanatory and low-noise?
- Orchestrator: which `xdm.*` entities are exposed for containment?
- Engineer: is it left-filtered, wildcard-clean, and idempotent?
