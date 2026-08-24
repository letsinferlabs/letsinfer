# Let's Infer canonical prefix-shared code workload

--- BEGIN EVENT LEDGER ---

{{BODY}}

--- END EVENT LEDGER ---

Fixture: `{{FIXTURE_ID}}`. Stream: `{{SLOT}}`.

Write a Python 3 function named `reconcile_events(lines)` that parses this
ledger-shaped input, preserves first-seen key order, keeps the final valid
state for each key, and returns both the ordered states and a count of rejected
lines. Include the function, concise type hints, and three focused assertions.
Do not use third-party packages. Finish with the exact verification marker
`{{MARKER}}`.
