# Writing detections

A rule is one YAML mapping. Save it in the console (Detections) or
`POST /api/v1/rules {"yaml": "..."}`.

```yaml
id: PC-CUSTOM-001
title: Database dump written to a temp directory
description: pg_dump or mysqldump writing into /tmp.
severity: medium            # info | low | medium | high | critical
mitre: [T1005, T1074.001]
kind: process_start         # omit to match every event kind
match:
  all:                      # every condition must hold
    - { field: process.name, op: in, value: [pg_dump, mysqldump] }
    - { field: process.cmdline, op: regex, value: '(/tmp/|/dev/shm/)' }
  any: []                   # at least one must hold (if present)
  none: []                  # none may hold
threshold:                  # optional: fire on the Nth match in a window
  count: 3
  window_secs: 300
  group_by: process.user
response: []                # kill_process | quarantine_file | isolate_host (protect mode only)
```

## Operators

| op | Meaning |
|---|---|
| `eq` | exact match |
| `contains` | case-insensitive substring |
| `startswith`, `endswith` | prefix / suffix |
| `in` | value is one of a list |
| `regex` | Rust `regex` syntax (no look-around or backreferences); prefix `(?i)` for case-insensitive |
| `gt`, `lt` | numeric comparison |
| `exists` | field is present |

Numbers are compared as text for `eq` and `in`, so quote them in lists:
`value: ['3333', '4444']`.

## Fields

See the event model in [ARCHITECTURE.md](ARCHITECTURE.md). Third-party events
sent through `/api/v1/ingest` can carry any field name; rules address them the
same way.

## Guidance

- Match on behaviour (parent/child, arguments, paths), not only on names an
  attacker can change.
- Use `none` to carve out known-good tooling instead of loosening the match.
- Leave `response` empty until the rule has run quietly in `detect` mode.
- Identical alerts (same rule, endpoint and subject) within 60 seconds are
  collapsed.
