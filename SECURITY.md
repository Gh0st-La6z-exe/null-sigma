# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ Active |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via GitHub's
[Security Advisories](https://github.com/Gh0st-La6z-exe/null-sigma/security/advisories/new)
feature. This keeps the details confidential until a fix is released.

Include in your report:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The version(s) affected
- Any suggested fix if you have one

## Response Timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix and disclosure**: coordinated with the reporter; target within 30 days
  for confirmed vulnerabilities

## Scope

The published library (`null-sigma` **0.1.x** on crates.io) parses untrusted
YAML (Sigma rules) and evaluates untrusted event data (flat maps, and nested
JSON when the `json` feature is enabled). Both are attack surfaces.

Sibling packages in this repository (`null-sigma-cli`, the harness
`null_sigma_run`) inherit the same event/rule surfaces plus JSONL ingest.
Report CLI/harness ingest panics or trust-contract failures here as well;
they are not separate crates.io products yet.

In-scope vulnerabilities include:
- Panics on malformed YAML input (`parse_rule`, `parse_rules`)
- Panics on arbitrary event data (`evaluate_event`, `evaluate_batch`,
  `evaluate_json` / flatten path with `json`)
- Panics or silent detection loss on malformed JSONL ingest (CLI / harness)
- Regex denial-of-service via crafted `|re` patterns
- Incorrect detection results (false negatives) that could allow evasion
- Memory safety issues (though the crate uses `#![forbid(unsafe_code)]`)

Out of scope:
- Issues in upstream dependencies (report directly to those crates)
- Performance degradation without correctness impact
