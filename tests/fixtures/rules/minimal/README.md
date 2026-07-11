# Minimal synthetic Sigma rules (CI / trust smokes)

Two tiny `process_creation` rules for `null_sigma_run` trust checks without the
gitignored SigmaHQ corpus. Not a vendored rule set — structural fixtures only.

| File | Matches on |
|---|---|
| `cmd_whoami.yml` | `CommandLine` contains `whoami` |
| `powershell_encoded.yml` | `CommandLine` contains `powershell` |

Used by default when `RULE_DIR` is unset in `harness/scripts/smoke_*.sh`.
Override for local Tier B benches:

```bash
RULE_DIR=corpus/sigmahq/rules/windows/process_creation ./scripts/smoke_error_policy.sh
```
