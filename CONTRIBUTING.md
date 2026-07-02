# Contributing to null-sigma

## Prerequisites

- Rust stable (≥ 1.82, matching `rust-version` in `Cargo.toml`)
- `cargo` with `rustfmt` and `clippy` components

## Running tests

```bash
cargo test
```

166 tests across four suites: unit, corpus replay, proptest property-based,
and integration. All must pass before submitting a PR.

## Running benchmarks

```bash
cargo bench
```

Criterion generates HTML reports at `target/criterion/report/index.html`.
If your change affects a hot path, include before/after median timings in the
PR description.

## Code standards

All four CI checks must pass:

```bash
cargo fmt -- --check      # formatting
cargo clippy -- -W clippy::all -W clippy::pedantic   # lint
cargo test                # tests
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps        # docs
```

Run `cargo fmt` before pushing — the CI will reject unformatted code.

## Adding a Sigma modifier

1. Add the variant to `ValueModifier` in `src/types.rs`
2. Add the string mapping in `ValueModifier::from_str`
3. Implement the matching logic in `src/matcher.rs`
4. Add at least one passing and one non-matching test in `tests/sigma_tests.rs`
5. Update the modifier table in `README.md`

## Reporting security issues

See [SECURITY.md](SECURITY.md).
