# Contributing to null-sigma

## Prerequisites

- Rust stable (≥ 1.82, matching `rust-version` in `Cargo.toml`)
- `cargo` with `rustfmt` and `clippy` components
- Windows: Rustup with the MSVC Rust host and Visual Studio Build Tools with the
  **Desktop development with C++** workload, including the MSVC toolset and
  Windows SDK

The repository does not include Rustup or Visual Studio installer binaries.
Install those prerequisites locally. A plain PowerShell session may not have
`cl.exe` and `link.exe` on `PATH`; use **Developer
PowerShell for VS 2022** or initialize the environment first:

```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc
cmd /c 'call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul & cargo test'
```

If that command reports that `link.exe` cannot be found, modify the Build Tools
installation and add the **Desktop development with C++** workload. Do not
install or use the GNU host unless MinGW compatibility is an explicit goal;
the GNU host requires `dlltool.exe` and is not the supported Windows path.

## Running tests

```bash
cargo test
```

The suite covers unit, corpus replay, proptest property-based, and integration
tests. All must pass before submitting a PR.

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
