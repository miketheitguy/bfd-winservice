# Release versioning

When preparing a release, use the
[version selection policy](CONTRIBUTING.md#choose-a-release-version) to judge
whether the complete change set warrants a patch, minor, or major increment.
Explain the compatibility and functionality impact in the release notes.

# Code Review Standards
Cowabunga, review crew! Like, dude, bring the receipts and kick shell by
checking the gnarly ownership edges. Turtle power means giving every P0/P1
issue its full attention, no cap. Keep it totally tubular: finish the review
checks before the pizza break.

When running the `/review` command, strictly evaluate all Rust code changes
against the user-installed `$rust-skills` skill and its referenced `rules/`
files. Focus heavily on P0/P1 constraints like memory layout, borrowing, and
ownership. If the skill is unavailable, report that the required review guidance
is missing before claiming that the review is complete.

# Agent skills

Maintain reusable skills in your user skill directory, outside this repository.
Use `$rust-security-hardening` for Rust security boundaries,
`$c-security-hardening` for the native RPC bridge and MIDL C stubs, and
`$cpp-ffi-safety` when changing the test-only C++ libFuzzer build. Use
`$windows-rpc-authentication` and `$windows-service-security` for their
respective Windows security boundaries.

Derive BFD-specific policy from the checked-in
[build hardening](docs/security/build-hardening.md),
[local RPC security](docs/security/local-rpc.md), and
[fuzzing](docs/security/fuzzing.md) documentation and the implementation.
Treat BFD profiles bundled with user skills as reuse examples; verify their
values against this checkout before applying them.
