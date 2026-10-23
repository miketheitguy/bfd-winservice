# Rust validation guide

Cowabunga, validation crew. Use this guide to select checks for the code you
change and record what they establish. Maintainers should apply the local
[Rust engineering guidelines](.codex/skills/rust-skills/SKILL.md) to ownership,
borrowing, initialization, error handling, and native boundaries.

## Choose a validation task

Choose the checks that cover your change:

| Task | Guide |
| --- | --- |
| Run required tests, Clippy, formatting, and API documentation | [Development validation](docs/development/validation.md#required-checks) |
| Exercise optimized, ASan, Miri, and native paths | [Development validation](docs/development/validation.md) |
| Inspect both production executable images | [Hardening verification](docs/security/build-hardening.md#verification) |
| Review configuration snapshots and engine ownership | [Library development](docs/development/library.md) |
| Check RPC authentication, conversion, and cancellation | [Local RPC security](docs/security/local-rpc.md) and [status contract](docs/rpc-session-status-design.md) |
| Check provider lifetime and cleanup | [BGP provider contract](docs/reference/bgp-provider.md) |
| Validate installer policy and actual service tokens | [Disposable-host validation](docs/development/validation.md#validate-installed-service-security-in-a-disposable-vm) |
| Verify installed operation | [Setup](docs/setup.md), [monitoring](docs/monitoring.md), and [BGP actions](docs/bgp.md) |

## Review ownership and security boundaries

Check packet acceptance before state mutation, immutable configuration,
single-owner engine state, bounded queues, and native storage through
cancellation. Use the [review checklist](CODE_REVIEW.md) to cover the service,
provider, authentication-key, and installer boundaries.

The registry loader reads settings and decrypts `Secrets\AuthKeyDpapi` before
the engine starts. Review its bounded binary reads and DPAPI allocation owner
alongside the [key provisioning tool](scripts/Set-BfdAuthenticationKey.ps1).
Provisioning and runtime errors must omit key material.

## Record evidence and limits

Record the source revision, commands, target, exit status, skipped tests, and
artifact hashes for each validation run. A passing fixture applies to the paths
it exercises. Miri checks portable Rust logic; it does not execute Windows APIs
or the native RPC C bridge. ASan does not instrument Windows system DLLs.

Temporary HKCU keys, reduced copies of a test token, and loopback sockets do
not establish the installed SCM identity or external BGP interoperability.
Use a disposable installation to verify service-issued tokens, Secrets ACLs,
DPAPI decryption, repair, and shutdown. Test actual RRAS actions and peer
interoperability separately in an authorized network lab.
