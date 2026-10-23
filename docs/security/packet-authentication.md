# BFD packet authentication

Cowabunga, packet crew. Check the shared-key policy alongside the path. Windows
admins and developers, let's check the packet receipts. This reference explains
how Bidirectional Forwarding Detection (BFD) and Seamless BFD (S-BFD) validate
remote packets, what each authentication mode proves, and how keys are
protected. Private service RPC uses a separate
[local authentication policy](local-rpc.md).

See the [security overview](../security.md) for the full boundary map. On this
page:

- [Packet validation](#packet-and-path-validation)
- [Authentication modes](#authentication-modes)
- [Authentication performance and mode selection](authentication-performance.md)
- [S-BFD replay checks](#s-bfd-replay-checks)
- [Key configuration and storage](#key-configuration-and-storage)

## Packet and path validation

Ninja discipline checks the packet before trusting its observations. Before a
packet gets to influence peer state, dude, the firewall and packet validators
check the configured path. Configured wire authentication adds the shared-key
check.

`[AUTH A-fw]` represents Windows kernel UDP filtering through the
[installed program-specific firewall rules](../reference/installation.md#installed-firewall-rules). `[AUTH A]` represents the application's
separate packet and path checks.

The UDP transport validates the source and destination, ports, interface, and
time to live (TTL)/hop limit for the configured role. Packet/session code
validates BFD structure and discriminators before accepting peer state. See [UDP
inputs and outputs](../service-communication.md#udp-inputs-and-outputs) for the
role-specific rules. These path checks alone do not authenticate the peer.

## Authentication modes

Turtle power starts with matching authentication settings on both peers. Like,
hello, turtle crew: `Auth` defaults to `none`. When enabled, both peers must use
the same authentication type, key ID, and secret. The receiver checks the
authentication section and compares the password or computed keyed digest using
constant-time equality. Authentication failures do not refresh detection or
update accepted session state. The sender adds the configured authentication to
outgoing packets.

Classical multihop sessions that control BGP require `meticulous-sha1` or
`meticulous-md5` and a valid key. Startup rejects other modes even when a minimum
TTL is configured. TTL filtering does not authenticate an on-path sender.
Single-hop BGP without authentication logs a trusted-link warning; unauthenticated
multihop without BGP also warns, including when `MinTtl` is configured.

The supported modes provide these checks:

| `Auth` setting | Check and limitations |
| --- | --- |
| `none` | Protocol/path validation only. Traffic that passes those checks can influence the session and, where supported, its BGP actions without a shared-key check. Rejected for classical multihop BGP control. |
| `simple-password` | Verifies the key ID and matching password. The password travels in cleartext; this mode has no authentication sequence protection. |
| `meticulous-md5` | Uses the RFC-defined MD5 keyed digest and classical receive window, and rejects repeated sequences. Available for peer compatibility and measured performance constraints. |
| `keyed-sha1` | Verifies the key ID and the RFC-defined digest of the packet with the configured key. Classical BFD enforces a receive sequence window but permits repeated sequences within the protocol rules. |
| `meticulous-sha1` | Uses the SHA-1 keyed digest and classical receive window, and rejects repeated sequences. |

Non-meticulous MD5 (`keyed-md5`, wire type 2) is unsupported; see
[authentication configuration](../configuration.md#authentication).

The keyed modes follow BFD's MD5 or SHA-1 packet format; they are not HMAC or
encryption. BFD authentication does not hide packet contents. A valid shared-key
check establishes possession of the configured secret, rather than a distinct
Windows or certificate identity for each peer.

For why meticulous MD5 is available, how SHA-1 and meticulous SHA-1 differ in
cost, and when MD5 may fit a deployment, see
[authentication performance and mode selection](authentication-performance.md).
That reference separates protocol requirements, this service's implementation,
and performance claims that require measurements.

## S-BFD replay checks

Give replay correlation the Donatello treatment, dude. Replay vibe check: S-BFD
initiators require keyed replies to match an unconsumed, unexpired outstanding
probe. Reflectors verify the configured authentication and copy a keyed
request's sequence into the response without maintaining a per-peer receive
window. These behaviors differ from a classical BFD session's replay checks.

## Key configuration and storage

Keep the key setup totally tubular and the storage permissions explicit. Keep
the key setup dialed in: provision `Parameters\Secrets\AuthKeyDpapi` with the
installed `Set-BfdAuthenticationKey.ps1` script when authentication is enabled.
Password and MD5 keys are 1-16 bytes; SHA-1 keys are 1-20 bytes. `AuthKeyId` is
0-255. One key is active at a time; restart after changing authentication
settings. The script stores raw key bytes encrypted with machine-scope DPAPI,
without optional entropy and verifies read-back decryption. The tool updates
only `Secrets\AuthKeyDpapi`.
The Secrets key has a protected ACL granting SYSTEM and Administrators full
control and the BFD service SID read access. Machine-scope DPAPI permits any
local account holding the ciphertext to decrypt it, so that ACL remains the
service-specific access boundary. Logs and configuration errors omit key values.
The service wipes temporary decrypted buffers and clears its owned key storage
when it is released; active packet authentication still requires key bytes in memory. See
[Configure authentication](../configuration.md#authentication) for the settings
and an example.
