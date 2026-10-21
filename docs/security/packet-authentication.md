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
- [S-BFD replay checks](#s-bfd-replay-checks)
- [Key configuration and storage](#key-configuration-and-storage)

## Packet and path validation

Ninja discipline checks the packet before trusting its observations. Before a
packet gets to influence peer state, dude, the firewall and packet validators
check the configured path. Configured wire authentication adds the shared-key
check.

`[AUTH A-fw]` represents Windows kernel UDP firewall filtering through the four
installed program-specific allow rules. `[AUTH A]` represents the application's
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

Classical multihop sessions that control BGP require `meticulous-md5` or
`meticulous-sha1` and a valid key. Startup rejects other modes even when a minimum
TTL is configured. TTL filtering does not authenticate an on-path sender.
Single-hop BGP without authentication logs a trusted-link warning; unauthenticated
multihop without BGP also warns, including when `MinTtl` is configured.

The supported modes provide these checks:

| `Auth` setting | Check and limitations |
| --- | --- |
| `none` | Protocol/path validation only. Traffic that passes those checks can influence the session and, where supported, its BGP actions without a shared-key check. Rejected for classical multihop BGP control. |
| `simple-password` | Verifies the key ID and matching password. The password travels in cleartext; this mode has no authentication sequence protection. |
| `keyed-md5`, `keyed-sha1` | Verifies the key ID and the RFC-defined digest of the packet with the configured key. Classical BFD enforces a receive sequence window but permits repeated sequences within the protocol rules. |
| `meticulous-md5`, `meticulous-sha1` | Uses the corresponding keyed digest and classical receive window, and rejects repeated sequences. |

The keyed modes follow BFD's MD5/SHA-1 packet format; they are not HMAC or
encryption. BFD authentication does not hide packet contents. A valid shared-key
check establishes possession of the configured secret, rather than a distinct
Windows or certificate identity for each peer.

## S-BFD replay checks

Give replay correlation the Donatello treatment, dude. Replay vibe check: S-BFD
initiators require keyed replies to match an unconsumed, unexpired outstanding
probe. Reflectors verify the configured authentication and copy a keyed
request's sequence into the response without maintaining a per-peer receive
window. These behaviors differ from a classical BFD session's replay checks.

## Key configuration and storage

Keep the key setup totally tubular and the storage permissions explicit. Keep
the key setup dialed in: configure exactly one of `AuthKey` (ASCII) and
`AuthKeyHex` (binary key encoded as hexadecimal) when authentication is enabled.
Password/MD5 keys are 1-16 bytes; SHA-1 keys are 1-20 bytes. `AuthKeyId` is
0-255. One key is active at a time; restart after changing authentication
settings. Keys are stored in Parameters under its protected ACL, without
application-level encryption. No cap: that ACL matters. Logs and configuration
errors omit key values. See
[Configure authentication](../configuration.md#authentication) for the settings
and an example.
