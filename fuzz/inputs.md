# Stateful fuzz input formats

Cowabunga, harness maintainers. Use this reference when changing corpus
generation, structured mutation, or crash reproduction. For commands, see
the [fuzz harness guide](README.md). The [security reference](../docs/security/fuzzing.md)
owns target boundaries and sanitizer limits.

## Session input format

The first byte modulo five selects `none`, `simple-password`, `keyed-sha1`,
`meticulous-sha1`, or `meticulous-md5`, in that order. All eight selector bits
supply the public value used to derive authentication test bytes. Each subsequent
64-byte frame has an operation byte, a time-advance byte in units of
10 milliseconds, and a payload.
The operation's low three bits select one of these actions:

| Value | Action |
| --- | --- |
| `0` | Receive the payload as arbitrary wire bytes. |
| `1` | Generate and sign a structurally valid packet from the payload. |
| `2` | Expire the session at the advanced time. |
| `3` | Attempt a timing update; classical sessions reject it. |
| `4` | Generate a signed packet, then set an invalid version. |
| `5` | Generate and sign a packet with the wrong receiver discriminator. |
| `6` | Generate and sign a packet with a zero sender discriminator. |
| `7` | Generate a signed packet, then remove its last byte. |

Actions `4` through `7` must be rejected without changing observable session
state. A final partial frame is accepted when it contains both control bytes.
Generated traffic keeps structural fields valid so mutations can explore state
transitions while raw reception covers rejection.

## Initiator input format

The `initiator` target uses the same selector, 64-byte frames, 10-millisecond
time advances, and 32-action limit as `session`. Its action values differ:

| Value | Action |
| --- | --- |
| `0` | Receive arbitrary response bytes. |
| `1` | Transmit a probe and immediately receive its valid reflected response. |
| `2` | Expire the session and clear expired probe tracking. |
| `3` | Apply nonzero TX/RX timing and detection-multiplier updates from the frame. |
| `4` | Transmit a probe whose response is lost. |
| `5` | Deliver a retained response, including delayed or already consumed replies. |
| `6` | Reject a signed unissued sequence and wrong discriminator, then accept the valid response. |
| `7` | Toggle reflector maintenance from the payload's low bit and exchange a probe. |

An independent bounded queue requires every accepted keyed response to match
an unconsumed, unexpired transmitted probe. The public packet API treats
generation as transmission; failed native sends and sequence wraparound remain
covered by focused crate regressions rather than this fuzz target.
