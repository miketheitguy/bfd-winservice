# Logging queues, buffering, and shutdown

Donatello's output-worker notes, dude. This reference is for maintainers changing
logger ownership or diagnosing output loss. For configuration and event IDs,
use [Logs and events](../logging.md).

## Output queue and loss

Even a bodacious log pipeline has queue limits. One background writer handles
the text and ETW workload for the engine and its BGP worker. Packet processing
enqueues records without waiting for the writer's I/O. The queue holds up to
256 records. When it fills, additional records are dropped instead of waiting
for queue space.
Text messages are limited to 16 KiB on UTF-8 character boundaries. When output
resumes, the writer reports how many records were dropped to the enabled file
log. This diagnostic does not produce an Operational event.

## File rotation and buffering

Keep the log stash totally tubular and check rotation behavior. File output
rotates before a complete line would exceed 64 MiB. The writer renames the
active file to `LogFilePath` with `.1` appended, replacing the earlier backup,
and creates a new file. Each file stays within 64 MiB, including buffered bytes
and timestamps. Existing oversized files are rotated without extending them; the
logger does not shrink their existing contents.

If a reader denies delete sharing, rotation can fail. Lines that need rotation
are dropped from file output until rotation succeeds, with retries at most once
every 30 seconds as new lines arrive. If the rename succeeds but creating the
new file fails, file output stays paused and retries only creation; it never
appends to the backup. Operational ETW events continue independently. Rotation failures produce a diagnostic at each retry.

File output uses an 8 KiB buffer to group writes. While output is responsive,
the writer flushes pending bytes within 100 milliseconds, when the buffer
fills, before replacing the output file, and on normal shutdown. Library
callers can use `Logger::flush(timeout)` to wait for queued output and buffered
file bytes.

## Shutdown and timestamps

Ninja discipline includes knowing when an entry was written. Before reporting
Stopped, each service explicitly waits up to two seconds for queued output to
flush. Releasing the last logger then allows up to another 500 milliseconds for
the writer to drain. If output
remains blocked, execution ends without waiting for that writer. Queued events
can be lost in this case; abrupt termination can also lose buffered file
entries. File timestamps record when the writer formats each entry. Slow output
can delay that timestamp relative to the underlying BFD state change, and
buffering can delay when the entry becomes visible.

## Library API

`Logger::new()` returns `io::Result<Logger>` with ETW output.
`Logger::open(&options)` also opens the configured file when `LogToFile=1`.
Neither constructor accepts an execution-mode argument, and neither writes
diagnostics to STDOUT. Clones share one bounded worker.
`Logger::flush(timeout)` waits for queued output and buffered file bytes;
`Logger::dropped_records()` reports queue loss. Keep blocking flushes out of
the protocol timer loop. See [logger implementation](../../src/runtime/logging.rs).
