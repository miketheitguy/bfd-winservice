# BGP provider lifecycle and native contract

Cowabunga, provider maintainers. This reference owns the worker queues, recovery
budgets, shutdown ownership, and Windows RRAS MI contract. For peer setup and
the state-to-action rules, use [Control a Windows BGP peer](../bgp.md).

## Worker retries and broker recovery

Keep the retry story totally tubular, including its limits. A dedicated worker
handles provider calls while BFD continues running. Failed actions retry after
one second unless replaced by a newer action or shutdown. At most a Stop/Start
pair remains queued; Down discards queued Starts. An already issued call
finishes before the next action runs, unless shutdown queues a newer final
action, which cancels it.

SCM restarts a crashed broker after five seconds. An outstanding failed action
continues its normal retries; a completed action isn't replayed. A normal broker
Stop does not trigger automatic restart.
The broker supervises provider requests while Running as well as during Stop.
If a request, including schema lookup and cleanup, remains active for 20 seconds,
the watchdog exits the broker process and SCM recovery restarts it. The check
runs once per second; idle RPC waits do not count as stalled provider work.
If Stop was requested, the broker reports Stopped before exiting, preventing an
automatic restart.

When no action is pending, the BFD worker waits for a BFD state change. It sends
no connection probes and doesn't track broker instances. Startup sends no BGP
control calls; the first Up queries the peer before deciding whether to Start.

BGP control uses authenticated `ncalrpc` with a two-second bind deadline and a
30-second total call budget. A cancellation signal interrupts an in-flight call;
the native bridge retains its state, event, binding, and reply storage until
completion. If ownership cannot be established, BFD fails closed instead of
releasing pending storage. The broker admits one control manager and at most
one queued provider request. Cancelled or expired queued requests are discarded.
An auto-reset request event wakes the single consumer after enqueueing. While
idle, the dispatcher waits for either that event or the service stop signal,
giving stop priority when both are signaled. It does not poll an empty queue
every 50 milliseconds. This changes idle dispatch only; active-call cancellation
checks and provider watchdog supervision retain their existing budgets.
An MI operation already running can still finish after its RPC caller cancels;
cancellation does not roll it back. MI calls remain synchronous and can delay
broker cleanup.

The BFD worker shares the engine's background log writer. The broker has its own
ETW/text diagnostic writer and does not open the BFD file log. Slow log output
does not delay provider calls; the [logging queue limits](../logging.md#log-destinations)
apply to both processes.

### Provider timeouts and final cleanup

No pizza break until you understand the cleanup ownership, dude. Each Management
Infrastructure (MI) operation requests a five-second timeout, which is **not a
hard shutdown deadline**
([timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)).

Shutdown never queues a Stop. The latest queued action still runs, such as a Start that withdraws BFD's Stop or one queued by a recent Up. When an action is queued, an older in-flight call is cancelled, and each call of the final action runs within 20 seconds, including any wait for the broker to finish the cancelled call. If the final action fails, it is recorded as event 3; because the stop was requested, the SCM exit code stays `0` and recovery doesn't restart BFD. Final calls are not retried indefinitely.

If the broker's cleanup still runs 60 seconds after a Stop request, or BFD's still runs 60 seconds plus its AdminDown announcement period, the service reports Stopped and ends its process, leaving the BGP peer unchanged.

### Windows shutdown

Turtle power includes an orderly exit during Windows shutdown. BFD accepts the
SCM preshutdown notification instead of the shutdown notification. During
Windows shutdown it announces AdminDown and completes any final BGP action while
the broker, which stops in the later shutdown phase, is still running. The
installer sets the service's preshutdown timeout to 125 seconds, covering the
maximum 60-second announcement period, 60 seconds of cleanup, and final logs.
`MaxShutdownAnnounceMs` defaults to 30 seconds and limits shutdown delay from a
peer advertising very long timers. Truncating a Detection Time produces a
warning because the peer might classify the administrative stop as a failure.

## Native provider contract

The broker calls [`PS_BgpPeer`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/ps-bgppeer) in `root\Microsoft\Windows\RemoteAccess` through Rust bindings to `mi.dll` and the [MI client API](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_invoke).

Before Start, [`PS_BgpPeer.Get`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/get-ps-bgppeer) reads the selected peer. The broker uses the `Bgp.ConnectivityStatus` contract in the Windows RemoteAccess module's `PS_BgpPeer_v1.0.cdxml`: `Idle=1`, `Connecting=2`, and `Connected=3` mean started; `Stopped=4` means stopped. This also works when the CIM property omits enum qualifiers. An unknown status returns an error and does not authorize Start. The BFD handshake runs independently.

Each method receives a one-element `Name` string array and, when configured, `RoutingDomain`. [`Stop`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/stop-ps-bgppeer) also receives `Force=true`. All calls require successful MI completion. A status query also requires a non-null unsigned 32-bit `ReturnValue=0` and exactly one peer. Start and Stop can return empty output on RRAS; the broker reads the peer back and requires the requested started or stopped state before reporting success. Any explicit invalid or nonzero `ReturnValue` remains an error. Start checks for supersession before and after its status query; provider calls are not atomic with BFD state changes.
