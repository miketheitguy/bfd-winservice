# Native RPC completion and lifetime policy

Use this policy for the asynchronous MIDL client/native bridge. Keep the supported API's actual state machine explicit rather than hiding it behind a generic timeout wrapper.

1. Initialize and retain `RPC_ASYNC_STATE`, its event, the binding, security policy storage, and all input/output buffers for the entire native operation.
2. Establish a real local deadline using asynchronous binding/calls and event waits. `RPC_C_OPT_CALL_TIMEOUT` is ignored for `ncalrpc`; it is not a local deadline mechanism.
3. On deadline or shutdown, request cancellation with `RpcAsyncCancelCall`, then drain native completion. Cancellation is a request, not proof that buffers are unused or that server work never executed.
4. For a procedure call, use the documented completion notification and `RpcAsyncCompleteCall` to finish the call and retrieve its result. Inspect both transport/completion and application statuses.
5. For asynchronous `RpcBindingBind`, observe bind completion via `RpcAsyncGetCallStatus`; do not treat it as a procedure call requiring `RpcAsyncCompleteCall`. If the bind succeeds after its deadline, unbind that late success before returning failure.
6. Unbind a bound handle before `RpcBindingFree`, then release associated security policy storage. Follow API-specific failure semantics instead of freeing a possibly active binding.

Never return while the runtime can still access a stack-based async state or output record. Never close its event, release a borrowed security descriptor/SID, or replace the worker while ownership is unresolved. Do not forcibly terminate a thread.

Choose and document a bounded process-specific failure policy. The BFD telemetry worker retains its one native stack and allocations on uncertainty; its supervisor quarantines telemetry without spawning replacements. The BFD-side BGP control worker is joined during shutdown, so unresolved native ownership terminates that process instead of returning into released storage. These are distinct policies, not a universal instruction to detach or abort every RPC client.

Do not retry non-idempotent work automatically after an ambiguous completion. Mark outcome unknown and reconcile using the operation's contract. A canceled/expired queued request should be discarded before privileged execution. If checking server cancellation, `RpcServerTestCancel` returns `RPC_S_OK` for cancellation and `RPC_S_CALL_IN_PROGRESS` when not canceled; do not invert them.

## Verification

Exercise bind timeout, normal call completion, call cancellation, server disappearance, late successful bind, uncertain ownership, bounded shutdown, and recovery after clean failures. Verify that every branch retains or releases the same resources according to the state machine. Keep the injected fault fixtures away from installed services and privileged live state.

## Primary references

- [RPC exception handling](https://learn.microsoft.com/en-us/windows/win32/rpc/exception-handling)
- [RpcExceptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcexceptionfilter)
- [Async RPC error handling](https://learn.microsoft.com/en-us/windows/win32/rpc/error-handling)
- [RpcBindingBind](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcbindingbind)
- [RpcAsyncCompleteCall](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcasynccompletecall)
- [RpcAsyncGetCallStatus](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcasyncgetcallstatus)
- [RpcServerTestCancel](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcservertestcancel)
