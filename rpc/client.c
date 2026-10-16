/* Keep RPC structured exceptions and asynchronous-state lifetimes in C.
 * RpcExceptionFilter deliberately leaves fatal native faults unhandled; only
 * recoverable RPC exceptions become ordinary call errors. */
#include <windows.h>
#include <rpc.h>
#include <rpcasync.h>
#include "bfd_local_client.h"

/* A single supervised worker retains uncertain RPC ownership until process
 * exit. Never abort the provider host or free storage still used by RPC. */
__declspec(noreturn) static void retain_uncertain_call(void)
{
    for (;;) { Sleep(INFINITE); }
}

static RPC_STATUS initialize_async(RPC_ASYNC_STATE *state)
{
    RPC_STATUS status = RpcAsyncInitializeHandle(state, sizeof(*state));
    if (status != RPC_S_OK) {
        return status;
    }
    state->NotificationType = RpcNotificationTypeEvent;
    state->u.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    return state->u.hEvent != NULL ? RPC_S_OK : GetLastError();
}

static RPC_STATUS wait_async(RPC_ASYNC_STATE *state, unsigned long timeout_ms,
    void *binding, unsigned long *reply)
{
    DWORD wait = WaitForSingleObject(state->u.hEvent, timeout_ms);
    RPC_STATUS failure = RPC_S_OK;
    RPC_STATUS status;

    if (wait != WAIT_OBJECT_0) {
        failure = wait == WAIT_TIMEOUT ? RPC_S_CALL_CANCELLED : GetLastError();
        /* Abortive cancellation completes locally without a server response.
         * Retain the state and event until the runtime signals completion. */
        status = RpcAsyncCancelCall(state, TRUE);
        if (status != RPC_S_OK) {
            /* An error leaves call-storage ownership and bind state uncertain.
             * The broker supervisor quarantines this one retained worker. */
            retain_uncertain_call();
        }
        if (WaitForSingleObject(state->u.hEvent, INFINITE) != WAIT_OBJECT_0) {
            retain_uncertain_call();
        }
    }
    status = binding ? RpcAsyncGetCallStatus(state)
                     : RpcAsyncCompleteCall(state, reply);
    if (status == RPC_S_ASYNC_CALL_PENDING) {
        /* This event is configured only for final completion notification. */
        retain_uncertain_call();
    }
    if (binding != NULL && failure != RPC_S_OK && status == RPC_S_OK) {
        /* A bind can complete successfully while its deadline expires. The
         * Rust caller receives a failure and therefore will not unbind it. */
        if (RpcBindingUnbind(binding) != RPC_S_OK) {
            retain_uncertain_call();
        }
    }
    return failure != RPC_S_OK ? failure : status;
}

unsigned long bfd_rpc_bind(void *binding, unsigned long timeout_ms)
{
    RPC_ASYNC_STATE state = {0};
    RPC_STATUS status = initialize_async(&state);
    if (status != RPC_S_OK) {
        return status;
    }
    RpcTryExcept {
        status = RpcBindingBind(&state, binding,
            BfdClient_BfdLocal_v1_1_c_ifspec);
        if (status == RPC_S_OK) {
            status = wait_async(&state, timeout_ms, binding, NULL);
        }
    }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode())) {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    CloseHandle(state.u.hEvent);
    return status;
}

unsigned long bfd_rpc_call_probe(void *binding, unsigned long timeout_ms)
{
    RPC_ASYNC_STATE state = {0};
    unsigned long reply = RPC_S_CALL_FAILED;
    RPC_STATUS status = initialize_async(&state);
    if (status != RPC_S_OK) {
        return status;
    }
    RpcTryExcept {
        BfdClient_Probe(&state, binding);
        status = wait_async(&state, timeout_ms, NULL, &reply);
    }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode())) {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    CloseHandle(state.u.hEvent);
    return status == RPC_S_OK ? reply : status;
}

void *bfd_rpc_client_interface(void)
{
    return BfdClient_BfdLocal_v1_1_c_ifspec;
}

unsigned long bfd_rpc_call_status(void *binding, unsigned long timeout_ms,
    BFD_SESSION_STATUS_V1 *output)
{
    RPC_ASYNC_STATE state = {0};
    unsigned long reply = RPC_S_CALL_FAILED;
    RPC_STATUS status = initialize_async(&state);
    if (status != RPC_S_OK) { return status; }
    RpcTryExcept {
        BfdClient_GetSessionStatusV1(&state, binding, output);
        status = wait_async(&state, timeout_ms, NULL, &reply);
    }
    RpcExcept(RpcExceptionFilter(RpcExceptionCode())) {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    CloseHandle(state.u.hEvent);
    return status == RPC_S_OK ? reply : status;
}
