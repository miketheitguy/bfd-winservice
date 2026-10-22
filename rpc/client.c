/* Keep RPC structured exceptions and asynchronous-state lifetimes in C.
 * RpcExceptionFilter deliberately leaves fatal native faults unhandled; only
 * recoverable RPC exceptions become ordinary call errors. */
#include <windows.h>
#include <rpc.h>
#include <rpcasync.h>
#include "bfd_local_client.h"
#include "bgp_control_client.h"
#include <stdlib.h>
#include "exception_policy.h"

#define BGP_CANCEL_DRAIN_TIMEOUT_MS 2000

/* Telemetry retains one supervised worker; BGP fails the BFD process closed.
 * Both policies preserve all storage still potentially owned by RPC. */
__declspec(noreturn) static void abandon_uncertain_call(BOOL fail_stop)
{
    if (fail_stop) {
        abort();
    }
    for (;;) {
        Sleep(INFINITE);
    }
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
    void *binding, unsigned long *reply, HANDLE cancel, BOOL fail_stop)
{
    HANDLE events[2] = {state->u.hEvent, cancel};
    DWORD wait = WaitForMultipleObjects(cancel ? 2 : 1, events, FALSE, timeout_ms);
    RPC_STATUS failure = RPC_S_OK;
    RPC_STATUS status;

    if (wait != WAIT_OBJECT_0) {
        failure = wait == WAIT_OBJECT_0 + 1 ? ERROR_OPERATION_ABORTED
            : wait == WAIT_TIMEOUT ? RPC_S_CALL_CANCELLED : GetLastError();
        /* Abortive cancellation completes locally without a server response.
         * Retain the state and event until the runtime signals completion. */
        status = RpcAsyncCancelCall(state, TRUE);
        if (status != RPC_S_OK) {
            /* An error leaves call-storage ownership and bind state uncertain.
             * Apply the caller's retention or fail-stop policy. */
            abandon_uncertain_call(fail_stop);
        }
        if (WaitForSingleObject(state->u.hEvent,
                fail_stop ? BGP_CANCEL_DRAIN_TIMEOUT_MS : INFINITE) != WAIT_OBJECT_0) {
            abandon_uncertain_call(fail_stop);
        }
    }
    status = binding ? RpcAsyncGetCallStatus(state)
                     : RpcAsyncCompleteCall(state, reply);
    if (status == RPC_S_ASYNC_CALL_PENDING) {
        /* This event is configured only for final completion notification. */
        abandon_uncertain_call(fail_stop);
    }
    if (binding != NULL && failure != RPC_S_OK && status == RPC_S_OK) {
        /* A bind can complete successfully while its deadline expires. The
         * Rust caller receives a failure and therefore will not unbind it. */
        if (RpcBindingUnbind(binding) != RPC_S_OK) {
            abandon_uncertain_call(fail_stop);
        }
    }
    return failure != RPC_S_OK ? failure : status;
}

/* Every boundary uses the same Windows SEH filter. Initiation exceptions have
 * already cleaned up RPC state; accepted operations drain completion before we
 * close the event. Do not catch faults around Rust server managers: SEH must
 * never unwind through Rust frames. MIDL/RPC owns server-side NDR exceptions. */
static RPC_STATUS bind_async(void *binding, unsigned long timeout_ms,
    RPC_IF_HANDLE interface_spec, BOOL fail_stop)
{
    RPC_ASYNC_STATE state = {0};
    RPC_STATUS status = initialize_async(&state);
    if (status != RPC_S_OK) {
        return status;
    }
    RpcTryExcept {
        status = RpcBindingBind(&state, binding, interface_spec);
        if (status == RPC_S_OK) {
            status = wait_async(&state, timeout_ms, binding, NULL, NULL, fail_stop);
        }
    }
    RpcExcept(bfd_rpc_exception_filter(RpcExceptionCode())) {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    CloseHandle(state.u.hEvent);
    return status;
}

unsigned long bfd_rpc_bind(void *binding, unsigned long timeout_ms)
{
    return bind_async(binding, timeout_ms, BfdClient_BfdLocal_v2_0_c_ifspec, FALSE);
}

void *bfd_rpc_client_interface(void)
{
    return BfdClient_BfdLocal_v2_0_c_ifspec;
}

unsigned long bfd_rpc_call_status(void *binding, unsigned long timeout_ms,
    BFD_SESSION_STATUS_V1 *output)
{
    RPC_ASYNC_STATE state = {0};
    unsigned long reply = RPC_S_CALL_FAILED;
    RPC_STATUS status = initialize_async(&state);
    if (status != RPC_S_OK) {
        return status;
    }
    RpcTryExcept {
        BfdClient_GetSessionStatusV1(&state, binding, output);
        status = wait_async(&state, timeout_ms, NULL, &reply, NULL, FALSE);
    }
    RpcExcept(bfd_rpc_exception_filter(RpcExceptionCode())) {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    CloseHandle(state.u.hEvent);
    return status == RPC_S_OK ? reply : status;
}

/* BGP's worker is joined during BFD shutdown. Uncertain ownership fails the
 * process closed rather than freeing pending storage or hanging that join. */
unsigned long bgp_rpc_bind(void *binding, unsigned long timeout_ms)
{
    return bind_async(binding, timeout_ms, BgpClient_BgpControl_v2_0_c_ifspec, TRUE);
}

unsigned long bgp_rpc_call(void *binding, unsigned long timeout_ms,
    HANDLE cancel, unsigned long operation, BGP_CONTROL_RESULT *output)
{
    RPC_ASYNC_STATE state = {0};
    unsigned long reply = RPC_S_CALL_FAILED;
    RPC_STATUS status = initialize_async(&state);
    if (status != RPC_S_OK) {
        return status;
    }
    RpcTryExcept {
        BgpClient_Control(&state, binding, operation, output);
        status = wait_async(&state, timeout_ms, NULL, &reply, cancel, TRUE);
    }
    RpcExcept(bfd_rpc_exception_filter(RpcExceptionCode())) {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    CloseHandle(state.u.hEvent);
    return status == RPC_S_OK ? reply : status;
}
