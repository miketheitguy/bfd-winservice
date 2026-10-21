/* Linked from the static library only by the Rust test harness. No production
 * entry point references this object or raises synthetic exceptions. */
#include "exception_policy.h"

unsigned long bfd_rpc_test_native_asan_enabled(void)
{
#if defined(__SANITIZE_ADDRESS__)
    return 1;
#else
    return 0;
#endif
}

int bfd_rpc_test_exception_filter(unsigned long code)
{
    return bfd_rpc_exception_filter(code);
}

unsigned long bfd_rpc_test_raise(unsigned long code)
{
    unsigned long status = RPC_S_OK;
    RpcTryExcept {
        RpcRaiseException(code);
    }
    RpcExcept(bfd_rpc_exception_filter(RpcExceptionCode())) {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}
