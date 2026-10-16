#ifndef BFD_RPC_EXCEPTION_POLICY_H
#define BFD_RPC_EXCEPTION_POLICY_H

#include <rpc.h>

/* Use Microsoft's RPC filter at every maintained client SEH boundary. Fatal
 * native faults continue searching for a handler; they are never RPC success
 * or ordinary transport errors. Keep SEH inside C, away from Rust managers. */
static __inline int bfd_rpc_exception_filter(unsigned long code)
{
    return RpcExceptionFilter(code);
}

#endif
