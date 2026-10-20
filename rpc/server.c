/* The generated NDR server stub owns marshaling; Rust owns authorization. */
#include <windows.h>
#include <rpc.h>
#include <stddef.h>
#include "bfd_local_server.h"

extern unsigned long bfd_rpc_get_session_status(void *binding,
    BFD_SESSION_STATUS_V1 *status);

void *bfd_rpc_server_interface(void)
{
    return BfdServer_BfdLocal_v2_0_s_ifspec;
}

unsigned long BfdServer_GetSessionStatusV1(handle_t binding,
    BFD_SESSION_STATUS_V1 *status)
{
    return bfd_rpc_get_session_status(binding, status);
}

unsigned long bfd_rpc_status_layout(unsigned long field)
{
    switch (field) {
    case 0: return sizeof(BFD_SESSION_STATUS_V1);
    case 1: return __alignof(BFD_SESSION_STATUS_V1);
    case 2: return offsetof(BFD_SESSION_STATUS_V1, instance);
    case 3: return offsetof(BFD_SESSION_STATUS_V1, sequence);
    case 4: return offsetof(BFD_SESSION_STATUS_V1, role);
    case 5: return offsetof(BFD_SESSION_STATUS_V1, local_address);
    case 6: return offsetof(BFD_SESSION_STATUS_V1, peer_address);
    case 7: return offsetof(BFD_SESSION_STATUS_V1, source_address);
    default: return 0;
    }
}
