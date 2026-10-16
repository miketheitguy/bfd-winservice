/* NDR owns marshaling; Rust repeats authentication before dispatch. */
#include <windows.h>
#include <rpc.h>
#include <stddef.h>
#include "bgp_control_server.h"

extern unsigned long bgp_rpc_control(void *binding, unsigned long operation,
    BGP_CONTROL_RESULT *result);

unsigned long BgpServer_Control(handle_t binding, unsigned long operation,
    BGP_CONTROL_RESULT *result)
{
    return bgp_rpc_control(binding, operation, result);
}

void *bgp_rpc_server_interface(void)
{
    return BgpServer_BgpControl_v1_0_s_ifspec;
}

unsigned long bgp_rpc_result_layout(unsigned long field)
{
    switch (field) {
    case 0: return sizeof(BGP_CONTROL_RESULT);
    case 1: return __alignof(BGP_CONTROL_RESULT);
    case 2: return offsetof(BGP_CONTROL_RESULT, status);
    case 3: return offsetof(BGP_CONTROL_RESULT, value);
    default: return 0;
    }
}
