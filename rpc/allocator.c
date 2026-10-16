#include <stdlib.h>
#include <rpc.h>

void *__RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void *allocation)
{
    free(allocation);
}
