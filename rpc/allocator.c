#include <stdlib.h>
#include <rpc.h>

/* Preserve the allocation and invalidation contracts declared by rpcndr.h. */
_Use_decl_annotations_
void *__RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

_Use_decl_annotations_
void __RPC_USER midl_user_free(void *allocation)
{
    free(allocation);
}
