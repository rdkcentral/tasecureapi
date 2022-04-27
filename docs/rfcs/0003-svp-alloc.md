- Feature Name: SVP Memory Alloc in REE
- Author(s): Eric Berry
- Start Date: 2021-12-02
- RFC PR:
- Leader(s):

## Introduction

Some DRM vendors need to allocate SVP memory regions outside the SecApi 3 TA. This update formalizes
this to do the memory allocation outside the SecApi 3 TA.

## Motivation / use-cases

With the adoption of RFC 0002, SecApi 3 created functions to allocate and free SVP memory. Some
vendors required that SVP memory be allocated and freed outside the TA. To facilitate this
requirement, new functions: sa_svp_memory_alloc and sa_svp_memory_free will be created to
perform this function. The functions sa_svp_buffer_alloc and sa_svp_buffer_free will then be
updated to use sa_svp_memory_alloc and sa_svp_memory_free to perform the memory allocation. If a
vendor requires these functions to be implemented inside the TA, the vendor can then add these
functions to their TA interface.

Regardless of whether the SVP memory region is allocated in the REE or the TA, SVP memory regions
must be secure and only accessible by the TA.

## Updates/Obsoletes

None

## Affected platforms

All

## Open Source Dependencies

None

## Detailed design

New functions added to sa_svp.h

```c

/**
 * Allocate an SVP memory block.
 *
 * @param[out] svp_memory pointer to the SVP memory region.
 * @param[in] size Size of the restricted SVP memory region in bytes.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - svp_memory is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_svp_memory_alloc(
        void** svp_memory,
        size_t size);

/**
 * Free an SVP memory block.
 *
 * @param[in] svp_memory pointer to the SVP memory region.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - svp_memory is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_svp_memory_free(void* svp_memory);
```

These functions may be implemented in the REE or in the TA. The svp_memory parameter can then be
passed to sa_svp_buffer_create or sa_svp_buffer_release to incorporate into an SVP buffer.

The following functions will be slightly changed so that the parameter names correspond to the above
functions.

```c
sa_status sa_svp_buffer_create(
        sa_svp_buffer* svp_buffer,
        void* svp_memory,
        size_t size);

sa_status sa_svp_buffer_release(
        void** svp_memory,
        size_t* size,
        sa_svp_buffer svp_buffer);
```

Function definitions before the change:

```c
sa_status sa_svp_buffer_create(
        sa_svp_buffer* svp_buffer,
        void* buffer,
        size_t size);

sa_status sa_svp_buffer_release(
        void** out,
        size_t* out_length,
        sa_svp_buffer svp_buffer);
```

## Drawbacks

None

## Alternatives considered

None

## Unresolved questions

None

