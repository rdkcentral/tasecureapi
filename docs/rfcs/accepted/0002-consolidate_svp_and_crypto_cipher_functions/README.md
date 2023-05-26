# RFC 0002-Consolidate SVP and Crypto Cipher Functions

- Feature Name: Consolidate SVP and Non-SVP Cipher APIs
- Author(s): Eric Berry
- Start Date: 2021-06-23
- RFC PR: 0002
- Leader(s): Eric Berry

## Introduction

Comcast would like to consolidate SVP and non-SVP cipher functions rather than having separate
APIs.

## Motivation / use-cases

SecApi 2 Adapter is a library that implements the SecApi 2.3 API and delegates cryptographic calls
to the SecApi 3 library. The intention is that the SecApi 2 Adapter library can be introduced along
with a new SecApi 3 library and can provide compatability for applications and libraries that have
not upgraded to the new interface yet.

There is an incompatibility between the design of SecApi 2.3 and SecApi 3.  Specifically, the SecApi
2 SecCipher_ProcessOpaque function requires that the input buffer be an SVP buffer while the SecApi
3 sa_svp_cipher_process function requires that the input buffer be a clear buffer.  This means
that SecApi 2 Adapter would not be able to provide SVP operations to any library that needs it.

While trying to update the SecApi 3 design to support SVP based input buffers, we came to the
conclusion that we could simplify the SecApi 3 cipher API by eliminating separate SVP cipher
operations and consolidating them into non-SVP operations. The updated interfaces are in the
[Detailed Design](#detailed-design) below.

## Updates/Obsoletes

None

## Affected platforms

All

## Open Source Dependencies

None

## Detailed design

These are the consolidated interfaces:

```c
 typedef enum {
     SA_BUFFER_TYPE_CLEAR = 0,
     SA_BUFFER_TYPE_SVP
 } sa_buffer_type;

typedef struct {
    sa_buffer_type buffer_type;

    union {
        struct {
            void* buffer;
            size_t length;
            size_t offset;
        } clear;
        struct {
            sa_svp_buffer buffer;
            size_t offset;
        } svp;
    } context;
} sa_buffer;

sa_status sa_crypto_cipher_process(
    sa_buffer out,
    sa_crypto_cipher_context context,
    sa_buffer in,
    size_t bytes_to_process);

sa_status sa_crypto_cipher_process_last(
    sa_buffer out,
    sa_crypto_cipher_context context,
    sa_buffer in,
    size_t bytes_to_process,
    void* parameters);

sa_status sa_svp_key_check(
    sa_key key,
    sa_buffer in,
    size_t bytes_to_process,
    const void* expected,
    size_t expected_length);
```
The `sa_crypto_cipher_init` function now has an additional parameter `buffer_type` that indicates
whether the cipher operation requires SVP output buffers or clear output buffers.

The `sa_crypto_cipher_process`, `sa_crypto_cipher_process_last`, and `sa_svp_key_check` functions
will now allow either clear or SVP buffers for their in and out parameters. Usages of clear
buffers will require keys that allow SVP-optional rights.

These functions will be eliminated:
+ `sa_svp_crypto_cipher-init`
+ `sa_svp_crypto_cipher-process`
+ `sa_svp_crypto_cipher-process_last`
+ `sa_svp_crypto_cipher-release`
+ `sa_svp_crypto_cipher-update_iv`

## Drawbacks

Having a union for the in and out buffer parameters does make usage of the crypto APIs a little
more difficult because two extra structures for the out and in buffers will need to be populated
to submit a cipher process request.

## Alternatives considered

A design that added additional functions for SVP in buffers was considered but made the API more
complicated. It required two new function `sa_svp_cipher_process_insvp` and
`sa_svp_cipher_process_last_insvp` that provided svp buffers for the in parameter.

A similar design of adding an svp_buffer to only the in parameter of `sa_svp_cipher_process` and
`sa_svp_cipher_process_last` was also considered, which evolved into the proposed design.

## Unresolved questions

None
