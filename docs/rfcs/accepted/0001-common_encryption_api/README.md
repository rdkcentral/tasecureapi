# RFC 0001-Common Encryption API

- Feature Name: Common Encryption API
- Author(s): Eric Berry
- Start Date: 2021-06-08
- RFC PR: 0001
- Leader(s): Eric Berry

## Introduction

SecApi needs a mechanism to natively support Common Encryption.

## Motivation / use-cases

SecApi 2 has been used for many years to provide cryptographic operations for DRM libraries on RDK.
SecApi 2 does not natively support ISO/IEC 23001-7 Common encryption. The library attempted to add
the SecCipher_ProcessCtrWithDataShift and SecCipher_ProcessCtrWithOpaqueDataShift to support Common
Encryption, but they were never implemented correctly by any SOC vendor and therefore have not been
actively used by DRM libraries. DRM libraries have adopted a mechanism of gathering all of the
scattered encrypted data into a decryption buffer, decrypting it, then scattering the decrypted data
back into its original location. This functionality works, but the multiple copy operations can
cause slow decryption times on some platforms.

The SecApi 2 library has become complex and the need was identified to create SecApi 3 to simplify
the cryptographic interface. The design of SecApi 3 has been to keep the cryptographic interface as
simple and streamlined as possible so that it could be a general, all-purpose cryptographic library.
The decision was made to continue to use the gather, decrypt, scatter design for Common Encryption
that was used in SecApi 2 to keep its design simple and general purpose. This unfortunately brings
the same inefficient Common Encryption design into SecApi 3.

After much discussion, a desire was expressed to natively support Common Encryption with SecApi 3
even though this would be a specialized cryptographic function.

*ISO/IEC 23001-7 Common encryption in ISO base media file format files* identifies how content is
divided into samples, and sub-samples with clear and encrypted blocks using the CENC (CTR mode),
CENS (CTR mode with pattern encryption), CBC1 (CBC mode), and CBCS (CBC mode with pattern
encryption) encryption modes. This design takes the definitions and fields defined in that
specification and builds an API that can be used to implement the specification.

A comparison was made with the Widevine interface that implements common encryption, shown
below in Use Case 3, as well as the PlayReady interface that implements common encryption, also
shown below in Use Case 4, and this design was verified to be compatible with both of those
implementations.

## Updates/Obsoletes

None

## Affected platforms

All

## Open Source Dependencies

None

## Detailed design

**sa_subsample_length Structure**

```c
typedef struct {
    size_t bytes_of_clear_data;
    size_t bytes_of_protected_data;
} sa_subsample_length;
```

This structure gives the length definition of a subsample. A subsample usually contains a video or
audio NAL (Network Abstraction Layer) unit (or alternatively a NAL unit could be encoded into more
than one subsample). Subsamples are divided into two sections: a clear data section, followed by a
protected data section.

+ `bytes_of_clear_data` identifies the length of the clear data section.
+ `bytes_of_protected_data` identifies the length of the protected data section.

Either one of these values can be 0, but not both.

**sa_sample Structure**

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

typedef struct {
    void* iv;
    size_t iv_length;
    size_t crypt_byte_block;
    size_t skip_byte_block;
    size_t subsample_count;
    sa_subsample_length *subsample_lengths;
    sa_crypto_cipher_context context;
    sa_buffer* out;
    sa_buffer* in;
} sa_sample;
```

+ `sa_sample` provides the definition of a sample.
+ `iv` identifies the IV to used to decrypt the sample. When using CBCS mode, the IV is used for
  the encryption of each subsample. In all other modes, the IV is used starting at the encryption of
  the first subsample only.
+ `iv_length` the length of the `iv` field.
+ `crypt_byte_block` in CENS mode and CBCS mode the protected data is only partially encrypted.
  This field is non-zero and identifies the number of 16 byte blocks that are encrypted. The
  following field identifies the number of 16 bytes block that are skipped. This pattern repeats
  until the entire protected block is used. Any remaining block less than 16 bytes is unencrypted.
  Setting this field to 0 indicates CENC or CBC1 mode and that the entire protected data section is
  encrypted.
+ `skip_byte_block` identifies the number of 16 byte blocks to skip in a protected data section.
  In CENC and CBC1 mode, the entire protected data section is encrypted and this field must be set
  to 0. In CENS and CBCS mode, audio tracks can be fully encrypted, so this field should be set to
  0 for those cases.
+ `subsample_count` identifies the number of subsamples in this sample.
+ `subsample_lengths` is the array of subsample_lengths.
+ `context` contains a cipher context that was initialized with either a SA_CIPHER_ALGORITHM_AES_CTR
  algorithm for CENC or CENS mode or SA_CIPHER_ALGORITHM_AES_CBC for CBC1 or CBCS mode. The context
  was also initialized with the decryption key and for decrypt mode. Trying to use these functions
  with any other encryption algorithms or encrypt mode will result in an error.
+ `out.buffer_type` identifies whether the out buffer is svp or clear.
+ `out.context.svp.buffer` or `out.context.clear.buffer` is the output buffer in which to put the
  decrypted data. Widevine specifies an output buffer per sample, where PlayReady has one output
  buffer for all samples. This design follows the Widevine model because it can support PlayReady,
  but the reverse is not possible.
+ `out.context.clear.length` identifies the length of the output clear buffer.
+ `out.context.svp.offset` or `out.context.clear.offset` identifies the offset into the buffer.
+ `in.buffer_type` identifies whether the in buffer is svp or clear.
+ `in.context.svp.buffer` or `in.context.clear.buffer` buffer from which the encrypted data is
  retrieved. Widevine specifies an input buffer per sample, where PlayReady has one input buffer
  for all samples. This design follows the Widevine model because it can support PlayReady, but
  the reverse is not possible.
+ `in.context.clear.length` identifies the length of the input clear buffer.
+ `in.context.svp.offset` or `in.context.clear.offset` identifies the offset into the SVP buffer.

** Process Common Encryption Function**

```c
sa_status sa_cipher_process_common_encryption(
    size_t samples_length,
    sa_sample *samples);
```

This function is called to decrypt an array of samples either in SVP buffers or in clear buffers.

+ `samples_length` identifies to number of samples in the array.
+ `samples` contains an array of samples to decrypt.

### Use Case 1 - CENC Scheme: Audio Track Sample Followed by Video Track Sample

+ Audio has two subsamples.
+ Video has three subsamples and the third subsample has no clear data.

```
samples_length: 2
sample[0]: // Audio sample no SVP
  iv: 112233445566778899AABBCCDDEEFF00
  iv_length: 16
  crypt_byte_block: 0
  skip_byte_block: 0
  subsample_count: 2
  subsample_lengths[0]:
    bytes_of_clear_data: 50
    bytes_of_protected_data: 100
  subsample_lengths[1]:
    bytes_of_clear_data: 50
    bytes_of_protected_data: 100 // Note that CENC continues block from subsample[0] protected data
  context: CTR algorithm, decrypt mode, decryption key
  out.buffer_type: SA_BUFFER_TYPE_CLEAR
  out.context.clear:
    buffer: *********
    length: 300
    offset: 0
  in.buffer_type: SA_BUFFER_TYPE_CLEAR
  in.context.clear:
    buffer: **********
    length: 300
    offset: 0
sample[1]: // Video sample with SVP
  iv: 112233445566778899AABBCCDDEEFF00
  iv_length: 16
  crypt_byte_block: 0
  skip_byte_block: 0
  subsample_count: 3
  subsample_lengths[0]:
    bytes_of_clear_data: 50
    bytes_of_protected_data: 200
  subsample_lengths[1]:
    bytes_of_clear_data: 50
    bytes_of_protected_data: 200 // Note that CENC continues block from subsample[0] protected data
  subsample_lengths[2]:
    bytes_of_clear_data: 0
    bytes_of_protected_data: 200 // Note that CENC continues block from subsample[1] protected data
  context: CTR algorithm, decrypt mode, decryption key
  out.buffer_type: SA_BUFFER_TYPE_SVP
  out.context.svp:
    buffer: *********
    offset: 0
  in.buffer_type: SA_BUFFER_TYPE_CLEAR
  in.context.clear:
    buffer: **********
    length: 700
    offset: 0
```

### Use Case 2 - CBCS Scheme: Audio Track Sample Followed by Video Track Sample

+ Audio has two subsamples that are fully encrypted.
+ Video has three subsamples with 1:9 pattern encryption and the third subsample has no clear data.

```
samples_length: 2
sample[0]: // Audio sample no SVP
  iv: 112233445566778899AABBCCDDEEFF00
  iv_length: 16
  crypt_byte_block: 1
  skip_byte_block: 0
  subsample_count: 2
  subsample_lengths[0]:
    bytes_of_clear_data: 50
    bytes_of_protected_data: 100
  subsample_lengths[1]:
    bytes_of_clear_data: 50
    bytes_of_protected_data: 100 // Note that CBCS resets the IV with the new subsample
  context: CBC algorithm, decrypt mode, decryption key
  out.buffer_type: SA_BUFFER_TYPE_CLEAR
  out.context.clear:
    buffer: *********
    length: 300
    offset: 0
  in.buffer_type: SA_BUFFER_TYPE_CLEAR
  in.context.clear:
    buffer: **********
    length: 300
    offset: 0
sample[1]: // Video sample with SVP
  iv: 112233445566778899AABBCCDDEEFF00
  iv_length: 16
  crypt_byte_block: 1
  skip_byte_block: 9
  subsample_count: 3
  subsample_lengths[0]:
    bytes_of_clear_data: 50
    bytes_of_protected_data: 200
  subsample_lengths[1]:
    bytes_of_clear_data: 50
    bytes_of_protected_data: 200 // Note that CBCS resets the IV with the new subsample
  subsample_lengths[2]:
    bytes_of_clear_data: 0
    bytes_of_protected_data: 200 // Note that CBCS resets the IV with the new subsample
  context: CBC algorithm, decrypt mode, decryption key
  out.buffer_type: SA_BUFFER_TYPE_SVP
  out.context.svp:
    buffer: *********
    offset: 0
  in.buffer_type: SA_BUFFER_TYPE_CLEAR
  in.context.clear:
    buffer: **********
    length: 700
    offset: 0
```

### Use Case 3 - Mapping Widevine data structure

This use case describes how to map the Widevine data structure into a call to 
`sa_cipher_process_common_encryption`.  The comments listed after the parameters identify which
Widevine field to use.

**Widevine Common Encryption Interface**

```c
typedef enum OEMCryptoBufferType {
    OEMCrypto_BufferType_Clear,
    OEMCrypto_BufferType_Secure,
    OEMCrypto_BufferType_Direct
} OEMCryptoBufferType;

typedef struct {
    OEMCryptoBufferType type;
    union {
        struct {  // type == OEMCrypto_BufferType_Clear
            OEMCrypto_SharedMemory* address;
            size_t address_length;
        } clear;
        struct {  // type == OEMCrypto_BufferType_Secure
            void* handle;
            size_t handle_length;
            size_t offset;
        } secure;
        struct {  // type == OEMCrypto_BufferType_Direct
            bool is_video;
        } direct;
    } buffer;
} OEMCrypto_DestBufferDesc;

typedef struct {
    const OEMCrypto_SharedMemory* input_data
    size_t input_data_length;
    OEMCrypto_DestBufferDesc output_descriptor;
} OEMCrypto_InputOutputPair;

typedef struct {
    size_t num_bytes_clear;
    size_t num_bytes_encrypted;
    uint8_t subsample_flags;
    size_t block_offset;
} OEMCrypto_SubSampleDescription;

typedef struct {
    OEMCrypto_InputOutputPair buffers;
    uint8_t iv[16];
    const OEMCrypto_SubSampleDescription* subsamples;
    size_t subsamples_length;
} OEMCrypto_SampleDescription;

typedef struct {
    size_t encrypt;
    size_t skip;
} OEMCrypto_CENCEncryptPatternDesc;

OEMCryptoResult OEMCrypto_DecryptCENC(
    OEMCrypto_SESSION session,
    const OEMCrypto_SampleDescription* samples,
    size_t samples_length,
    const OEMCrypto_CENCEncryptPatternDesc* pattern);
```

```
samples_length: 2                      // samples_length
sample[0]: // Audio sample no SVP
  iv: 112233445566778899AABBCCDDEEFF00 // samples[0].iv
  iv_length: 16
  crypt_byte_block: 0                  // pattern.encrypt
  skip_byte_block: 0                   // pattern.skip
  subsample_count: 2                   // samples[0].subsamples_length
  subsample_lengths[0]:
    bytes_of_clear_data: 50            // samples[0].subsamples[0].num_bytes_clear
    bytes_of_protected_data: 100       // samples[0].subsamples[0].num_bytes_encrypted
  subsample_lengths[1]:
    bytes_of_clear_data: 50            // samples[0].subsamples[1].num_bytes_clear
    bytes_of_protected_data: 100       // samples[0].subsamples[1].num_bytes_clear
  context: CTR algorithm, decrypt mode, decryption key
  out.buffer_type: SA_BUFFER_TYPE_CLEAR// samples[0].buffers.output_descriptor.type == OEMCrypto_BufferType_Clear
  out.context.clear:
    buffer: *********                  // samples[0].buffers.output_descriptor.buffer.clear.address
    length: 300                        // samples[0].buffers.output_descriptor.buffer.clear.length
    offset: 0
  in.buffer_type: SA_BUFFER_TYPE_CLEAR
  in.context.clear:
    buffer: **********                 // samples[0].buffers.input_data
    length: 300                        // samples[0].buffers.input_data_length
    offset: 0
sample[1]: // Video sample with SVP
  iv: 112233445566778899AABBCCDDEEFF00 // samples[1].iv
  iv_length: 16
  crypt_byte_block: 0                  // pattern.encrypt
  skip_byte_block: 0                   // pattern.skip
  subsample_count: 3
  subsample_lengths[0]:
    bytes_of_clear_data: 50            // samples[1].subsamples[0].num_bytes_clear
    bytes_of_protected_data: 200       // samples[1].subsamples[0].num_bytes_encrypted
  subsample_lengths[1]:
    bytes_of_clear_data: 50            // samples[1].subsamples[1].num_bytes_clear
    bytes_of_protected_data: 200       // samples[1].subsamples[1].num_bytes_encrypted
  subsample_lengths[2]:
    bytes_of_clear_data: 0             // samples[1].subsamples[2].num_bytes_clear
    bytes_of_protected_data: 200        // samples[1].subsamples[2].num_bytes_encrypted
  context: CTR algorithm, decrypt mode, decryption key
  out.buffer_type: SA_BUFFER_TYPE_SVP  // samples[0].buffers.output_descriptor.type == OEMCrypto_BufferType_Secure
  out.context.svp:
    buffer: *********                  // samples[1].buffers.output_descriptor.buffer.secure.handle
    offset: 0                          // samples[1].buffers.output_descriptor.buffer.secure.offset
  in.buffer_type: SA_BUFFER_TYPE_CLEAR
  in.context.clear:
    buffer: **********                 // samples[1].buffers.input_data
    length: 700                        // samples[1].buffers.input_data_length
    offset: 0
```

### Use Case 4 - Mapping PlayReady data structure

This use case describes how to map the PlayReady data structure into a call to
`sa_cipher_process_common_encryption`.  The comments listed after the parameters identify which
PlayReady field to use.

**PlayReady Common Encryption Interface**

```c
DRM_API DRM_RESULT DRM_CALL Drm_Reader_DecryptMultipleOpaque(
    __in
                DRM_DECRYPT_CONTEXT      *f_pDecryptContext,
    __in
                DRM_DWORD                 f_cEncryptedRegionInitializationVectors,
    __in_ecount( f_cEncryptedRegionInitializationVectors )
        const   DRM_UINT64               *f_pEncryptedRegionInitializationVectorsHigh,
    __in_ecount_opt( f_cEncryptedRegionInitializationVectors )
        const   DRM_UINT64               *f_pEncryptedRegionInitializationVectorsLow,
    __in_ecount( f_cEncryptedRegionInitializationVectors )
        const   DRM_DWORD                *f_pEncryptedRegionCounts,
    __in
                DRM_DWORD                 f_cEncryptedRegionMappings,
    __in_ecount( f_cEncryptedRegionMappings )
        const   DRM_DWORD                *f_pEncryptedRegionMappings,
    __in
                DRM_DWORD                 f_cEncryptedRegionSkip,
    __in_ecount_opt( f_cEncryptedRegionSkip )
        const   DRM_DWORD                *f_pEncryptedRegionSkip,
    __in
                DRM_DWORD                 f_cbEncryptedContent,
    __in_bcount( f_cbEncryptedContent )
        const   DRM_BYTE                 *f_pbEncryptedContent,
    __out
                DRM_DWORD                *f_pcbOpaqueClearContent,
    __deref_out_bcount( *f_pcbOpaqueClearContent )
                DRM_BYTE                **f_ppbOpaqueClearContent
     );
```

```
samples_length: 2                      // samples_length
sample[0]: // Audio sample no SVP
  iv: 112233445566778899AABBCCDDEEFF00 // f_pEncryptedRegionInitializationVectorsHigh[0] +
                                       // f_pEncryptedRegionInitializationVectorsLow[0]
  iv_length: 16
  crypt_byte_block: 0                  // if(f_cEncryptedRegionSkip == 0) 0
                                       // if (f_cEncryptedRegionSkip == 2) f_pEncryptedRegionSkip[0]
  skip_byte_block: 0                   // if(f_cEncryptedRegionSkip == 0) 0
                                       // if (f_cEncryptedRegionSkip == 2) f_pEncryptedRegionSkip[1]
  subsample_count: 2                   // f_pEncryptedRegionCounts[0] / 2
  subsample_lengths[0]:
    bytes_of_clear_data: 50            // f_pEncryptedRegionMappings[0]
    bytes_of_protected_data: 100       // f_pEncryptedRegionMappings[1]
  subsample_lengths[1]:
    bytes_of_clear_data: 50            // f_pEncryptedRegionMappings[2]
    bytes_of_protected_data: 100       // f_pEncryptedRegionMappings[3]
  context: CTR algorithm, decrypt mode, decryption key
  out.buffer_type: SA_BUFFER_TYPE_SVP  // Drm_Content_SetProperty(DRM_CSP_DECRYPTION_OUTPUT_MODE)
  out.context.clear:
    buffer: *********                  // f_ppbOpaqueClearContent
    length: 300
    offset: 0                          // 0
  in.buffer_type: SA_BUFFER_TYPE_CLEAR
  in.context.clear:
    buffer: **********                 // f_pbEncryptedContent
    length: 300                        // calculated from f_pEncryptedRegionMappings[0..3]
    offset: 0
sample[1]: // Video sample with SVP
  iv: 112233445566778899AABBCCDDEEFF00 // f_pEncryptedRegionInitializationVectorsHigh[1] +
                                       // f_pEncryptedRegionInitializationVectorsLow[1]
  iv_length: 16
  crypt_byte_block: 0                  // if(f_cEncryptedRegionSkip == 0) 0
                                       // if (f_cEncryptedRegionSkip == 2) f_pEncryptedRegionSkip[0]
  skip_byte_block: 0                   // if(f_cEncryptedRegionSkip == 0) 0
                                       // if (f_cEncryptedRegionSkip == 2) f_pEncryptedRegionSkip[1]
  subsample_count: 3                   // f_pEncryptedRegionCounts[1] / 2
  subsample_lengths[0]:
    bytes_of_clear_data: 50            // f_pEncryptedRegionMappings[4]
    bytes_of_protected_data: 200       // f_pEncryptedRegionMappings[5]
  subsample_lengths[1]:
    bytes_of_clear_data: 50            // f_pEncryptedRegionMappings[6]
    bytes_of_protected_data: 200       // f_pEncryptedRegionMappings[7]
  subsample_lengths[2]:
    bytes_of_clear_data: 0             // f_pEncryptedRegionMappings[8]
    bytes_of_protected_data: 200       // f_pEncryptedRegionMappings[9]
  context: CTR algorithm, decrypt mode, decryption key
  out.buffer_type: SA_BUFFER_TYPE_SVP  // Drm_Content_SetProperty(DRM_CSP_DECRYPTION_OUTPUT_MODE)
  out.context.svp:
    buffer: *********                  // f_ppbOpaqueClearContent
    offset: 0                          // 0
  in.buffer_type: SA_BUFFER_TYPE_CLEAR
  in.context.clear:
    buffer: **********                 // f_pbEncryptedContent + 300
    length: 700                        // calculated from f_pEncryptedRegionMappings[4..9]
    offset: 0
```

## Drawbacks

SecApi 3 as originally designed is meant to be a general, all-purpose cryptographic library. Adding
support for Common Encryption with SecApi 3 would add a specialized cryptographic function to this
library.

## Alternatives considered

None

## Unresolved questions

None

## Future possibilities

None

## References

*ISO/IEC 23001-7 Common encryption in ISO base media file format files*
