# tasecureapi-lite: which SecAPI calls are open

`_RDKB_LITE_` is an opt-in build of `reference/` that contains only the SecAPI calls FKPS (`test_fkps`) and AUTHN
(`test_authn`) need. Everything else is not built: the client library has no `sa_*` entry point for it, and the TA
dispatch table in `ta.c` answers `SA_STATUS_OPERATION_NOT_SUPPORTED` for its command ids. The OpenSSL engine and provider
(`sa_engine*`, `sa_provider*`) are not part of the lite library.

```bash
# from reference/
cmake -S . -B build -D_RDKB_LITE_=ON -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF
cmake --build build --target saclient

# with the unit tests (section 5)
cmake -S . -B build -D_RDKB_LITE_=ON -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build
```

Without `-D_RDKB_LITE_=ON` the build is the unchanged full reference.

## How the set was chosen

A call is open if it executes in a full run of the two tests (call counts in section 1, from an lldb trace of
`ta_sa_*`, see section 9). `sa_get_version` is also kept open although the tests do not call it (section 2).

## 1. Open: needed by the tests

### 1a. Required for processor creation

`SecProcessor_GetInstance_Directories` (called by both tests) needs all of these:

| API | Why it is needed |
|---|---|
| `sa_key_derive`, **root key ladder** | The store key container is derived from the root key ladder (`derive_root_key_ladder`). `deriveConcatKdf` depends on it: the Concat KDF parent key is itself a ladder output. |
| `sa_key_export` | Exports the derived store key (`process_store_key_container`). |
| `sa_key_import` | `SecKey_Provision(SEC_OBJECTID_STORE_AES_KEY ...)` imports the store key. |
| `sa_key_header` | Key-properties lookup when keys are opened. |
| `sa_key_derive`, **Concat KDF** | Certificate MAC key: `SecKey_Derive_ConcatKDF`. |

### 1b. All commands executed by the tests

Counts are calls during one full run of each test (the AUTHN column covers fresh authentication and renewal).

| API | `test_fkps` | AUTHN | Variants seen |
|---|---:|---:|---|
| `sa_get_device_id` | 10 | 22 | |
| `sa_crypto_random` | 10 | 87 | |
| `sa_crypto_mac_init / process / compute / release` | 1 | 32-45 | HMAC |
| `sa_key_digest` | 2 | 2 | |
| `sa_key_derive` | 10 | 18 | root key ladder, Concat KDF |
| `sa_key_export` | 7 | 30 | |
| `sa_key_import` | 6 | 75 | SoC key container, symmetric bytes, exported format |
| `sa_key_header` | 2 | 52 | |
| `sa_key_release` | 16 | 104 | |
| `sa_key_unwrap` | 0 | 11 | AES-CBC (5), AES-ECB (2), RSA (4) |
| `sa_crypto_sign` | 0 | 4 | RSA PKCS#1 v1.5 |
| `sa_crypto_cipher_init / process / release` | 0 | 2 | AES-ECB (`SecCipher_SingleInputId`) |
| library init / close (`ta_sa_init`, `ta_sa_close`) | 1 | 1 | |

## 2. Open, but not executed by the tests

| API | Why it is open |
|---|---|
| `sa_get_version` | Kept open on purpose. FKPS / AUTHN never call it: its only user in the adapter is `SecProcessor_PrintInfo`, which prints version information, and the one call to that in `test_authn` is under `#if 0`. It is a small call that lets an integrator confirm that the TA responds. |

Inside open calls, only the variants in section 1b were exercised by FKPS / AUTHN. Other algorithms (HKDF, ANSI X9.63
and CMAC KDFs, other cipher modes, ...) are outside those flows; some remain available in lite, while the variants
listed in section 3 are disabled.

## 3. Closed commands and disabled variants

Not executed in either flow. The TA dispatch table in `ta.c` has 35 commands: **18 open, 17 closed** (closed = inside
`#ifndef _RDKB_LITE_`). The matching client sources (`src/clientimpl/src/sa_*.c`) and TA sources
(`src/taimpl/src/ta_sa_*.c`) are not built in lite.

| # | Command | Notes |
|---:|---|---|
| 1 | `sa_crypto_cipher_update_iv` | not called by FKPS / AUTHN |
| 2 | `sa_crypto_cipher_process_last` | only issued for PKCS#7-padded ciphers; FKPS / AUTHN use `AES_ECB_NO_PADDING` |
| 3 | `sa_crypto_mac_process_key` | not called by FKPS / AUTHN |
| 4 | `sa_get_name` | |
| 5 | `sa_get_ta_uuid` | |
| 6 | `sa_key_generate` | |
| 7 | `sa_key_get_public` | |
| 8 | `sa_key_exchange` | ECDH |
| 9 | `sa_key_provision_ta` | dead call site |
| 10 | `sa_process_common_encryption` | CENC |
| 11 | `sa_svp_supported` | SVP |
| 12 | `sa_svp_buffer_create` | SVP |
| 13 | `sa_svp_buffer_check` | SVP |
| 14 | `sa_svp_buffer_copy` | SVP |
| 15 | `sa_svp_buffer_release` | SVP |
| 16 | `sa_svp_buffer_write` | SVP |
| 17 | `sa_svp_key_check` | SVP |

There is no SVP support in lite. The `sa_svp_*` helpers (`alloc`, `free`, `memory_alloc`, `memory_free`) are not built either.

**Open (18):** `GET_VERSION`, `GET_DEVICE_ID`, `CRYPTO_RANDOM`, `CRYPTO_MAC_INIT / PROCESS / COMPUTE / RELEASE`,
`KEY_DIGEST`, `KEY_RELEASE`, `KEY_DERIVE`, `KEY_EXPORT`, `KEY_IMPORT`, `KEY_HEADER`, `KEY_UNWRAP`, `CRYPTO_SIGN`,
`CRYPTO_CIPHER_INIT / PROCESS / RELEASE`.

The lite library exports these 18 `sa_*` functions, plus the `sa_rights_set_allow_all` helper from `util`.

Within the open `sa_key_derive` command, `SA_KDF_ALGORITHM_NETFLIX` is disabled. A valid Netflix derivation request
returns `SA_STATUS_OPERATION_NOT_SUPPORTED`. Other KDF variants are unchanged, and the 18-open / 17-closed command
counts above are unchanged. Netflix authenticated DH is also unavailable because `sa_key_exchange` is closed.

Within the open `sa_key_import` command, `SA_KEY_FORMAT_TYPEJ` is disabled and returns
`SA_STATUS_OPERATION_NOT_SUPPORTED`. `SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO` is also disabled and returns
`SA_STATUS_OPERATION_NOT_SUPPORTED`. FKPS / AUTHN import only `SA_KEY_FORMAT_EXPORTED`, `SA_KEY_FORMAT_SOC` and
`SA_KEY_FORMAT_SYMMETRIC_BYTES` keys; the other import formats are unchanged.

Elliptic-curve (EC) keys and algorithms are disabled inside the open commands, because FKPS / AUTHN use only symmetric
and RSA keys. The following return `SA_STATUS_OPERATION_NOT_SUPPORTED`:

- `sa_key_import` with `SA_KEY_FORMAT_EC_PRIVATE_BYTES`, or with a SoC key container that holds an `ECC-*` key
- `sa_key_unwrap` with `SA_KEY_TYPE_EC` or `SA_CIPHER_ALGORITHM_EC_ELGAMAL`
- `sa_crypto_cipher_init` with `SA_CIPHER_ALGORITHM_EC_ELGAMAL`
- `sa_crypto_sign` with `SA_SIGNATURE_ALGORITHM_ECDSA` or `SA_SIGNATURE_ALGORITHM_EDDSA`

An exported EC key is rejected with `SA_STATUS_INVALID_KEY_FORMAT`, because EC key sizes are not accepted in lite.

The following RSA variants are also disabled inside open commands and return `SA_STATUS_OPERATION_NOT_SUPPORTED`:

- `sa_crypto_sign` with `SA_SIGNATURE_ALGORITHM_RSA_PSS`
- `sa_crypto_cipher_init` or `sa_key_unwrap` with `SA_CIPHER_ALGORITHM_RSA_OAEP`

RSA PKCS#1 v1.5 signing, decrypting and unwrapping remain available. RSA key import through
`SA_KEY_FORMAT_EXPORTED` and SoC containers remains available for the FKPS / AUTHN flows.

## 4. How it is implemented

| Layer | Change |
|---|---|
| `src/taimpl/src/internal/ta.c` | per-command `#ifndef _RDKB_LITE_ ... #endif  // _RDKB_LITE_` around the closed `case` labels and their `ta_invoke_*` functions |
| `src/taimpl/CMakeLists.txt` | lite source list (only the open commands, plus `ta_sa_svp_supported.c`, which is compiled but whose command stays closed; `internal/netflix.c`, `internal/typej.c` and `internal/ec.c` are not in it); YAJL is unconditional; `taimpltest` uses the same test list as the full build |
| `src/taimpl/src/ta_sa_key_derive.c`, `src/taimpl/src/ta_sa_key_exchange.c`, `src/taimpl/src/ta_sa_key_import.c` | `ta_sa_key_derive_netflix`, `ta_sa_key_exchange_netflix_dh`, `ta_sa_key_import_typej` and their calls are guarded; the lite branches report `SA_STATUS_OPERATION_NOT_SUPPORTED` |
| `src/taimpl/src/ta_sa_key_{import,unwrap}.c`, `src/taimpl/src/ta_sa_crypto_{sign,cipher_init,cipher_process}.c`, `src/taimpl/src/internal/{unwrap,soc_key_container,key_type}.c`, `src/taimpl/include/internal/unwrap.h` | the EC helpers (`ta_sa_key_import_ec_private_bytes`, `ta_sa_key_unwrap_ec`, `unwrap_ec`, `ta_sa_crypto_sign_ecdsa`, `ta_sa_crypto_sign_eddsa`, `ta_sa_crypto_cipher_init_ec`, `ta_sa_crypto_cipher_process_ec_elgamal`) and the EC branches are guarded; the lite branches report `SA_STATUS_OPERATION_NOT_SUPPORTED`, and `key_type.c` accepts no EC key size |
| `src/taimpl/src/ta_sa_key_import.c`, `src/taimpl/src/ta_sa_key_unwrap.c`, `src/taimpl/src/ta_sa_crypto_{sign,cipher_init,cipher_process}.c`, `src/taimpl/src/internal/{rsa,cipher_store,unwrap}.c` | RSA-PSS, RSA-OAEP and `RSA_PRIVATE_KEY_INFO` import helpers, state and dispatch branches are guarded; the open APIs report `SA_STATUS_OPERATION_NOT_SUPPORTED` |
| `src/taimpl/src/internal/client_store.c` | cipher store initialized / shut down in lite |
| `src/clientimpl/CMakeLists.txt` | lite builds only the 18 client sources of the open calls |
| `src/client/CMakeLists.txt` | lite `saclient` is `saclientimpl` only (no OpenSSL engine / provider); lite passes `-D_RDKB_LITE_` to `saclienttest` |
| `src/client/test/*` | tests of closed calls, Netflix derivation tests, Type-J / `RSA_PRIVATE_KEY_INFO` import tests and RSA-PSS / RSA-OAEP tests are guarded with `#ifndef _RDKB_LITE_` |

### TA source files built in lite

The lite TA (`libtaimpl`) is built from the 51 source files below. They are the sources of the open commands plus the
modules those commands depend on.

| Group | Sources (`src/taimpl/src/`) | Why they are built |
|---|---|---|
| Porting layer | `porting/{init,memory,otp,overflow,rand,transport}.c`, `porting/{svp,video_output}.c` | platform services: OTP root key and key ladder, random numbers, memory; `svp.c` and `video_output.c` are part of the porting layer list |
| Core | `internal/{ta,saimpl,client_store,object_store,slots,rights,buffer,pad}.c` | command dispatch, client sessions, handle tables, rights, buffers |
| Key store | `internal/{key_store,key_type,stored_key}.c` | stored key objects and their type and size checks |
| MAC and digest | `internal/{digest,hmac_context,cmac_context,mac_store}.c`, `ta_sa_crypto_mac_{init,process,compute,release}.c`, `ta_sa_key_digest.c` | `CRYPTO_MAC_*`, `KEY_DIGEST` |
| Key commands | `ta_sa_key_{derive,export,import,header,release,unwrap}.c`, `internal/kdf.c` | `KEY_DERIVE`, `KEY_EXPORT`, `KEY_IMPORT`, `KEY_HEADER`, `KEY_RELEASE`, `KEY_UNWRAP` |
| Sign and cipher | `ta_sa_crypto_sign.c`, `ta_sa_crypto_cipher_{init,process,release}.c`, `internal/cipher_store.c` | `CRYPTO_SIGN`, `CRYPTO_CIPHER_INIT`, `CRYPTO_CIPHER_PROCESS`, `CRYPTO_CIPHER_RELEASE` |
| Key formats | `internal/{soc_key_container,json,unwrap,symmetric}.c` | SoC key container import (`ta_sa_key_import.c`) and key unwrapping (`ta_sa_key_unwrap.c`) |
| RSA | `internal/rsa.c` | RSA key validation on import (`ta_sa_key_import.c`, `soc_key_container.c`, `unwrap.c`), RSA unwrap, sign and decrypt (`unwrap.c`, `ta_sa_crypto_sign.c`, `ta_sa_crypto_cipher_*`) |
| Session and device | `ta_sa_{init,close,get_device_id,get_version,crypto_random}.c`, `ta_sa_svp_supported.c` | session setup, device id, version, random; `ta_sa_svp_supported.c` is compiled but its command stays closed |

**Not compiled in lite (22 source files):** the `ta_sa_*.c` files of the closed commands in section 3
(`ta_sa_crypto_cipher_process_last.c`, `ta_sa_crypto_cipher_update_iv.c`, `ta_sa_crypto_mac_process_key.c`,
`ta_sa_get_name.c`, `ta_sa_get_ta_uuid.c`, `ta_sa_key_exchange.c`, `ta_sa_key_generate.c`, `ta_sa_key_get_public.c`,
`ta_sa_key_provision.c`, `ta_sa_process_common_encryption.c`, and the six `ta_sa_svp_*.c` files), and the internal modules
`internal/cenc.c`, `internal/dh.c`, `internal/svp_store.c`, `internal/netflix.c`, `internal/typej.c` and `internal/ec.c`.

**External libraries:** OpenSSL, and YAJL (the JSON parser used by `internal/json.c`).

## 5. Tests

The unit tests build and run against the lite library (`-DBUILD_TESTS=ON`). Tests of closed calls are not compiled:
a whole test file that only exercises a closed call is wrapped in `#ifndef _RDKB_LITE_ ... #endif  // _RDKB_LITE_`, and
inside shared test files only the affected `TEST`, helper, `case` or `INSTANTIATE_TEST_SUITE_P` block is guarded.

| Configuration | Result |
|---|---|
| Lite (`ctest --output-on-failure -j4`) | 2472 discovered tests, 0 failures |
| Full (`ctest --output-on-failure -j4`) | 6781 discovered tests, 0 failures |

These results were verified after the RSA-PSS, RSA-OAEP and `RSA_PRIVATE_KEY_INFO` guards. Lite excludes the tests for
those variants, in addition to the previously excluded Netflix, Type-J and EC tests. Symbol checks found no RSA-PSS
signing, RSA-OAEP decrypt, OAEP cipher-state, or RSA private-key-info import helper symbols in the lite TA library;
the full library retains them.

`saclienttest` runs in one process in about 2 seconds. What is covered and what is not:

- **Exercised by FKPS / AUTHN:** MAC, RSA PKCS#1 v1.5 sign and unwrap, AES cipher operations, key derive / import / export /
  header / digest, random, `get_version`, and `get_device_id`.
- **Not compiled:** the tests of the closed calls (`key_generate`, `key_get_public`, `key_exchange`, `key_provision_ta`,
  `get_name`, `get_ta_uuid`, `process_common_encryption`, `mac_process_key`, `cipher_process_last`, `cipher_update_iv`,
  the SVP calls), the Netflix derivation cases, the Type-J import tests, and the OpenSSL engine and provider tests.
- **Skipped in lite:** test cases that need a DH or EC key (key derive with a DH / EC base key, EC unwrap, DH / EC export
  and import, EC ElGamal decrypt) and SVP buffer cases.
- **RSA unit-test limitation:** direct RSA private-key import is disabled, so tests that create RSA keys through
  `SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO` cannot exercise RSA PKCS#1 v1.5 in lite. The FKPS / AUTHN runs use imported
  exported or SoC RSA keys instead. The full build retains RSA-PSS, RSA-OAEP and private-key-info import tests.

## 6. Compatibility requirements that are not API calls

| Requirement | Detail |
|---|---|
| **3-stage key ladder.** The adapter calls `derive_root_key_ladder(c1, c2, c3, c4 = NULL)`. | `c4` is optional in `sa_key_derive.c`, `ta.c`, `ta_sa_key_derive.c`, `otp.c`. With no `c4` the output is the 3-stage ladder result. A 3-block parameter blob means "no c4". |
| **Root key.** The software OTP root key is read from a PKCS#12 file. | Set `ROOT_KEYSTORE` and `ROOT_KEYSTORE_PASSWORD`; without them, derived keys do not match a real device. |

## 7. Size: lite vs full

Measured after the Netflix, Type-J and EC guards and before the RSA variant guards on macOS arm64, Release, with
`ENABLE_SVP=OFF` in both configurations.
"full" = built without `_RDKB_LITE_`; "lite" = `reference/build` (`-D_RDKB_LITE_=ON`).
Bytes from `stat`; `__TEXT` from `size -m`.

| Artifact | Full | Lite | Difference |
|---|---:|---:|---:|
| `libsaclient.3.4.1.dylib` | 436,248 | 279,144 | -157,104 (-36.0%) |
| `libsaclient` stripped (`strip -x`) | 417,704 | 274,408 | -143,296 (-34.3%) |
| `libsaclient` `__TEXT` segment | 327,680 | 212,992 | -114,688 (-35.0%) |
| `libtaimpl.a` | 585,408 | 424,888 | -160,520 (-27.4%) |
| `libsaclientimpl.a` | 94,584 | 61,784 | -32,800 (-34.7%) |
| `ta_sa_*` functions in the library | 85 | 50 | -35 |
| exported `sa_*` symbols | 44 | 19 (18 calls + 1 helper) | -25 |

## 8. Limits

- Only the two test flows were traced. If your FKPS / AUTHN usage differs (other key types, ECDH, `sa_key_generate`,
  `sa_key_get_public`, other unwrap / cipher modes), re-run the trace before relying on lite.
- The lite library does not provide the closed calls, so code that references them (for example the SecAPI2 adapter's
  generic command dispatcher) does not link against it.
- A full FKPS / AUTHN run needs real device credentials (serial and root key).
- The lite unit tests skip DH and EC key cases and cannot exercise RSA PKCS#1 v1.5 with private keys created through
  `SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO` (section 5).

## 9. Reproducing the trace

```bash
# lldb script: break on every ta_sa_* function, print the frame and continue
breakpoint set --func-regex ^ta_sa_
breakpoint modify --auto-continue true 1
breakpoint command add 1
frame info
DONE
process launch
quit
```
Run `lldb -b -s <script> ./test_fkps` and `lldb -b -s <script> ./test_authn`, then count the `ta_sa_*` names in the
output. Use a full (non-lite) library for the trace.
