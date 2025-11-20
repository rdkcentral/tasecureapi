# Security API Reference Implementation

## Summary

This library is the reference implementation of the Comcast Security API v3+. SoC vendors are
responsible for implementing this layer, including both the REE client interface and TA client
interface, as well as the backing implementation in TEE.

In this reference implementation, the functionality is implemented using OpenSSL.

## Directories

### 'client'

This directory contains the client facing SecAPI headers, as well as the unit test suite for the
SecAPI.

This folder should be copied over from the reference implementation to the SoC vendor
implementation as-is, without any changes. Comcast will update the reference implementation and
unit tests over time and will expect SoC vendors to keep this folder up to date. Some unit tests,
like sa_key_import_soc.cpp, may be modified by the vendor, especially if the vendor library does
not support a particular feature. The vendor *MUST* declare to Comcast which unit tests have been
modified.

### 'clientimpl'

This directory contains the reference implementation of the SecAPI client library that dispatches
client calls to the SecAPI TA. It is responsible for the serialization of parameters and transport
to the TA.

Client implementation library is required to be ported to both the host (REE) environment for use
by client applications, as well as the TEE environment for use by TA clients.

Only the files in the 'internal' directory need to be modified. All other code in the src directory
is platform independent and should *NOT* be modified.

clientimpl code performs the marshaling of calls from API calls into the TA. Some TEEs require
communication through shared memory, others may be able to use standard memory between the processor
and the TEE. To use shared memory, define the compile time flag USE_SHARED_MEMORY. Vendors *MUST*
implement the client-side functions defined in the porting directory: ta_open_session,
ta_close_session, ta_invoke_command, ta_alloc_shared_memory, and ta_free_shared_memory which are
defined in ta_client.h. Example implementations are in ta_client.c. ta_client.h also defines the
macros, controlled by the compile time USE_SHARED_MEMORY flag, that determine whether shared memory
or standard memory is used by the client-side library.

Vendors *MUST* implement code identified by ```TODO SoC Vendor``` in files in the src/porting
directory.

Vendors may modify code in the src/internal if needed.

### 'taimpl'

This directory contains the reference implementation of the SecAPI TA. TA is responsible for
servicing client requests.

Only the files in the include/internal, include/porting, src/internal, and src/porting directories
need to be modified. All other code in the src and include directories is platform independent and
should *NOT* be modified.

Vendors *MUST* implement code to call the TA-side functions: ta_open_session_handler,
ta_close_session_handler, and ta_invoke_command_handler which defined in ta.h and implemented in
ta.c.

Vendors *MUST* implement code identified by ```TODO SoC Vendor``` in files in the include/porting
and src/porting directories.

include/internal and src/internal directories contain the OpenSSL implementation of SecApi 3.
Vendors may modify code in the include/internal and src/internal directories if needed to replace
the OpenSSL cryptographic implementation with a SoC specific cryptographic implementation. 

### 'util'

This directory contains common functions that are used by both the REE client as well as the TA
implementation. This directory contains code to read a secret symmetric root key from a PKCS 12 key
store. This code is only used by the reference implementation and allows the reference implementation to
be used for testing purposes with a key that is delivered by a keying provider. The reference
implementation provides a default test root key embedded in include/root_keystore.h that is encrypted
with a default password. This default password is also embedded in include/root_keystore.h so the key can
be easily decrypted in tests. If a test root key is provided by a keying provider, the keying provider
should use a different password to the PKCS 12 key store. To change the default test PKCS 12 key store
and password for the reference implementation and for executing the tests, set the ROOT_KEYSTORE
environment variable with the location of the PKCS 12 key store file and the ROOT_KEYSTORE_PASSWORD
environment variable with the password.

NOTE - OpenSSL does not support PKCS 12 Secret Bags since there is no industry specification for the
contents of a Secret Bag. This implementation reads a PKCS 12 key store that is created by Java's
keytool application, which creates a proprietary format of a Secret Bag.

## Building

Generate make files using `cmake`
Add -DCMAKE_INSTALL_PREFIX=<directory> to install to a non-standard install directory.

The build assumes that the following packages have already been installed:
YAJL - include -DYAJL_ROOT=<directory> if not found
OPENSSL - include -DOPENSSL_ROOT_DIR=<directory> if not found

OpenSSL 1.0.2 and 3.0.0+ is supported. OpenSSL 1.1.1j+ is supported.

SoC and root key tests are also disabled by default. To enable these tests, add -DENABLE_SOC_KEY_TESTS=1. The TEST_KEY
key defined in sa_key_common.cpp must match the root key defined on the test device for these tests to pass.

-DDISABLE_CENC_1000000_TESTS=true can be added to disable 1KB sample common encryption tests.

```
cmake -S . -B cmake-build
```

Build reference implementation and unit tests

```
cmake --build cmake-build
```

Run unit test suite

```
cmake --build cmake-build --target test
```
or
```
cd cmake-build
ctest -V
```

To test for memory leaks

```
cd cmake-build
ctest -T memcheck
```

### Install

To install SecApi 3 (libsaclient), run a cmake install with an optional --prefix argument to
install in a non-standard directory.

```
cmake --install cmake-build [--prefix <directory>]
```

This copies the include files, the library, libsaclient.(so/dll/dylib) containing the SecAPI code (the
extension .so/.dll/.dylib created depends on which platform you are building on), and the test application,
saclienttest and taimpltest, to their appropriate locations on the system.

### Build artifacts

#### saclient

This is a client library that client applications link against. It exposes the public, platform
independent SecAPI header files, and links with the platform specific client implementation library
(saclientimpl).  Comcast is responsible for maintaining the public headers exposed by the SecAPI,
while the SoC vendors are responsible for implementing the client library.

#### saclienttest

This is a SecAPI unit test suite that uses the SecAPI public interfaces to test the functionality
of the implementation.  It links against saclient. Comcast is responsible for implementing these
tests.

To Run Key Provision File Based Tests, please refer to:
[SecApiKeyProvisionTaTests.md](./test/SecApiKeyProvisionTaTests.md).

#### saclientimpl

This is a library that implements the SecAPI client interfaces. This library is implemented by the
SoC vendor and it conforms to the interfaces specified in saclient.

#### taimpl

This component is the SecAPI TA that is responsible for processing client requests. The TA is
intended to run in a TEE.

#### taimpltest

This is a SecAPI unit test suite that must be run from inside a TA against the TA code directly.
It executes tests as if another TA were calling into the SecApi 3 TA.

#### util

This is a library that implements utility functions used by the other libraries.

#### utiltest

This is a unit test suite for testing the utility library functions.

## Versioning

SecAPI version is specified using 4 numbers. The first 3 contain the major, minor, and point release
of the SecAPI specification document that this release has implemented. This version triplet is
specified in the src/client/include/sa.h file under the SA_SPECIFICATION_VERSION macro. Comcast is
responsible for updating the version number in this file.  Please see https://semver.org/
for reference.

An additional number is added for specifying an implementation revision for a particular spec
version. SoC vendors are responsible for updating this number with every revision of their
implementation. The full 4 number version can be retrieved using the sa_get_version() call.

## Porting guidance

### Suggested procedure for porting the SecAPI

1. Copy the reference implementation repo.
2. Replace the name of the project in ./CMakeLists.txt.
3. Modify files in src/clientimpl/src/internal, src/taimpl/include/internal,
   src/taimpl/include/porting, src/taimpl/src/internal, and src/taimpl/src/porting folders with
   platform specific implementation for a given platform.
4. Keep all folder except the ones mentioned in 3) up to date with reference implementation
   regularly.

### Secure Heap

SoC vendors are expected to provide memory allocation and de-allocation functions for secure heap if
available on the target platform (memory_secure_alloc, memory_secure_realloc, memory_secure_free).
The secure heap shall be used for storing unencrypted key material while in use.

## Coding Standards

clang-format is used to format all code according to the settings in the associated 
.clang-format file. All attempts were used to use descriptive variable names and predefined
constants instead of magic numbers. When the OpenSSL library is used, standard OpenSSL usage
convention is followed by testing return values against the value 1 which represents success.

clang-tidy is a linting tool used to diagnose and fixing typical programming errors.
