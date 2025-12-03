# Build Patches for ED/X Curve Provider Libraries

## Overview
This directory contains patches that fix build issues discovered during the automation process. These patches are applied automatically by CMake during the build.

## Patches

### 1. ed25519-hash-custom.h.patch
**Purpose**: Remove typedef redefinition to avoid C11 compilation errors

**Issue**: 
The custom hash header defined `typedef unsigned char hash_512bits[64];` but this type is already defined in `ed25519-donna.h`. When compiled with `-Werror,-Wtypedef-redefinition`, this causes a build failure.

**Fix**:
Removes the redundant typedef and adds a comment explaining why.

**Error Fixed**:
```
error: redefinition of typedef 'hash_512bits' is a C11 feature [-Werror,-Wtypedef-redefinition]
typedef unsigned char hash_512bits[64];
                      ^
ed25519-donna.h:61:23: note: previous definition is here
typedef unsigned char hash_512bits[64];
```

**Applied to**: `cmake/custom_headers/ed25519-hash-custom.h`

## How Patches Are Applied

**Current Approach: Pre-patched Custom Headers**

The custom headers in `cmake/custom_headers/` are already patched and ready to use. During the CMake build process:

1. FetchContent downloads the provider libraries (ed25519-donna, curve25519-donna, libdecaf)
2. Custom headers from `cmake/custom_headers/` are copied to the downloaded sources
3. Providers are compiled with the pre-patched custom headers

**Why Pre-patched?**

This approach is simpler and more reliable than applying patches at build time:
- ✅ No dependency on `patch` utility
- ✅ No risk of patch application failures
- ✅ Faster builds (no patch processing)
- ✅ Custom headers are version-controlled with fixes already applied
- ✅ Clear single source of truth in `cmake/custom_headers/`

**What Are Patch Files For?**

The `.patch` files in this directory serve as:
- 📝 **Documentation** of what changes were made to fix build issues
- 🔍 **Reference** for understanding the differences from upstream
- 📋 **History** of build fixes discovered during automation
- 🔄 **Portability** if you need to apply fixes to different versions

## Directory Structure

```
cmake/
├── custom_headers/          # Pre-patched integration headers (used by build)
│   ├── ed25519-hash-custom.h
│   ├── ed25519-randombytes-custom.h
│   ├── curve25519-donna.h
│   └── curve25519-randombytes-custom.h
└── patches/                 # Patch documentation (for reference)
    ├── ed25519-hash-custom.h.patch
    ├── README_PATCHES.md
    └── build_fixes_summary.txt
```

## Alternative: Runtime Patch Application (Not Used)

If you wanted to apply patches at build time instead, you could add this to CMakeLists.txt:

```cmake
# After FetchContent_Populate(ed25519_donna)
# Copy custom headers
file(COPY ${CMAKE_SOURCE_DIR}/cmake/custom_headers/ed25519-hash-custom.h 
     DESTINATION ${ed25519_donna_SOURCE_DIR})

# Apply patches if needed
find_program(PATCH_EXECUTABLE patch)
if(PATCH_EXECUTABLE)
    execute_process(
        COMMAND ${PATCH_EXECUTABLE} -p1 -i ${CMAKE_SOURCE_DIR}/cmake/patches/ed25519-hash-custom.h.patch
        WORKING_DIRECTORY ${ed25519_donna_SOURCE_DIR}
        RESULT_VARIABLE PATCH_RESULT
    )
    if(PATCH_RESULT EQUAL 0)
        message(STATUS "Applied ed25519-hash-custom.h patch")
    else()
        message(WARNING "Failed to apply ed25519-hash-custom.h patch (may already be applied)")
    endif()
endif()
```

**However**, this is unnecessary since we maintain the custom headers ourselves.

## Build Configuration Discoveries

### Include Path Requirements

The following include paths are required for provider libraries:

#### ed25519-donna (edwards_provider)
```cmake
target_include_directories(edwards_provider 
    PUBLIC ${ed25519_donna_SOURCE_DIR}
    PRIVATE 
        ${CMAKE_SOURCE_DIR}/src/taimpl/include  # For porting/rand.h
        ${MBEDTLS_INCLUDE_DIR}                  # For mbedtls/sha512.h
)
```

**Key Discovery**: The `porting/` directory is under `include/` not `src/`:
- ❌ Wrong: `${CMAKE_SOURCE_DIR}/src/taimpl/src/porting`
- ✅ Right: `${CMAKE_SOURCE_DIR}/src/taimpl/include` (allows `#include "porting/rand.h"`)

#### curve25519-donna (curve25519_provider)
```cmake
target_include_directories(curve25519_provider 
    PUBLIC ${curve25519_donna_SOURCE_DIR}
    PRIVATE ${CMAKE_SOURCE_DIR}/src/taimpl/include  # For porting/rand.h
)
```

### Compile Definitions

#### ed25519-donna
```cmake
target_compile_definitions(edwards_provider PRIVATE 
    ED25519_CUSTOMHASH      # Use our custom SHA-512 implementation
    ED25519_CUSTOMRANDOM    # Use our custom random implementation
)
```

#### curve25519-donna
```cmake
target_compile_definitions(curve25519_provider PRIVATE
    CURVE25519_SUFFIX=_donna  # Avoid symbol conflicts
)
```

### Compiler Flags

```cmake
target_compile_options(edwards_provider PRIVATE
    -Werror
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-unused-function
    -Wno-macro-redefined  # Allow redefinition of ED25519_CUSTOMHASH/CUSTOMRANDOM
)
```

## Lessons Learned

1. **Typedef Conflicts**: External libraries may define common types - check for conflicts
2. **Include Path Resolution**: Understand directory structure before setting include paths
3. **Custom Headers Must Be Self-Contained**: They need access to all dependencies
4. **Pre-patched vs Runtime Patching**: Pre-patched custom headers are simpler than applying patches during build
5. **Test Clean Builds**: Always verify automation works from `rm -rf _deps/*`

## Verification

To verify patches work correctly:

```bash
cd reference/cmake-build
rm -rf _deps/ed25519_donna-* _deps/curve25519_donna-* _deps/libdecaf-*
cmake ..
make edwards_provider curve25519_provider -j8
```

Expected result: Clean build with no errors.

## Patch Maintenance

When updating custom headers:
1. Make changes in `cmake/custom_headers/`
2. Test the build
3. If creating a new patch file, use:
   ```bash
   diff -u original_file.h modified_file.h > file.h.patch
   ```
4. Update this README with patch description

---
**Last Updated**: November 22, 2025
