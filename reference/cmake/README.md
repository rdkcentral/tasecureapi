# CMake Build Resources Directory

This directory contains CMake scripts, patches, and custom integration files used during the SecAPI build process.

## Directory Structure

```
cmake/
├── patch_mbedtls.cmake                  # Script to patch mbedTLS
├── patches_mbedtls/                     # mbedTLS patches (external code)
│   ├── gcm_multipart_mbedtls3x_backport.patch
│   └── mbedtls_rsa_pss_hang_fix.patch
├── patches/                             # Provider build fix documentation
│   ├── README_PATCHES.md
│   ├── build_fixes_summary.txt
│   └── ed25519-hash-custom.h.patch
├── custom_headers/                      # Pre-patched provider integration headers
│   ├── ed25519-hash-custom.h
│   ├── ed25519-randombytes-custom.h
│   ├── curve25519-donna.h
│   ├── curve25519-randombytes-custom.h
│   ├── edwards_CMakeLists.txt          # Backup CMakeLists
│   ├── curve25519_CMakeLists.txt       # Backup CMakeLists
│   └── decaf_CMakeLists.txt            # Backup CMakeLists
├── SAVED_CUSTOM_FILES.md                # Documentation of saved files
└── ClangFormat.cmake                    # Clang-format integration
```

## File Descriptions

### Scripts

#### `patch_mbedtls.cmake`
CMake script that patches mbedTLS source code during the build process. Called by `ExternalProject_Add` in the main CMakeLists.txt.

**What it does:**
- Modifies mbedTLS CMakeLists.txt to require CMake 3.10...3.28
- Enables CMAC and PLATFORM_MEMORY in mbedTLS config.h
- Applies RSA PSS hang fix patch
- Applies GCM multi-part fix patch (backported from mbedTLS 3.x)

**How it's used:**
```cmake
ExternalProject_Add(mbedtls_external
    ...
    PATCH_COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/patch_mbedtls.cmake <SOURCE_DIR>
    ...
)
```

#### `ClangFormat.cmake`
Utilities for clang-format integration (code formatting).

---

### Patches for mbedTLS (`patches_mbedtls/`)

These patches fix issues in the external mbedTLS library. Applied automatically during build via `patch_mbedtls.cmake`.

#### `mbedtls_rsa_pss_hang_fix.patch`
**Purpose:** Fixes RSA-PSS signature verification hang issue  
**Target:** mbedTLS 2.16.10 `library/rsa.c`  
**Applied:** Automatically via `patch` command in `patch_mbedtls.cmake`

#### `gcm_multipart_mbedtls3x_backport.patch`
**Purpose:** Backports GCM multi-part encryption fix from mbedTLS 3.x  
**Target:** mbedTLS 2.16.10 `library/gcm.c`  
**Applied:** Automatically via `patch` command in `patch_mbedtls.cmake`

---

### Provider Build Fixes (`patches/`)

Documentation of fixes applied to ED/X curve provider integration. These are **not applied at runtime** - the fixes are already in `custom_headers/`.

#### `README_PATCHES.md`
Comprehensive documentation of all provider build fixes:
- Typedef redefinition fix
- Include path requirements
- mbedTLS dependency
- Compile definitions needed
- Lessons learned during automation

#### `build_fixes_summary.txt`
Detailed summary of 5 build fixes discovered during automation:
1. Include path correction (porting/rand.h location)
2. mbedTLS include directory addition
3. Typedef redefinition removal
4. Compile definitions (ED25519_CUSTOMHASH/CUSTOMRANDOM)
5. Compiler warning suppression

#### `ed25519-hash-custom.h.patch`
Patch file showing the typedef removal fix. **For documentation only** - the fix is already applied in `custom_headers/ed25519-hash-custom.h`.

---

### Custom Provider Integration Headers (`custom_headers/`)

Pre-patched custom headers that integrate external ED/X curve libraries with SecAPI. These files are **copied into downloaded provider sources** during CMake configuration.

#### ED25519 Integration (ed25519-donna)

**`ed25519-hash-custom.h`**
- Adapts ed25519-donna to use mbedTLS SHA-512 instead of OpenSSL
- Implements: `ed25519_hash_context`, `ed25519_hash_init()`, `ed25519_hash_update()`, `ed25519_hash_final()`, `ed25519_hash()`
- **Pre-patched:** Typedef redefinition removed (was causing C11 error)

**`ed25519-randombytes-custom.h`**
- Adapts ed25519-donna to use SecAPI's porting layer for random number generation
- Implements: `ed25519_randombytes_unsafe()` using `rand_bytes()` from `porting/rand.h`
- Note: "unsafe" suffix is ed25519-donna convention, implementation IS cryptographically secure

#### X25519 Integration (curve25519-donna)

**`curve25519-donna.h`**
- Forward declarations for curve25519-donna functions
- Defines `curve25519_donna()` interface

**`curve25519-randombytes-custom.h`**
- Adapts curve25519-donna to use SecAPI's porting layer for random number generation
- Implements: `curve25519_randombytes()` using `rand_bytes()` from `porting/rand.h`

#### Backup CMakeLists (Archive)

**`edwards_CMakeLists.txt`**  
**`curve25519_CMakeLists.txt`**  
**`decaf_CMakeLists.txt`**

Backup copies of original CMakeLists.txt files from when providers were manually integrated. Kept for reference but **not used in automated build**.

---

### Documentation

#### `SAVED_CUSTOM_FILES.md`
List of files that were preserved in `custom_headers/` before removing the manual provider integration and implementing FetchContent automation.

---

## How These Resources Are Used

### During CMake Configuration

1. **FetchContent downloads provider libraries** (ed25519-donna, curve25519-donna, libdecaf)
   ```cmake
   FetchContent_Declare(ed25519_donna 
       GIT_REPOSITORY https://github.com/floodyberry/ed25519-donna.git
   )
   ```

2. **Custom headers are copied** to downloaded sources
   ```cmake
   file(COPY ${CMAKE_SOURCE_DIR}/cmake/custom_headers/ed25519-hash-custom.h
        DESTINATION ${ed25519_donna_SOURCE_DIR})
   ```

3. **mbedTLS is downloaded and patched**
   ```cmake
   ExternalProject_Add(mbedtls_external
       PATCH_COMMAND ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/cmake/patch_mbedtls.cmake <SOURCE_DIR>
   )
   ```

### During Build

4. **Provider libraries are compiled** with custom headers integrated
   - `edwards_provider` (ED25519)
   - `curve25519_provider` (X25519)
   - `decaf` (ED448/X448)

5. **All patches are already applied** (mbedTLS via `patch` command, providers via pre-patched headers)

---

## Why This Structure?

### Separation of Concerns

- **`patches_mbedtls/`** - Patches for **external code we don't control** (mbedTLS)
- **`patches/`** - Documentation of fixes to **our integration code** (custom headers)
- **`custom_headers/`** - **Working versions** of our integration headers (pre-patched)

### Pre-patched vs Runtime Patching

**mbedTLS:** Runtime patching using `patch` command
- ✅ We don't maintain mbedTLS source
- ✅ Patches can be updated independently
- ✅ Clear separation of upstream vs our fixes

**Custom Headers:** Pre-patched in repository
- ✅ We maintain these files
- ✅ No `patch` utility dependency
- ✅ Simpler and faster builds
- ✅ Single source of truth
- ✅ Version controlled with fixes already applied

---

## Maintenance

### When Updating Custom Headers

1. Edit files in `cmake/custom_headers/`
2. Test the build
3. If creating a diff for documentation:
   ```bash
   diff -u original.h modified.h > cmake/patches/file.h.patch
   ```
4. Update `cmake/patches/README_PATCHES.md` if needed

### When Updating mbedTLS Patches

1. Create/modify `.patch` file in `cmake/patches_mbedtls/`
2. Update `cmake/patch_mbedtls.cmake` if adding new patches
3. Test clean build:
   ```bash
   cd cmake-build
   rm -rf mbedtls
   cmake ..
   make mbedtls_external
   ```

### Testing Everything

Clean build from scratch:
```bash
cd reference
rm -rf cmake-build
mkdir cmake-build && cd cmake-build
cmake ..
make -j8
```

Expected result: All libraries download, all patches apply, everything builds successfully.

---

## Build Dependencies

### Required for Provider Automation

- **Git:** To clone provider libraries
- **CMake 3.10+:** For FetchContent and ExternalProject
- **Python 3:** For libdecaf code generation

### Required for mbedTLS Patching

- **patch:** Unix patch utility (standard on macOS/Linux)

### Build Targets Created

- `edwards_provider` (libedwards_provider.a) - ED25519 support
- `curve25519_provider` (libcurve25519_provider.a) - X25519 support  
- `decaf` (libdecaf.a) - ED448/X448 support
- `mbedtls_external` - mbedTLS 2.16.10 with patches

---

## References

- [ED/X Curve Library Architecture](../docs/ED_X_CURVE_LIBRARY_ARCHITECTURE.md)
- [Provider Libraries Automation](../docs/PROVIDER_LIBRARIES_AUTOMATION.md)
- [Automation Success Summary](../docs/AUTOMATION_SUCCESS_SUMMARY.md)
- [Build Fixes Documentation](patches/README_PATCHES.md)
- [Build Fixes Summary](patches/build_fixes_summary.txt)

---

**Last Updated:** November 22, 2025  
**Automation Status:** ✅ Fully Automated
