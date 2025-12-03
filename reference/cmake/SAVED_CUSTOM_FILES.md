# Provider Libraries - Saved Custom Files

## Location
All custom files saved to: `reference/cmake/custom_headers/`

## Files Preserved

### 1. ed25519-donna Customizations
- **ed25519-hash-custom.h** (1032 bytes)
  - Integrates mbedTLS SHA-512 instead of OpenSSL
  - Used by ed25519-donna for hashing operations
  
- **ed25519-randombytes-custom.h** (590 bytes)
  - Integrates SecAPI's random number generator
  - Uses `#include "porting/rand.h"` and `rand_load()`

### 2. curve25519-donna Customizations
- **curve25519-donna.h** (732 bytes)
  - Header file we created (not in upstream)
  - Declares `curve25519_donna()` function
  
- **curve25519-randombytes-custom.h** (727 bytes)
  - Integrates SecAPI's random number generator
  - Uses `#include "porting/rand.h"` and `rand_load()`

### 3. Build Configurations
- **edwards_CMakeLists.txt** (1351 bytes)
  - Build config for ed25519-donna provider
  
- **curve25519_CMakeLists.txt** (530 bytes)
  - Build config for curve25519-donna provider
  
- **decaf_CMakeLists.txt** (2996 bytes)
  - Build config for libdecaf provider
  - Includes architecture detection
  - DECAF_448=1 definition

## Next Steps

1. Create ExternalProject configurations in taimpl/CMakeLists.txt
2. Remove src/taimpl/src/internal/providers/ directory
3. Test clean build with automatic download
4. Verify all tests still pass

## Restoration

If needed, files can be restored from `cmake/custom_headers/` or from git history.
