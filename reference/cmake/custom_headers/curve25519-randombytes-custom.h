/*
 * Custom random number generator for curve25519-donna
 * Uses /dev/urandom for random byte generation
 */

#ifndef CURVE25519_RANDOMBYTES_CUSTOM_H
#define CURVE25519_RANDOMBYTES_CUSTOM_H

#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

static void curve25519_randombytes(uint8_t *buffer, size_t length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        // Fallback or error handling
        return;
    }
    
    size_t total = 0;
    while (total < length) {
        ssize_t n = read(fd, buffer + total, length - total);
        if (n <= 0) {
            break;
        }
        total += n;
    }
    
    close(fd);
}

#endif /* CURVE25519_RANDOMBYTES_CUSTOM_H */
