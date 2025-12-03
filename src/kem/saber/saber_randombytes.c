#include <stddef.h>
#include <stdint.h>

#include "rng.h"        
#include "oqs/oqs.h"    

void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength) {
    (void) entropy_input;
    (void) personalization_string;
    (void) security_strength;
}

int randombytes(unsigned char *x, unsigned long long xlen) {
    if (xlen == 0) {
        return RNG_SUCCESS;
    }
    OQS_randombytes(x, (size_t) xlen);
    return RNG_SUCCESS;
}
