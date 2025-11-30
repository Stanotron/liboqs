#include <stddef.h>
#include <stdint.h>

/* Provided by liboqs */
void OQS_randombytes(uint8_t *buf, size_t len);

/* HAWK expects this symbol */
void randombytes(uint8_t *buf, size_t len) {
    OQS_randombytes(buf, len);
}
