// SPDX-License-Identifier: MIT
//
// OQS wrapper for SABER KEM family: LightSaber, Saber, FireSaber.

#ifndef OQS_KEM_SABER_H
#define OQS_KEM_SABER_H

#include <oqs/oqs.h>

#if defined(__cplusplus)
extern "C" {
#endif

/** Algorithm identifier for LightSaber KEM. */
#define OQS_KEM_alg_saber_lightsaber "LightSaber-KEM"
/** Algorithm identifier for Saber KEM. */
#define OQS_KEM_alg_saber_saber "Saber-KEM"
/** Algorithm identifier for FireSaber KEM. */
#define OQS_KEM_alg_saber_firesaber "FireSaber-KEM"

/* Sizes taken from SABER specification / ETSI TR 103 823 Table 18:
 *   LightSaber: pk=672, sk=1568, ct=736
 *   Saber:      pk=992, sk=2304, ct=1088
 *   FireSaber:  pk=1312, sk=3040, ct=1472
 *   Shared secret: 32 bytes (SABER_KEYBYTES)
 */

#define OQS_KEM_saber_lightsaber_length_public_key    672
#define OQS_KEM_saber_lightsaber_length_secret_key   1568
#define OQS_KEM_saber_lightsaber_length_ciphertext    736
#define OQS_KEM_saber_lightsaber_length_shared_secret  32

#define OQS_KEM_saber_saber_length_public_key         992
#define OQS_KEM_saber_saber_length_secret_key        2304
#define OQS_KEM_saber_saber_length_ciphertext        1088
#define OQS_KEM_saber_saber_length_shared_secret       32

#define OQS_KEM_saber_firesaber_length_public_key    1312
#define OQS_KEM_saber_firesaber_length_secret_key    3040
#define OQS_KEM_saber_firesaber_length_ciphertext    1472
#define OQS_KEM_saber_firesaber_length_shared_secret   32

OQS_API OQS_KEM *OQS_KEM_saber_lightsaber_new(void);
OQS_API OQS_KEM *OQS_KEM_saber_saber_new(void);
OQS_API OQS_KEM *OQS_KEM_saber_firesaber_new(void);

/* "Normal" randomized API */

OQS_API OQS_STATUS OQS_KEM_saber_lightsaber_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_saber_lightsaber_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                                                   const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_saber_lightsaber_decaps(uint8_t *shared_secret,
                                                   const uint8_t *ciphertext,
                                                   const uint8_t *secret_key);

OQS_API OQS_STATUS OQS_KEM_saber_saber_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_saber_saber_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                                              const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_saber_saber_decaps(uint8_t *shared_secret,
                                              const uint8_t *ciphertext,
                                              const uint8_t *secret_key);

OQS_API OQS_STATUS OQS_KEM_saber_firesaber_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_saber_firesaber_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                                                  const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_saber_firesaber_decaps(uint8_t *shared_secret,
                                                  const uint8_t *ciphertext,
                                                  const uint8_t *secret_key);

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OQS_KEM_SABER_H
