// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_HAWK_H
#define OQS_SIG_HAWK_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_hawk_512)
#define OQS_SIG_hawk_512_length_public_key  1024   // from hawk512/api.h
#define OQS_SIG_hawk_512_length_secret_key  184    // from hawk512/api.h
#define OQS_SIG_hawk_512_length_signature   555    // from hawk512/api.h

OQS_SIG *OQS_SIG_hawk_512_new(void);
OQS_API OQS_STATUS OQS_SIG_hawk_512_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_hawk_512_sign(uint8_t *signature, size_t *signature_len,
                                         const uint8_t *message, size_t message_len,
                                         const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_hawk_512_verify(const uint8_t *message, size_t message_len,
                                           const uint8_t *signature, size_t signature_len,
                                           const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_hawk_512_sign_with_ctx_str(uint8_t *signature, size_t *signature_len,
                                                      const uint8_t *message, size_t message_len,
                                                      const uint8_t *ctx, size_t ctxlen,
                                                      const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_hawk_512_verify_with_ctx_str(const uint8_t *message, size_t message_len,
                                                        const uint8_t *signature, size_t signature_len,
                                                        const uint8_t *ctx, size_t ctxlen,
                                                        const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_hawk_1024)
#define OQS_SIG_hawk_1024_length_public_key  2440  /* CRYPTO_PUBLICKEYBYTES from hawk1024/api.h */
#define OQS_SIG_hawk_1024_length_secret_key  360   /* CRYPTO_SECRETKEYBYTES from hawk1024/api.h */
#define OQS_SIG_hawk_1024_length_signature   1221  /* CRYPTO_BYTES from hawk1024/api.h */

OQS_SIG *OQS_SIG_hawk_1024_new(void);
OQS_API OQS_STATUS OQS_SIG_hawk_1024_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_hawk_1024_sign(uint8_t *signature, size_t *signature_len,
                                          const uint8_t *message, size_t message_len,
                                          const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_hawk_1024_verify(const uint8_t *message, size_t message_len,
                                            const uint8_t *signature, size_t signature_len,
                                            const uint8_t *public_key);
OQS_API OQS_STATUS OQS_SIG_hawk_1024_sign_with_ctx_str(uint8_t *signature, size_t *signature_len,
                                                       const uint8_t *message, size_t message_len,
                                                       const uint8_t *ctx, size_t ctxlen,
                                                       const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_hawk_1024_verify_with_ctx_str(const uint8_t *message, size_t message_len,
                                                         const uint8_t *signature, size_t signature_len,
                                                         const uint8_t *ctx, size_t ctxlen,
                                                         const uint8_t *public_key);
#endif

#endif
