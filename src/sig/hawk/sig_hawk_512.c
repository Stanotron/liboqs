// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <string.h>

#include <oqs/sig_hawk.h>

#if defined(OQS_ENABLE_SIG_hawk_512)

OQS_SIG *OQS_SIG_hawk_512_new(void) {

    OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
    if (sig == NULL) {
        return NULL;
    }
    sig->method_name = OQS_SIG_alg_hawk_512;
    sig->alg_version = "HAWK NIST reference implementation";

    sig->claimed_nist_level = 1;   // Hawk-512 is NIST-I
    sig->euf_cma = true;
    sig->suf_cma = false;
    sig->sig_with_ctx_support = false;

    sig->length_public_key = OQS_SIG_hawk_512_length_public_key;
    sig->length_secret_key = OQS_SIG_hawk_512_length_secret_key;
    sig->length_signature  = OQS_SIG_hawk_512_length_signature;

    sig->keypair = OQS_SIG_hawk_512_keypair;
    sig->sign = OQS_SIG_hawk_512_sign;
    sig->verify = OQS_SIG_hawk_512_verify;
    sig->sign_with_ctx_str = OQS_SIG_hawk_512_sign_with_ctx_str;
    sig->verify_with_ctx_str = OQS_SIG_hawk_512_verify_with_ctx_str;

    return sig;
}

/* Low-level HAWK-512 functions from hawk512/api.c,
 * after name-mangling in CMake with:
 *   -Dcrypto_sign_keypair=hawk512_crypto_sign_keypair
 *   -Dcrypto_sign=hawk512_crypto_sign
 *   -Dcrypto_sign_open=hawk512_crypto_sign_open
 */
extern int hawk512_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
extern int hawk512_crypto_sign(unsigned char *sm, unsigned long long *smlen,
                               const unsigned char *m, unsigned long long mlen,
                               const unsigned char *sk);
extern int hawk512_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                    const unsigned char *sm, unsigned long long smlen,
                                    const unsigned char *pk);

OQS_API OQS_STATUS OQS_SIG_hawk_512_keypair(uint8_t *public_key, uint8_t *secret_key) {
    int rc = hawk512_crypto_sign_keypair(public_key, secret_key);
    return rc == 0 ? OQS_SUCCESS : OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_hawk_512_sign(uint8_t *signature, size_t *signature_len,
                                         const uint8_t *message, size_t message_len,
                                         const uint8_t *secret_key) {
    // HAWK api.c: crypto_sign(sm, smlen, m, mlen, sk)
    // returns sm = m || sig (signed message), smlen = mlen + siglen.

    unsigned long long sm_cap = (unsigned long long)(message_len + OQS_SIG_hawk_512_length_signature);
    unsigned char *sm = OQS_MEM_malloc(sm_cap);
    if (sm == NULL) {
        return OQS_ERROR;
    }

    unsigned long long out_smlen = 0;
    int rc = hawk512_crypto_sign(sm, &out_smlen,
                                 message, (unsigned long long) message_len,
                                 secret_key);
    if (rc != 0) {
        OQS_MEM_secure_free(sm, sm_cap);
        return OQS_ERROR;
    }

    if (out_smlen < (unsigned long long) message_len) {
        // should never happen
        OQS_MEM_secure_free(sm, sm_cap);
        return OQS_ERROR;
    }

    size_t sig_len = (size_t)(out_smlen - (unsigned long long) message_len);
    if (sig_len > OQS_SIG_hawk_512_length_signature) {
        // our advertised max signature length is too small
        OQS_MEM_secure_free(sm, sm_cap);
        return OQS_ERROR;
    }

    // Signature is the LAST sig_len bytes of sm (m || sig)
    memcpy(signature, sm + (out_smlen - sig_len), sig_len);
    *signature_len = sig_len;

    OQS_MEM_secure_free(sm, sm_cap);
    return OQS_SUCCESS;
}

OQS_API OQS_STATUS OQS_SIG_hawk_512_verify(const uint8_t *message, size_t message_len,
                                           const uint8_t *signature, size_t signature_len,
                                           const uint8_t *public_key) {
    // Rebuild sm = m || sig and call crypto_sign_open.

    unsigned long long smlen = (unsigned long long) message_len + (unsigned long long) signature_len;
    unsigned char *sm = OQS_MEM_malloc(smlen);
    if (sm == NULL) {
        return OQS_ERROR;
    }

    memcpy(sm, message, message_len);
    memcpy(sm + message_len, signature, signature_len);

    unsigned char *m_out = OQS_MEM_malloc(message_len);
    if (m_out == NULL) {
        OQS_MEM_secure_free(sm, smlen);
        return OQS_ERROR;
    }

    unsigned long long m_out_len = 0;
    int rc = hawk512_crypto_sign_open(m_out, &m_out_len, sm, smlen, public_key);

    OQS_MEM_secure_free(sm, smlen);
    OQS_MEM_secure_free(m_out, message_len);

    // Accept only if verify succeeded AND the recovered message length matches.
    return (rc == 0 && m_out_len == (unsigned long long) message_len) ? OQS_SUCCESS : OQS_ERROR;
}



OQS_API OQS_STATUS OQS_SIG_hawk_512_sign_with_ctx_str(uint8_t *signature, size_t *signature_len,
                                                      const uint8_t *message, size_t message_len,
                                                      const uint8_t *ctx_str, size_t ctx_str_len,
                                                      const uint8_t *secret_key) {
    // HAWK reference API doesn't support a context string; just allow empty ctx.
    if (ctx_str == NULL && ctx_str_len == 0) {
        return OQS_SIG_hawk_512_sign(signature, signature_len, message, message_len, secret_key);
    } else {
        return OQS_ERROR;
    }
}

OQS_API OQS_STATUS OQS_SIG_hawk_512_verify_with_ctx_str(const uint8_t *message, size_t message_len,
                                                        const uint8_t *signature, size_t signature_len,
                                                        const uint8_t *ctx_str, size_t ctx_str_len,
                                                        const uint8_t *public_key) {
    if (ctx_str == NULL && ctx_str_len == 0) {
        return OQS_SIG_hawk_512_verify(message, message_len, signature, signature_len, public_key);
    } else {
        return OQS_ERROR;
    }
}

#endif // OQS_ENABLE_SIG_hawk_512
