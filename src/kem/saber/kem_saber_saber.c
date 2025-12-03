// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>
#include <oqs/kem_saber.h>

#include <string.h>

// Low-level functions for "Saber" (SABER_L = 3)
extern int saber_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int saber_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int saber_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static OQS_KEM *allocate_kem_saber(void) {
    OQS_KEM *kem = OQS_MEM_malloc(sizeof(OQS_KEM));
    if (kem == NULL) {
        return NULL;
    }
    kem->method_name = OQS_KEM_alg_saber_saber;
    kem->alg_version = "SABER reference implementation (Saber)";

    kem->claimed_nist_level = 3;  // Category 3
    kem->ind_cca = true;

    kem->length_public_key    = OQS_KEM_saber_saber_length_public_key;
    kem->length_secret_key    = OQS_KEM_saber_saber_length_secret_key;
    kem->length_ciphertext    = OQS_KEM_saber_saber_length_ciphertext;
    kem->length_shared_secret = OQS_KEM_saber_saber_length_shared_secret;

    kem->length_keypair_seed = 0;
    kem->length_encaps_seed  = 0;

    kem->keypair_derand = NULL;
    kem->keypair        = OQS_KEM_saber_saber_keypair;
    kem->encaps_derand  = NULL;
    kem->encaps         = OQS_KEM_saber_saber_encaps;
    kem->decaps         = OQS_KEM_saber_saber_decaps;

    return kem;
}

OQS_API OQS_KEM *OQS_KEM_saber_saber_new(void) {
    return allocate_kem_saber();
}

OQS_API OQS_STATUS OQS_KEM_saber_saber_keypair(uint8_t *public_key, uint8_t *secret_key) {
    if (public_key == NULL || secret_key == NULL) {
        return OQS_ERROR;
    }
    int rc = saber_crypto_kem_keypair(public_key, secret_key);
    return (rc == 0) ? OQS_SUCCESS : OQS_ERROR;
}

OQS_API OQS_STATUS OQS_KEM_saber_saber_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                                              const uint8_t *public_key) {
    if (ciphertext == NULL || shared_secret == NULL || public_key == NULL) {
        return OQS_ERROR;
    }
    int rc = saber_crypto_kem_enc(ciphertext, shared_secret, public_key);
    return (rc == 0) ? OQS_SUCCESS : OQS_ERROR;
}

OQS_API OQS_STATUS OQS_KEM_saber_saber_decaps(uint8_t *shared_secret,
                                              const uint8_t *ciphertext,
                                              const uint8_t *secret_key) {
    if (shared_secret == NULL || ciphertext == NULL || secret_key == NULL) {
        return OQS_ERROR;
    }
    int rc = saber_crypto_kem_dec(shared_secret, ciphertext, secret_key);
    return (rc == 0) ? OQS_SUCCESS : OQS_ERROR;
}
