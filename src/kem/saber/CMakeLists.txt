# SPDX-License-Identifier: MIT

# All SABER .c files we copied (excluding the original rng.c)
set(SABER_SOURCES
    kem.c
    SABER_indcpa.c
    pack_unpack.c
    poly.c
    poly_mul.c
    cbd.c
    fips202.c
    verify.c
    saber_randombytes.c
)

set(SABER_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR})

# ==========================
# LightSaber (SABER_L = 2)
# ==========================
add_library(saber_lightsaber_ref OBJECT ${SABER_SOURCES})
target_include_directories(saber_lightsaber_ref PRIVATE ${SABER_INCLUDE_DIR})

target_compile_definitions(saber_lightsaber_ref PRIVATE
    SABER_L=2

    # Public KEM API
    crypto_kem_keypair=lightsaber_crypto_kem_keypair
    crypto_kem_enc=lightsaber_crypto_kem_enc
    crypto_kem_dec=lightsaber_crypto_kem_dec

    # RNG (our shim)
    randombytes=lightsaber_randombytes
    randombytes_init=lightsaber_randombytes_init

    # SHA3 / SHAKE from fips202.c
    sha3_256=lightsaber_sha3_256
    sha3_512=lightsaber_sha3_512
    shake128_absorb=lightsaber_shake128_absorb
    shake128_squeezeblocks=lightsaber_shake128_squeezeblocks
    shake256_absorb=lightsaber_shake256_absorb
    shake256_squeezeblocks=lightsaber_shake256_squeezeblocks
    shake128=lightsaber_shake128
    shake256=lightsaber_shake256

    # verify.c helpers
    verify=lightsaber_verify
    cmov=lightsaber_cmov

    # INDCPA core
    indcpa_kem_keypair=lightsaber_indcpa_kem_keypair
    indcpa_kem_enc=lightsaber_indcpa_kem_enc
    indcpa_kem_dec=lightsaber_indcpa_kem_dec

    # poly_mul.c
    poly_mul_acc=lightsaber_poly_mul_acc

    # cbd.c
    cbd=lightsaber_cbd

    # poly.c
    MatrixVectorMul=lightsaber_MatrixVectorMul
    InnerProd=lightsaber_InnerProd
    GenMatrix=lightsaber_GenMatrix
    GenSecret=lightsaber_GenSecret

    # pack_unpack.c
    POLT2BS=lightsaber_POLT2BS
    BS2POLT=lightsaber_BS2POLT
    POLVECq2BS=lightsaber_POLVECq2BS
    POLVECp2BS=lightsaber_POLVECp2BS
    BS2POLVECq=lightsaber_BS2POLVECq
    BS2POLVECp=lightsaber_BS2POLVECp
    BS2POLmsg=lightsaber_BS2POLmsg
    POLmsg2BS=lightsaber_POLmsg2BS
)

# ======================
# Saber (SABER_L = 3)
# ======================
add_library(saber_saber_ref OBJECT ${SABER_SOURCES})
target_include_directories(saber_saber_ref PRIVATE ${SABER_INCLUDE_DIR})

target_compile_definitions(saber_saber_ref PRIVATE
    SABER_L=3

    crypto_kem_keypair=saber_crypto_kem_keypair
    crypto_kem_enc=saber_crypto_kem_enc
    crypto_kem_dec=saber_crypto_kem_dec

    randombytes=saber_randombytes
    randombytes_init=saber_randombytes_init

    sha3_256=saber_sha3_256
    sha3_512=saber_sha3_512
    shake128_absorb=saber_shake128_absorb
    shake128_squeezeblocks=saber_shake128_squeezeblocks
    shake256_absorb=saber_shake256_absorb
    shake256_squeezeblocks=saber_shake256_squeezeblocks
    shake128=saber_shake128
    shake256=saber_shake256

    verify=saber_verify
    cmov=saber_cmov

    indcpa_kem_keypair=saber_indcpa_kem_keypair
    indcpa_kem_enc=saber_indcpa_kem_enc
    indcpa_kem_dec=saber_indcpa_kem_dec

    poly_mul_acc=saber_poly_mul_acc
    cbd=saber_cbd

    MatrixVectorMul=saber_MatrixVectorMul
    InnerProd=saber_InnerProd
    GenMatrix=saber_GenMatrix
    GenSecret=saber_GenSecret

    POLT2BS=saber_POLT2BS
    BS2POLT=saber_BS2POLT
    POLVECq2BS=saber_POLVECq2BS
    POLVECp2BS=saber_POLVECp2BS
    BS2POLVECq=saber_BS2POLVECq
    BS2POLVECp=saber_BS2POLVECp
    BS2POLmsg=saber_BS2POLmsg
    POLmsg2BS=saber_POLmsg2BS
)

# =========================
# FireSaber (SABER_L = 4)
# =========================
add_library(saber_firesaber_ref OBJECT ${SABER_SOURCES})
target_include_directories(saber_firesaber_ref PRIVATE ${SABER_INCLUDE_DIR})

target_compile_definitions(saber_firesaber_ref PRIVATE
    SABER_L=4

    crypto_kem_keypair=firesaber_crypto_kem_keypair
    crypto_kem_enc=firesaber_crypto_kem_enc
    crypto_kem_dec=firesaber_crypto_kem_dec

    randombytes=firesaber_randombytes
    randombytes_init=firesaber_randombytes_init

    sha3_256=firesaber_sha3_256
    sha3_512=firesaber_sha3_512
    shake128_absorb=firesaber_shake128_absorb
    shake128_squeezeblocks=firesaber_shake128_squeezeblocks
    shake256_absorb=firesaber_shake256_absorb
    shake256_squeezeblocks=firesaber_shake256_squeezeblocks
    shake128=firesaber_shake128
    shake256=firesaber_shake256

    verify=firesaber_verify
    cmov=firesaber_cmov

    indcpa_kem_keypair=firesaber_indcpa_kem_keypair
    indcpa_kem_enc=firesaber_indcpa_kem_enc
    indcpa_kem_dec=firesaber_indcpa_kem_dec

    poly_mul_acc=firesaber_poly_mul_acc
    cbd=firesaber_cbd

    MatrixVectorMul=firesaber_MatrixVectorMul
    InnerProd=firesaber_InnerProd
    GenMatrix=firesaber_GenMatrix
    GenSecret=firesaber_GenSecret

    POLT2BS=firesaber_POLT2BS
    BS2POLT=firesaber_BS2POLT
    POLVECq2BS=firesaber_POLVECq2BS
    POLVECp2BS=firesaber_POLVECp2BS
    BS2POLVECq=firesaber_BS2POLVECq
    BS2POLVECp=firesaber_BS2POLVECp
    BS2POLmsg=firesaber_BS2POLmsg
    POLmsg2BS=firesaber_POLmsg2BS
)

# =========================
# OQS wrapper OBJECT lib
# =========================
add_library(kem_saber OBJECT
    kem_saber_lightsaber.c
    kem_saber_saber.c
    kem_saber_firesaber.c
)
target_include_directories(kem_saber PRIVATE ${SABER_INCLUDE_DIR})

# Expose all SABER variant objects to src/CMakeLists.txt
set(SABER_OBJS
    $<TARGET_OBJECTS:saber_lightsaber_ref>
    $<TARGET_OBJECTS:saber_saber_ref>
    $<TARGET_OBJECTS:saber_firesaber_ref>
    $<TARGET_OBJECTS:kem_saber>
)

set(SABER_OBJS ${SABER_OBJS} PARENT_SCOPE)
