# SPDX-License-Identifier: MIT

set(HAWK_OBJS "")

# Common wrapper code: the two sig_hawk_* files and RNG shim
add_library(sig_hawk OBJECT
    sig_hawk_512.c
    sig_hawk_1024.c
    hawk_randombytes.c
)
target_include_directories(sig_hawk PRIVATE ${CMAKE_CURRENT_LIST_DIR})
list(APPEND HAWK_OBJS $<TARGET_OBJECTS:sig_hawk>)

# HAWK-512 reference implementation
if(OQS_ENABLE_SIG_hawk_512)
    add_library(hawk_512_ref OBJECT
        hawk512/api.c
        hawk512/hawk_kgen.c
        hawk512/hawk_sign.c
        hawk512/hawk_vrfy.c
        hawk512/ng_fxp.c
        hawk512/ng_hawk.c
        hawk512/ng_mp31.c
        hawk512/ng_ntru.c
        hawk512/ng_poly.c
        hawk512/ng_zint31.c
        hawk512/sha3.c
        # NOTE: we do NOT use hawk512/rng.c, we use hawk_randombytes.c instead
    )
    target_include_directories(hawk_512_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/hawk512)
    # Avoid symbol collisions with liboqs SHA3 by renaming HAWK's SHAKE/SHA3
    target_compile_definitions(hawk_512_ref PRIVATE
        crypto_sign_keypair=hawk512_crypto_sign_keypair
        crypto_sign=hawk512_crypto_sign
        crypto_sign_open=hawk512_crypto_sign_open
        shake_init=hawk512_shake_init
        shake_inject=hawk512_shake_inject
        shake_flip=hawk512_shake_flip
        shake_extract=hawk512_shake_extract
        sha3_init=hawk512_sha3_init
        sha3_update=hawk512_sha3_update
        sha3_close=hawk512_sha3_close
        shake_x4_flip=hawk512_shake_x4_flip
        shake_x4_extract_words=hawk512_shake_x4_extract_words
    )
    list(APPEND HAWK_OBJS $<TARGET_OBJECTS:hawk_512_ref>)
endif()

# HAWK-1024 reference implementation
if(OQS_ENABLE_SIG_hawk_1024)
    add_library(hawk_1024_ref OBJECT
        hawk1024/api.c
        hawk1024/hawk_kgen.c
        hawk1024/hawk_sign.c
        hawk1024/hawk_vrfy.c
        hawk1024/ng_fxp.c
        hawk1024/ng_hawk.c
        hawk1024/ng_mp31.c
        hawk1024/ng_ntru.c
        hawk1024/ng_poly.c
        hawk1024/ng_zint31.c
        hawk1024/sha3.c
        # again, we skip hawk1024/rng.c and use the common shim
    )
    target_include_directories(hawk_1024_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/hawk1024)
    target_compile_definitions(hawk_1024_ref PRIVATE
    # Public PQClean-style API renaming
    crypto_sign_keypair=hawk1024_crypto_sign_keypair
    crypto_sign=hawk1024_crypto_sign
    crypto_sign_open=hawk1024_crypto_sign_open

    # SHA3 / SHAKE helpers (to avoid clashes with liboqs sha3)
    shake_init=hawk1024_shake_init
    shake_inject=hawk1024_shake_inject
    shake_flip=hawk1024_shake_flip
    shake_extract=hawk1024_shake_extract
    sha3_init=hawk1024_sha3_init
    sha3_update=hawk1024_sha3_update
    sha3_close=hawk1024_sha3_close
    shake_x4_flip=hawk1024_shake_x4_flip
    shake_x4_extract_words=hawk1024_shake_x4_extract_words

    # Internal Hawk keygen / sign / verify helpers
    hawk_keygen=hawk1024_keygen
    hawk_sign_start=hawk1024_sign_start
    hawk_sign_finish=hawk1024_sign_finish
    hawk_sign_finish_alt=hawk1024_sign_finish_alt
    hawk_decode_private_key=hawk1024_decode_private_key
    hawk_decode_signature=hawk1024_decode_signature
    hawk_decode_public_key=hawk1024_decode_public_key
    hawk_verify_finish=hawk1024_verify_finish
    hawk_verify_inner=hawk1024_verify_inner

    # ntrugen / ng_* helpers (zint)
    hawk_ntrugen_zint_mul_small=hawk1024_ntrugen_zint_mul_small
    hawk_ntrugen_zint_mod_small_unsigned=hawk1024_ntrugen_zint_mod_small_unsigned
    hawk_ntrugen_zint_add_mul_small=hawk1024_ntrugen_zint_add_mul_small
    hawk_ntrugen_zint_norm_zero=hawk1024_ntrugen_zint_norm_zero
    hawk_ntrugen_rebuild_CRT=hawk1024_ntrugen_rebuild_CRT
    hawk_ntrugen_zint_negate=hawk1024_ntrugen_zint_negate
    hawk_ntrugen_zint_bezout=hawk1024_ntrugen_zint_bezout
    hawk_ntrugen_zint_add_scaled_mul_small=hawk1024_ntrugen_zint_add_scaled_mul_small
    hawk_ntrugen_zint_sub_scaled=hawk1024_ntrugen_zint_sub_scaled

    # ntrugen / ng_* helpers (poly)
    hawk_ntrugen_poly_mp_set_small=hawk1024_ntrugen_poly_mp_set_small
    hawk_ntrugen_poly_mp_set=hawk1024_ntrugen_poly_mp_set
    hawk_ntrugen_poly_mp_norm=hawk1024_ntrugen_poly_mp_norm
    hawk_ntrugen_poly_big_to_small=hawk1024_ntrugen_poly_big_to_small
    hawk_ntrugen_poly_max_bitlength=hawk1024_ntrugen_poly_max_bitlength
    hawk_ntrugen_poly_big_to_fixed=hawk1024_ntrugen_poly_big_to_fixed
    hawk_ntrugen_poly_sub_scaled=hawk1024_ntrugen_poly_sub_scaled
    hawk_ntrugen_poly_sub_scaled_ntt=hawk1024_ntrugen_poly_sub_scaled_ntt
    hawk_ntrugen_poly_sub_kf_scaled_depth1=hawk1024_ntrugen_poly_sub_kf_scaled_depth1
    hawk_ntrugen_poly_is_invertible=hawk1024_ntrugen_poly_is_invertible
    hawk_ntrugen_poly_is_invertible_ext=hawk1024_ntrugen_poly_is_invertible_ext
    hawk_ntrugen_poly_sqnorm=hawk1024_ntrugen_poly_sqnorm

    # ntrugen / ng_* helpers (NTRU + mp)
    hawk_ntrugen_solve_NTRU=hawk1024_ntrugen_solve_NTRU
    hawk_ntrugen_recover_G=hawk1024_ntrugen_recover_G
    hawk_ntrugen_PRIMES=hawk1024_ntrugen_PRIMES
    hawk_ntrugen_mp_div=hawk1024_ntrugen_mp_div
    hawk_ntrugen_mp_mkgmigm=hawk1024_ntrugen_mp_mkgmigm
    hawk_ntrugen_mp_mkgm=hawk1024_ntrugen_mp_mkgm
    hawk_ntrugen_mp_mkgm7=hawk1024_ntrugen_mp_mkgm7
    hawk_ntrugen_mp_mkigm=hawk1024_ntrugen_mp_mkigm
    hawk_ntrugen_mp_NTT=hawk1024_ntrugen_mp_NTT
    hawk_ntrugen_mp_iNTT=hawk1024_ntrugen_mp_iNTT

    # ntrugen / ng_* helpers (Hawk high-level)
    hawk_ntrugen_Hawk_keygen=hawk1024_ntrugen_Hawk_keygen
    hawk_ntrugen_Hawk_regen_fg=hawk1024_ntrugen_Hawk_regen_fg
    hawk_ntrugen_Hawk_recover_G=hawk1024_ntrugen_Hawk_recover_G
    hawk_ntrugen_Hawk_recover_qq=hawk1024_ntrugen_Hawk_recover_qq

    # ntrugen / ng_* helpers (fixed-point / FFT)
    hawk_ntrugen_inner_fxr_div=hawk1024_ntrugen_inner_fxr_div
    hawk_ntrugen_vect_FFT=hawk1024_ntrugen_vect_FFT
    hawk_ntrugen_vect_iFFT=hawk1024_ntrugen_vect_iFFT
    hawk_ntrugen_vect_set=hawk1024_ntrugen_vect_set
    hawk_ntrugen_vect_add=hawk1024_ntrugen_vect_add
    hawk_ntrugen_vect_mul_realconst=hawk1024_ntrugen_vect_mul_realconst
    hawk_ntrugen_vect_mul2e=hawk1024_ntrugen_vect_mul2e
    hawk_ntrugen_vect_mul_fft=hawk1024_ntrugen_vect_mul_fft
    hawk_ntrugen_vect_adj_fft=hawk1024_ntrugen_vect_adj_fft
    hawk_ntrugen_vect_mul_autoadj_fft=hawk1024_ntrugen_vect_mul_autoadj_fft
    hawk_ntrugen_vect_div_autoadj_fft=hawk1024_ntrugen_vect_div_autoadj_fft
    hawk_ntrugen_vect_invnorm_fft=hawk1024_ntrugen_vect_invnorm_fft
    hawk_ntrugen_vect_inv_mul2e_fft=hawk1024_ntrugen_vect_inv_mul2e_fft
)

    list(APPEND HAWK_OBJS $<TARGET_OBJECTS:hawk_1024_ref>)
endif()

set(HAWK_OBJS ${HAWK_OBJS} PARENT_SCOPE)
