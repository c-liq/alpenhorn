cmake_minimum_required(VERSION 2.8)
project(Alpenhorn)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_COMPILER gcc)
set(CMAKE_VERBOSE_MAKEFILE on)
set(CMAKE_ASM_COMPILER gcc)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
enable_language(ASM)

FUNCTION(PREPEND var prefix)
    SET(listVar "")
    FOREACH (f ${ARGN})
        LIST(APPEND listVar "${prefix}/${f}")
    ENDFOREACH (f)
    SET(${var} "${listVar}" PARENT_SCOPE)
ENDFUNCTION(PREPEND)

set(BN256_SOURCES linefunction.c optate.c fpe.c fp2e.c fp6e.c fp12e.c curvepoint_fp.c twistpoint_fp2.c final_expo.c
        scalar.c parameters.c mul.c mydouble.c fp2e_add2.s fp2e_sub2.s fp2e_double2.s fp2e_triple2.s fp2e_neg2.s
        fp2e_mul.s fp2e_mul_fpe.s fp2e_short_coeffred.s fp2e_add.s fp2e_sub.s fp2e_parallel_coeffmul.s fp2e_mulxi.s
        fp2e_double.s fp2e_triple.s fp2e_neg.s fp2e_conjugate.s fpe_mul.s fp2e_square.s consts.s
        scalar_sub_nored.s index_heap.c)

set(DCLXVI_ASM_SOURCES fp2e_add2.s fp2e_sub2.s fp2e_double2.s fp2e_triple2.s fp2e_neg2.s fp2e_mul.s fp2e_mul_fpe.s
        fp2e_short_coeffred.s fp2e_add.s fp2e_sub.s fp2e_parallel_coeffmul.s fp2e_mulxi.s fp2e_double.s fp2e_triple.s
        fp2e_neg.s fp2e_conjugate.s fpe_mul.s fp2e_square.s consts.s)
PREPEND(BN256_SOURCES lib/bn256/ ${BN256_SOURCES})
PREPEND(DCLXVI_ASM_SOURCES lib/bn256/ ${DCLXVI_ASM_SOURCES})

set(BN256_SOURCE_FILES lib/bn256/parameters.c lib/bn256/twistpoint_fp2.c lib/bn256/mul.c lib/bn256/mydouble.c lib/bn256/curvepoint_fp.c
        lib/bn256/heap_rootreplaced.s lib/bn256/index_heap.c lib/bn256/scalar_sub_nored.s

        lib/bn256/optate.c lib/bn256/linefunction.c lib/bn256/final_expo.c lib/bn256/gmp_convert.c
        src/crypto/bn256.c src/crypto/bn256_ibe.c src/crypto/bn256_bls.c src/crypto/crypto_salsa.c)
set(CMAKE_AR_F)

set(PBC_SOURCE_FILES ${BN256_SOURCE_FILES})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DQHASM -fomit-frame-pointer")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -DQHASM -fomit-frame-pointer -std=c99")
#set(CMAKE_C_STANDARD_LIBRARIES ${CMAKE_SOURCE_DIR}/asfunctions.a)
add_library(dclxvi STATIC ${BN256_SOURCES})
include_directories(${Alpenhorn_SOURCE_DIR}/include)
include_directories(${Alpenhorn_SOURCE_DIR}/lib)


set(ALP_SOURCE_FILES src/crypto/crypto.c src/crypto/crypto_salsa.c src/crypto/bn256.c src/utils/utils.c src/utils/byte_buffer.c
        src/utils/bloom.c src/utils/list.c src/utils/net.c src/utils/prime_gen.c lib/xxhash/xxhash.c)

set(CLIENT_SOURCE_FILES ${PBC_SOURCE_FILES} ${ALP_SOURCE_FILES} src/alpenhorn/client.c src/alpenhorn/keywheel_table.c include/alpenhorn/client_config.h)
set(MIX_SOURCE_FILES ${PBC_SOURCE_FILES} ${ALP_SOURCE_FILES} src/alpenhorn/mixnet.c)
set(PKG_SOURCE_FILES ${PBC_SOURCE_FILES} ${ALP_SOURCE_FILES} src/alpenhorn/pkg.c lib/thpool/thpool.c)
set(TEST_BN256_SOURCES tests/test_bn256_ibe.c include/greatest.h src/utils/utils.c)
set(TEST_PKG_SOURCE_FILES ${PKG_SOURCE_FILES} ${CLIENT_SOURCE_FILES} tests/test_bench_pkg_server.c include/greatest.h include/crypto_aes.h)
set(TEST_BLOOM_SOURCES src/utils/bloom.c src/utils/utils.c include/greatest.h tests/test_bloom.c lib/xxhash/xxhash.c src/utils/prime_gen.c)
set(TEST_MIX_SOURCES ${MIX_SOURCE_FILES} include/greatest.h tests/test_mix.c)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath /usr/local/lib -lsodium -lm -lgmp -lcurl")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I /usr/local/include -pthread -Wall -Wpedantic")

add_executable(client_example ${CLIENT_SOURCE_FILES} src/alpenhorn/client_example.c)
add_executable(mixnet_server ${MIX_SOURCE_FILES} src/alpenhorn/mixnet_run.c)
add_executable(pkg_server ${PKG_SOURCE_FILES} src/alpenhorn/pkg_run.c)


add_executable(user_gen src/utils/user_generator.c)
add_executable(test_bloom src/utils/bloom.c tests/test_bloom.c include/greatest.h lib/xxhash/xxhash.c src/utils/prime_gen.c)
target_link_libraries(pkg_server dclxvi)
