cmake_minimum_required(VERSION 2.8)
project(Alpenhorn)
set(CMAKE_C_STANDARD 99)
set(CMAKE_VERBOSE_MAKEFILE on)

set(USE_PBC FALSE)

if (USE_PBC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D USE_PBC")
endif ()

set(BN256_SOURCE_FILES lib/bn256/fpe.c lib/bn256/fp2e.c lib/bn256/scalar.c lib/bn256/parameters.c
        lib/bn256/twistpoint_fp2.c lib/bn256/mul.c lib/bn256/mydouble.c lib/bn256/curvepoint_fp.c
        lib/bn256/heap_rootreplaced.s lib/bn256/index_heap.c lib/bn256/scalar_sub_nored.s
        lib/bn256/fp12e.c lib/bn256/fpe.c lib/bn256/fp2e.c lib/bn256/fp6e.c
        lib/bn256/optate.c lib/bn256/linefunction.c lib/bn256/final_expo.c lib/bn256/gmp_convert.c
        src/crypto/bn256.c src/crypto/bn256_ibe.c src/crypto/bn256_bls.c)

set(PBCLIB_SOURCE_FILES src/crypto/pbc_bls.c src/crypto/pbc_ibe.c)

if (USE_PBC)
    set(PBC_SOURCE_FILES ${PBCLIB_SOURCE_FILES})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lpbc")
else ()
    set(PBC_SOURCE_FILES ${BN256_SOURCE_FILES})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DQHASM")
    set(CMAKE_C_STANDARD_LIBRARIES ${CMAKE_SOURCE_DIR}/asfunctions.a)
endif ()


include_directories(${Alpenhorn_SOURCE_DIR}/include)
include_directories(${Alpenhorn_SOURCE_DIR}/lib)

set(SOURCE_FILES tests/test_bench_pkg_server.c include/alpenhorn/mixnet.h src/alpenhorn/mixnet.c include/alpenhorn/pkg.h src/alpenhorn/pkg.c include/alpenhorn/client.h src/alpenhorn/client.c
        src/alpenhorn/keywheel_table.c include/alpenhorn/keywheel_table.h src/alpenhorn/pkg.c src/alpenhorn/client.c src/alpenhorn/mixnet.c include/alpenhorn/mixnet.h src/crypto/pbc_bls.c
        lib/bn256/gmp_convert.c lib/bn256/gmp_convert.h src/crypto/pbc_ibe.c include/alpenhorn/pbc_ibe.h src/utils/bloom.c src/utils/prime_gen.c include/prime_gen.h include/alpenhorn/pbc_bls.h
        include/alpenhorn/pkg.h src/utils/utils.c include/utils.h include/alpenhorn/config.h include/bloom.h src/utils/net_common.c include/net_common.h src/crypto/bn256_ibe.c include/alpenhorn/pkg_config.h
        include/bn256_ibe.h include/bn256.h src/crypto/bn256_bls.c include/bn256_bls.h tests/test_bn256_ibe.c tests/test_bn256_bls.c
        src/crypto/bn256_keygen.c src/alpenhorn/client_example.c include/constants.h
        include/utest.h include/greatest.h tests/test_mix.c src/alpenhorn/mixnet_run.c src/alpenhorn/pkg_run.c tests/bench_mix_distribution.c tests/bench_mail_distribution_clientsim.c include/alpenhorn/pbc_cfg.h src/utils/user_generator.c tests/bench_mix.c tests/simulate_mix_round.c src/crypto/crypto_aes.c src/crypto/crypto_chacha.c include/crypto_chacha.h src/crypto/crypto.c include/crypto.h)

set(CLIENT_SOURCE_FILES ${PBC_SOURCE_FILES}
        include/alpenhorn/config.h src/alpenhorn/client.c src/utils/bloom.c src/utils/prime_gen.c src/alpenhorn/keywheel_table.c src/utils/net_common.c src/utils/utils.c lib/xxhash/xxhash.c include/alpenhorn/client_config.h)

set(MIX_SOURCE_FILES ${PBC_SOURCE_FILES} src/alpenhorn/mixnet.c src/utils/utils.c src/utils/prime_gen.c lib/xxhash/xxhash.c src/utils/bloom.c src/utils/net_common.c)
set(PKG_SOURCE_FILES ${PBC_SOURCE_FILES} src/alpenhorn/pkg.c src/utils/utils.c lib/xxhash/xxhash.c src/utils/net_common.c lib/thpool/thpool.c)
set(TEST_BN256_SOURCES ${BN256_SOURCE_FILES} tests/test_bn256_ibe.c include/greatest.h src/utils/utils.c)
set(TEST_PKG_SOURCE_FILES ${PKG_SOURCE_FILES} ${CLIENT_SOURCE_FILES} tests/test_bench_pkg_server.c include/greatest.h include/crypto_aes.h)
set(TEST_BLOOM_SOURCES src/utils/bloom.c src/utils/utils.c include/greatest.h tests/test_bloom.c lib/xxhash/xxhash.c src/utils/prime_gen.c)
set(TEST_MIX_SOURCES ${MIX_SOURCE_FILES} include/greatest.h tests/test_mix.c)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-rpath /usr/local/lib")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath /usr/local/lib")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -I /usr/local/include -L /usr/local/lib -lgmp -lsodium -lm -lcurl -pthread -Werror -lmpfr")

add_executable(client_example ${CLIENT_SOURCE_FILES} src/alpenhorn/client_example.c)
add_executable(mixnet_server ${MIX_SOURCE_FILES} src/alpenhorn/mixnet_run.c)
add_executable(pkg_server ${PKG_SOURCE_FILES} src/alpenhorn/pkg_run.c)
add_executable(dummy ${SOURCE_FILES} include/alpenhorn/mixnet_config.h)
#add_executable(client_test ${CLIENT_SOURCE_FILES} ${MIX_SOURCE_FILES} ${PKG_SOURCE_FILES} tests/test_client.c include/greatest.h)
add_executable(test_bn256_ibe ${TEST_BN256_SOURCES})
add_executable(test_bloom ${TEST_BLOOM_SOURCES})
add_executable(test_mix ${TEST_MIX_SOURCES})
add_executable(bench_pkg ${TEST_PKG_SOURCE_FILES})
add_executable(bench_mix_dist ${MIX_SOURCE_FILES} tests/bench_mix_distribution.c)
add_executable(bench_mix_clientsim src/utils/utils.c src/utils/net_common.c tests/bench_mail_distribution_clientsim.c)
add_executable(user_gen src/utils/user_generator.c)
add_executable(bench_mix_decrypt ${MIX_SOURCE_FILES} tests/bench_mix.c)
add_executable(simulate_mix ${MIX_SOURCE_FILES} tests/simulate_mix_round.c)
add_executable(test_client ${CLIENT_SOURCE_FILES} ${PKG_SOURCE_FILES} ${MIX_SOURCE_FILES} tests/test_client.c)
add_executable(crypto_test src/crypto/crypto_aes.c src/utils/utils.c)
