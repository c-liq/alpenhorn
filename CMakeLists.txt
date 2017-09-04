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
        src/bn256.c src/bn256_ibe.c src/bn256_bls.c)

set(PBCLIB_SOURCE_FILES src/pbc_bls.c src/pbc_ibe.c)

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

set(SOURCE_FILES tests/test_bench_pkg_server.c include/mixnet.h src/mixnet.c include/pkg.h src/pkg.c include/client.h src/client.c
        src/keywheel_table.c include/keywheel_table.h src/pkg.c src/client.c src/mixnet.c include/mixnet.h src/pbc_bls.c
        lib/bn256/gmp_convert.c lib/bn256/gmp_convert.h src/pbc_ibe.c include/pbc_ibe.h src/bloom.c src/prime_gen.c include/prime_gen.h include/pbc_bls.h
        include/pkg.h src/utils.c include/utils.h include/config.h include/bloom.h src/net_common.c include/net_common.h src/bn256_ibe.c include/pkg_config.h
        include/bn256_ibe.h include/bn256.h src/bn256_bls.c include/bn256_bls.h tests/test_bn256_ibe.c tests/test_bn256_bls.c
        src/bn256_keygen.c src/client_example.c include/constants.h
        include/utest.h include/greatest.h tests/test_mix.c src/mixnet_run.c src/pkg_run.c tests/bench_mix_distribution.c tests/bench_mail_distribution_clientsim.c include/pbc_cfg.h src/user_generator.c tests/bench_mix.c tests/simulate_mix_round.c)

set(CLIENT_SOURCE_FILES ${PBC_SOURCE_FILES}
        include/config.h src/client.c src/bloom.c src/prime_gen.c src/keywheel_table.c src/net_common.c src/utils.c lib/xxhash/xxhash.c include/client_config.h)

set(MIX_SOURCE_FILES ${PBC_SOURCE_FILES} src/mixnet.c src/utils.c src/prime_gen.c lib/xxhash/xxhash.c src/bloom.c src/net_common.c)
set(PKG_SOURCE_FILES ${PBC_SOURCE_FILES} src/pkg.c src/utils.c lib/xxhash/xxhash.c src/net_common.c lib/thpool/thpool.c)
set(TEST_BN256_SOURCES ${BN256_SOURCE_FILES} tests/test_bn256_ibe.c include/greatest.h src/utils.c)
set(TEST_PKG_SOURCE_FILES ${PKG_SOURCE_FILES} ${CLIENT_SOURCE_FILES} tests/test_bench_pkg_server.c include/greatest.h)
set(TEST_BLOOM_SOURCES src/bloom.c src/utils.c include/greatest.h tests/test_bloom.c lib/xxhash/xxhash.c src/prime_gen.c)
set(TEST_MIX_SOURCES ${MIX_SOURCE_FILES} include/greatest.h tests/test_mix.c)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-rpath /usr/local/lib")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath /usr/local/lib")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -I /usr/local/include -L /usr/local/lib -lgmp -lsodium -lm -lcurl -pthread -Werror -lmpfr")

add_executable(client_example ${CLIENT_SOURCE_FILES} src/client_example.c)
add_executable(mixnet_server ${MIX_SOURCE_FILES} src/mixnet_run.c)
add_executable(pkg_server ${PKG_SOURCE_FILES} src/pkg_run.c)
add_executable(dummy ${SOURCE_FILES} include/mixnet_config.h)
#add_executable(client_test ${CLIENT_SOURCE_FILES} ${MIX_SOURCE_FILES} ${PKG_SOURCE_FILES} tests/test_client.c include/greatest.h)
add_executable(test_bn256_ibe ${TEST_BN256_SOURCES})
add_executable(test_bloom ${TEST_BLOOM_SOURCES})
add_executable(test_mix ${TEST_MIX_SOURCES})
add_executable(bench_pkg ${TEST_PKG_SOURCE_FILES})
add_executable(bench_mix_dist ${MIX_SOURCE_FILES} tests/bench_mix_distribution.c)
add_executable(bench_mix_clientsim src/utils.c src/net_common.c tests/bench_mail_distribution_clientsim.c)
add_executable(user_gen src/user_generator.c)
add_executable(bench_mix_decrypt ${MIX_SOURCE_FILES} tests/bench_mix.c)
add_executable(simulate_mix ${MIX_SOURCE_FILES} tests/simulate_mix_round.c)
add_executable(test_client ${CLIENT_SOURCE_FILES} ${PKG_SOURCE_FILES} ${MIX_SOURCE_FILES} tests/test_client.c)
