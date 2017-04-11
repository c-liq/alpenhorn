cmake_minimum_required(VERSION 3.6)
project(Alpenhorn)

set(CMAKE_C_STANDARD 99)
include_directories(${Alpenhorn_SOURCE_DIR}/include)
include_directories(${Alpenhorn_SOURCE_DIR}/lib)
file(GLOB OFILES lib/bn256/*.o)

set(SOURCE_FILES tests/test_bench_pkg_server.c include/mix.h src/mix.c include/pkg.h src/pkg.c include/client.h src/client.c
        src/keywheel_table.c include/keywheel_table.h src/pkg.c src/client.c src/mix.c include/mix.h src/pbc_sign.c
        lib/bn256/gmp_convert.c lib/bn256/gmp_convert.h src/ibe.c include/ibe.h src/bloom.c src/prime_gen.c include/prime_gen.h include/pbc_sign.h
        include/pkg.h src/utils.c include/utils.h include/config.h src/mixnet_server.c include/mixnet_server.h include/bloom.h
        src/pkg_net.c include/pkg_net.h src/net_common.c include/net_common.h src/bn256_ibe.c
        include/bn256_ibe.h include/bn256.h src/bn256_bls.c include/bn256_bls.h tests/test_bn256_ibe.c tests/test_bn256_bls.c src/bn256_keygen.c src/client_example.c tests/test.c tests/test_utils.c tests/test_utils.h)

set(BN256_SOURCE_FILES ${OFILES} lib/bn256/fpe.c lib/bn256/fp2e.c lib/bn256/scalar.c lib/bn256/parameters.c
        lib/bn256/twistpoint_fp2.c lib/bn256/mul.c lib/bn256/mydouble.c lib/bn256/curvepoint_fp.c
        lib/bn256/heap_rootreplaced.s
        lib/bn256/index_heap.c lib/bn256/scalar_sub_nored.s lib/bn256/fp12e.c lib/bn256/fpe.c lib/bn256/fp2e.c lib/bn256/fp6e.c
        lib/bn256/optate.c lib/bn256/linefunction.c lib/bn256/final_expo.c lib/bn256/asfunctions.a lib/bn256/gmp_convert.c)


set(CLIENT_SOURCE_FILES ${BN256_SOURCE_FILES} src/bn256.c src/bn256_ibe.c src/bn256_bls.c
        include/config.h src/client.c src/bloom.c src/prime_gen.c src/keywheel_table.c src/net_common.c src/utils.c lib/xxhash/xxhash.c include/client_config.h)

set(MIX_SOURCE_FILES ${BN256_SOURCE_FILES} src/bn256.c src/mixnet_server.c src/mix.c src/utils.c src/prime_gen.c lib/xxhash/xxhash.c src/bloom.c src/net_common.c)
set(PKG_SOURCE_FILES ${BN256_SOURCE_FILES} src/bn256.c src/bn256_ibe.c src/bn256_bls.c src/pkg.c src/pkg_net.c src/utils.c src/pbc_sign.c src/ibe.c lib/xxhash/xxhash.c src/net_common.c)


set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-rpath /usr/local/lib")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,-rpath /usr/local/lib")
set(CMAKE_C_FLAGS "-I /usr/local/include -L /usr/local/lib -lgmp -lsodium -lm -lcurl -l pbc -pthread -Wall -DQHASM")
set(CMAKE_VERBOSE_MAKEFILE on)


add_executable(client ${CLIENT_SOURCE_FILES})
add_executable(client_example ${CLIENT_SOURCE_FILES} src/client_example.c)
add_executable(mixnet_server ${MIX_SOURCE_FILES})
add_executable(pkg_server ${PKG_SOURCE_FILES})
add_executable(dummy ${SOURCE_FILES})
add_executable(client_test ${CLIENT_SOURCE_FILES} tests/test_client.c src/mix.c)

