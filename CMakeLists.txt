cmake_minimum_required(VERSION 3.6)
project(Alpenhorn)

set(CMAKE_C_STANDARD 99)
include_directories(${Alpenhorn_SOURCE_DIR}/include)
include_directories(${Alpenhorn_SOURCE_DIR}/lib)
file(GLOB OFILES lib/dclxci/*.o)

set(DCLXCI_SOURCE_FILES lib/dclxci/curvepoint_fp.c lib/dclxci/fp2e.c lib/dclxci/final_expo.c lib/dclxci/fp6e.c lib/dclxci/fp12e.c lib/dclxci/fpe.c
        lib/dclxci/twistpoint_fp2.c lib/dclxci/optate.c lib/dclxci/mydouble.c lib/dclxci/mul.c lib/dclxci/linefunction.c lib/dclxci/gmp_convert.c lib/dclxci/scalar.c lib/dclxci/curvepoint_fp_multiscalar.c
        lib/dclxci/twistpoint_fp2_multiscalar.c lib/dclxci/scalar_sub_nored.s lib/dclxci/asfunctions.a lib/dclxci/index_heap.c lib/dclxci/heap_rootreplaced.s
        ${OFILES})

set(SOURCE_FILES ${DCLXI_SOURCE_FILES} src/keywheel_table.c include/keywheel_table.h src/pkg.c src/client.c src/mix.c include/mix.h src/pbc_sign.c param_gen.c
        lib/dclxci/gmp_convert.c lib/dclxci/gmp_convert.h src/ibe.c src/ibe.h src/bloom.c src/prime_gen.c include/prime_gen.h include/pbc_sign.h include/pkg.h keygen.c src/alpenhorn_test.c
        src/utils.c include/utils.h include/config.h src/mixnet_server.c include/mixnet_server.h include/bloom.h src/client_net.c include/client_net.h src/pkg_net.c include/pkg_net.h src/net_common.c include/net_common.h
        )
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Werror -g")
set(CLIENT_SOURCE_FILES include/config.h src/client.c src/client_net.c src/bloom.c src/pbc_sign.c src/ibe.c src/prime_gen.c src/keywheel_table.c src/net_common.c src/utils.c lib/xxhash/xxhash.c)
set(MIX_SOURCE_FILES src/mixnet_server.c src/mix.c src/utils.c src/prime_gen.c lib/xxhash/xxhash.c src/bloom.c src/net_common.c)
set(PKG_SOURCE_FILES src/pkg.c src/pkg_net.c src/utils.c src/pbc_sign.c src/ibe.c lib/xxhash/xxhash.c src/net_common.c)
set(ALPENHORN_TEST_FILES src/alpenhorn_test.c src/client.c src/pkg.c src/bloom.c src/prime_gen.c src/mix.c src/utils.c lib/xxhash/xxhash.c src/keywheel_table.c src/pbc_sign.c src/ibe.c)
set(BLOOM_TEST_FILES src/bloom.c lib/xxhash/xxhash.c src/prime_gen.c tests/test_bloom.c src/client.c src/keywheel_table.c src/ibe.c src/pbc_sign.c src/utils.c tests/test_client.c)
set(TEST_PKG_FILES src/pkg.c src/utils.c src/pbc_sign.c src/ibe.c lib/xxhash/xxhash.c tests/test_bench_pkg_server.c)
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-rpath /usr/local/lib")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,-rpath /usr/local/lib")
set(CMAKE_C_FLAGS "-I /usr/local/include -L /usr/local/lib -lgmp -lsodium -lm -l pbc -pthread")
set(CMAKE_VERBOSE_MAKEFILE on)

add_executable(client_net ${CLIENT_SOURCE_FILES})
add_executable(mixnet_server ${MIX_SOURCE_FILES})
add_executable(pkg_server ${PKG_SOURCE_FILES})
add_executable(alpenhorn_test ${ALPENHORN_TEST_FILES})
add_executable(bloom_test ${BLOOM_TEST_FILES})
add_executable(test_bench_pkg_server ${TEST_PKG_FILES})
add_executable(dummy ${SOURCE_FILES})
add_executable(test_dxcvi ${DCLXCI_SOURCE_FILES} tests/test_bn256.c)
set_target_properties(dummy PROPERTIES EXCLUDE_FROM_ALL 1)
set_target_properties(test_dxcvi PROPERTIES COMPILE_FLAGS "-DQHASM")
