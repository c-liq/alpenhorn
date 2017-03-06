cmake_minimum_required(VERSION 3.6)
project(Alpenhorn)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES src/keywheel_table.c src/keywheel_table.h src/pkg.c src/client.c src/mix.c src/mix.h src/pbc_sign.c param_gen.c
        src/ibe.c src/ibe.h src/bloom.c src/prime_gen.c src/prime_gen.h src/pbc_sign.h src/pkg.h keygen.c tests/alpenhorn_test.c
        src/utils.c src/utils.h src/config.h src/mixnet_server.c src/mixnet_server.h src/bloom.h src/client_net.c src/client_net.h src/pkg_net.c src/pkg_net.h src/net_common.c src/net_common.h)

set(CLIENT_SOURCE_FILES src/client.c src/client_net.c src/bloom.c src/pbc_sign.c src/ibe.c src/prime_gen.c src/keywheel_table.c src/net_common.c src/utils.c lib/xxhash/xxhash.c)
set(MIX_SOURCE_FILES src/mixnet_server.c src/mix.c src/utils.c src/prime_gen.c lib/xxhash/xxhash.c src/bloom.c src/net_common.c)
set(PKG_SOURCE_FILES src/pkg.c src/pkg_net.c src/utils.c src/pbc_sign.c src/ibe.c lib/xxhash/xxhash.c src/net_common.c)

set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-rpath /usr/local/lib")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,-rpath /usr/local/lib")
set(CMAKE_C_FLAGS "-I /usr/local/include -L /usr/local/lib -lgmp -lsodium -lm -l pbc")
set(CMAKE_VERBOSE_MAKEFILE on)

add_executable(client_net ${CLIENT_SOURCE_FILES})
add_executable(mixnet_server ${MIX_SOURCE_FILES})
add_executable(pkg_server ${PKG_SOURCE_FILES})