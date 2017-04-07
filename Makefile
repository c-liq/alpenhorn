CPP=g++
CPPFLAGS=-g -Werror -DCHECK
CC=gcc
CFLAGS=-std=gnu99 -O3 -fomit-frame-pointer -g -I lib -I include/ -I /usr/local/include -L /usr/local/lib -lgmp -lsodium -l pbc -pthread -Wl,-rpath /usr/local/lib
LFLAGS=-lm

all: test_client test_ibe test_bls test_mix test_pkg

test_client: include/config.h src/client2.c src/client_net.c src/bloom.c src/prime_gen.c src/keywheel_table.c \
 			 src/net_common.c src/utils.c lib/xxhash/xxhash.c src/bn256_ibe.c src/bn256_bls.c src/bn256.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/scalar.c \
             lib/dclxci/twistpoint_fp2.c lib/dclxci/mul.c lib/dclxci/mydouble.c lib/dclxci/curvepoint_fp.c \
			 lib/dclxci/twistpoint_fp2_multiscalar.c lib/dclxci/heap_rootreplaced.s \
             lib/dclxci/index_heap.c lib/dclxci/scalar_sub_nored.s lib/dclxci/fp12e.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/fp6e.c \
             lib/dclxci/optate.c lib/dclxci/linefunction.c lib/dclxci/final_expo.c lib/dclxci/asfunctions.a lib/dclxci/gmp_convert.c
	$(CC) $(CFLAGS) $(LFLAGS) -DQHASM -o $@ $^




test_mix: include/config.h src/mix2.c src/mixnet_server.c src/bloom.c src/prime_gen.c \
 			 src/net_common.c src/utils.c lib/xxhash/xxhash.c src/bn256_ibe.c src/bn256_bls.c src/bn256.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/scalar.c \
             lib/dclxci/twistpoint_fp2.c lib/dclxci/mul.c lib/dclxci/mydouble.c lib/dclxci/curvepoint_fp.c \
			 lib/dclxci/twistpoint_fp2_multiscalar.c lib/dclxci/heap_rootreplaced.s \
             lib/dclxci/index_heap.c lib/dclxci/scalar_sub_nored.s lib/dclxci/fp12e.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/fp6e.c \
             lib/dclxci/optate.c lib/dclxci/linefunction.c lib/dclxci/final_expo.c lib/dclxci/asfunctions.a lib/dclxci/gmp_convert.c
	$(CC) $(CFLAGS) $(LFLAGS) -DQHASM -o $@ $^

test_pkg: include/config.h src/pkg2.c src/pkg_net.c src/bloom.c src/prime_gen.c \
 			 src/net_common.c src/utils.c lib/xxhash/xxhash.c src/bn256_ibe.c src/bn256_bls.c src/bn256.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/scalar.c \
             lib/dclxci/twistpoint_fp2.c lib/dclxci/mul.c lib/dclxci/mydouble.c lib/dclxci/curvepoint_fp.c \
			 lib/dclxci/twistpoint_fp2_multiscalar.c lib/dclxci/heap_rootreplaced.s \
             lib/dclxci/index_heap.c lib/dclxci/scalar_sub_nored.s lib/dclxci/fp12e.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/fp6e.c \
             lib/dclxci/optate.c lib/dclxci/linefunction.c lib/dclxci/final_expo.c lib/dclxci/asfunctions.a lib/dclxci/gmp_convert.c
	$(CC) $(CFLAGS) $(LFLAGS) -DQHASM -o $@ $^

test_justpkg: include/config.h src/pkg2.c tests/test_bench_pkg_server.c src/bloom.c src/prime_gen.c \
 			 src/net_common.c src/utils.c lib/xxhash/xxhash.c src/bn256_ibe.c src/bn256_bls.c src/bn256.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/scalar.c \
             lib/dclxci/twistpoint_fp2.c lib/dclxci/mul.c lib/dclxci/mydouble.c lib/dclxci/curvepoint_fp.c \
			 lib/dclxci/twistpoint_fp2_multiscalar.c lib/dclxci/heap_rootreplaced.s \
             lib/dclxci/index_heap.c lib/dclxci/scalar_sub_nored.s lib/dclxci/fp12e.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/fp6e.c \
             lib/dclxci/optate.c lib/dclxci/linefunction.c lib/dclxci/final_expo.c lib/dclxci/asfunctions.a lib/dclxci/gmp_convert.c
	$(CC) $(CFLAGS) $(LFLAGS) -DQHASM -o $@ $^


test_ibe: include/config.h src/pkg2.c src/bloom.c src/prime_gen.c src/keywheel_table.c \
           			 src/net_common.c src/utils.c lib/xxhash/xxhash.c src/bn256_ibe.c src/bn256_bls.c src/bn256.c \
			tests/test_bn256_ibe.c src/client2.c src/pkg2.c src/mix2.c src/utils.c include/config.h src/bn256_ibe.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/scalar.c \
             lib/dclxci/twistpoint_fp2.c lib/dclxci/mul.c lib/dclxci/mydouble.c lib/dclxci/curvepoint_fp.c \
			 lib/dclxci/twistpoint_fp2_multiscalar.c lib/dclxci/heap_rootreplaced.s \
             lib/dclxci/index_heap.c lib/dclxci/scalar_sub_nored.s lib/dclxci/fp12e.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/fp6e.c \
             lib/dclxci/optate.c lib/dclxci/linefunction.c lib/dclxci/final_expo.c lib/dclxci/asfunctions.a lib/dclxci/gmp_convert.c
	$(CC) $(CFLAGS) $(LFLAGS) -DQHASM -o $@ $^

test_bls: tests/test_bn256_bls.c src/utils.c include/config.h src/bn256_bls.c src/bn256.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/scalar.c \
             lib/dclxci/twistpoint_fp2.c lib/dclxci/mul.c lib/dclxci/mydouble.c lib/dclxci/curvepoint_fp.c \
			 lib/dclxci/twistpoint_fp2_multiscalar.c lib/dclxci/heap_rootreplaced.s \
             lib/dclxci/index_heap.c lib/dclxci/scalar_sub_nored.s lib/dclxci/fp12e.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/fp6e.c \
             lib/dclxci/optate.c lib/dclxci/linefunction.c lib/dclxci/final_expo.c lib/dclxci/asfunctions.a lib/dclxci/gmp_convert.c
	$(CC) $(CFLAGS) $(LFLAGS) -DQHASM -o $@ $^

keygen: src/bn256_keygen.c src/utils.c include/config.h src/bn256_bls.c src/bn256.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/scalar.c \
             lib/dclxci/twistpoint_fp2.c lib/dclxci/mul.c lib/dclxci/mydouble.c lib/dclxci/curvepoint_fp.c \
			 lib/dclxci/twistpoint_fp2_multiscalar.c lib/dclxci/heap_rootreplaced.s \
             lib/dclxci/index_heap.c lib/dclxci/scalar_sub_nored.s lib/dclxci/fp12e.c lib/dclxci/fpe.c lib/dclxci/fp2e.c lib/dclxci/fp6e.c \
             lib/dclxci/optate.c lib/dclxci/linefunction.c lib/dclxci/final_expo.c lib/dclxci/asfunctions.a lib/dclxci/gmp_convert.c
	$(CC) $(CFLAGS) $(LFLAGS) -DQHASM -o $@ $^



asfunctions.a: lib/dclxci/fp2e_add2.o lib/dclxci/fp2e_sub2.o \
	lib/dclxci/fp2e_double2.o lib/dclxci/fp2e_triple2.o lib/dclxci/fp2e_neg2.o \
	lib/dclxci/fp2e_mul.o lib/dclxci/fp2e_mul_fpe.o lib/dclxci/fp2e_short_coeffred.o \
	lib/dclxci/fp2e_add.o lib/dclxci/fp2e_sub.o lib/dclxci/fp2e_parallel_coeffmul.o lib/dclxci/fp2e_mulxi.o\
	lib/dclxci/fp2e_double.o lib/dclxci/fp2e_triple.o lib/dclxci/fp2e_neg.o lib/dclxci/fp2e_conjugate.o \
	lib/dclxci/fpe_mul.o lib/dclxci/fp2e_square.o \
	lib/dclxci/consts.o
	rm -f asfunctions.a
	ar cr asfunctions.a $^

clean:
	-rm client
	-rm test_bn256
	-rm test_bn256_check
