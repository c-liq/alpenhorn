#ifndef ALPENHORN_CONFIG_H
#define ALPENHORN_CONFIG_H

#include <memory.h>
#include <sodium.h>
#include <stdbool.h>
#include <sys/types.h>
#include "constants.h"
#include "crypto.h"
#include "crypto_salsa.h"
#include "byte_buffer.h"

typedef uint64_t u64;
typedef uint8_t u8;



// Server parameters
#ifdef USE_PBC
#define USE_PBC 1
#else
#define USE_PBC 0
#endif

#define LOG 1
#define num_pkg_servers 1U
#define num_mix_servers 2U
#define num_INTENTS 5
#define mix_num_dial_mbs_stored 5
#define read_buf_SIZE 512
#define write_buf_SIZE 1024

#if USE_PBC
#include <pbc/pbc.h>
#define g1_serialized_bytes 33U
#define g2_serialized_bytes 65U
#else
#include "bn256.h"
#define g1_serialized_bytes 64U
#define g2_serialized_bytes 128U
#define g1_xonly_serialized_bytes 32U
#define bn256_bls_sig_message_bytes g1_xonly_serialized_bytes
#define bn256_ibe_pkg_pk_bytes g1_serialized_bytes
#define bn256_ibe_client_sk_bytes g2_serialized_bytes

#endif

#define user_id_BYTES 60U
#define intent_BYTES sizeof(uint64_t)
#define mb_BYTES sizeof(uint64_t)
#define round_BYTES sizeof(uint64_t)
#define dialling_token_BYTES 32U


#define af_request_BYTES                                            \
  (user_id_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES + \
   bn256_bls_sig_message_bytes + crypto_box_PUBLICKEYBYTES + round_BYTES)
#define af_ibeenc_request_BYTES \
  (af_request_BYTES + g1_serialized_bytes + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES)
#define onion_layer_BYTES (crypto_secretbox_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_secretbox_MACBYTES)
#define onionenc_friend_request_BYTES \
  (mb_BYTES + af_ibeenc_request_BYTES + (num_mix_servers * onion_layer_BYTES))
#define onionenc_dial_token_BYTES \
  (mb_BYTES + dialling_token_BYTES + (num_mix_servers * onion_layer_BYTES))
#define cli_pkg_single_auth_req_BYTES \
  (round_BYTES + user_id_BYTES + crypto_sign_BYTES + crypto_pk_BYTES)
#define cli_pkg_reg_request_BYTES (user_id_BYTES + crypto_sign_PUBLICKEYBYTES)
#define cli_pkg_reg_confirm_BYTES (user_id_BYTES + crypto_sign_BYTES)
#define pkg_auth_res_BYTES (bn256_bls_sig_message_bytes + bn256_ibe_client_sk_bytes)
#define pkg_enc_auth_res_BYTES \
  (pkg_auth_res_BYTES + crypto_MACBYTES + crypto_NBYTES)
#define pkg_broadcast_msg_BYTES (bn256_ibe_pkg_pk_bytes + crypto_pk_BYTES)
#define pkg_sig_message_BYTES (user_id_BYTES + crypto_sign_PUBLICKEYBYTES + round_BYTES)

#if LOG
#define LOG_OUT(file, format, ...) fprintf(file, format, __VA_ARGS__); fflush(file);

#endif

static const uint8_t user_ids[10][user_id_BYTES] = {
	"chris", "alice", "bob", "eve", "charlie",
	"jim", "megan", "john", "jill", "steve"};

static const uint8_t user_publickeys[10][64] = {
	"dce2ce56f88900d2fc09128fd308954ece30fbda56b1202fd21ece8cb8e231bf",
	"a11a8d3b6325efa5b6b5372f1a54783bf5b9b0816e7aad6c848bd4936b19a493",
	"deb27d637dbb5e82234439dc6410dcff2720412affe09d69adaafeb775ca6eb1",
	"cbf9aa2432aa0b7ed86fd4cee2e54f998b4019e0e1d2194d207553082bd3dd5e",
	"2ddb31f8c4cf162218eb5b897c33c0002de8b7fc3fd6edb8be9d0c4b2a4f385a",
	"2c13f995d0c403014e58309c5b24cdd13fb90b68e1f60f187e3ecebf936b78b0",
	"f9f8f4330c77763cb472d560da5765093b8b50645a4345de646c99d69387d442",
	"27fc5fab0c93af7f4cd5e09aae95080609720ecac24b8f93e517015dded669e0",
	"031ca754e5896d5e84eb21866439e1b631225193619734f364de90f228485f94",
	"b1fcd02a40da1e342f2c8404c7438e24d673666fe8160e5d23c7278244abc085"};

static const uint8_t user_lt_secret_sig_keys[10][128] = {
	"6581ce40d6971c2fd1d2ca07fe5280be823a327bca5bb8d3d110ec906247493cdce2ce56f8"
		"8900d2fc09128fd308954ece30fbda56b1202fd21ece8cb8e231bf",
	"112425a435b38a6867722004400e228157a3b7722925c90db891ed31fd018ab9a11a8d3b63"
		"25efa5b6b5372f1a54783bf5b9b0816e7aad6c848bd4936b19a493",
	"458d01cfc4f208aebe02a07f84214be38d0a6a858c80af5a8d04b76241907d06deb27d637d"
		"bb5e82234439dc6410dcff2720412affe09d69adaafeb775ca6eb1",
	"7d6fe8126eb4fb33768d6df90101bc2f9a267339fd1161f9056fcb2fea920a28cbf9aa2432"
		"aa0b7ed86fd4cee2e54f998b4019e0e1d2194d207553082bd3dd5e",
	"07c02ccbd210d5b52a55a4227d18e02aec4d23b1ac7a5606a9161b7c370753472ddb31f8c4"
		"cf162218eb5b897c33c0002de8b7fc3fd6edb8be9d0c4b2a4f385a",
	"cad06e122e4600f617a65c5a67294c3a93d96c68c129ff7a382beb484f77a5992c13f995d0"
		"c403014e58309c5b24cdd13fb90b68e1f60f187e3ecebf936b78b0",
	"2563472f38a1b997b411d7584efc6937a5a07fc638f600004a9238f7293d6850f9f8f4330c"
		"77763cb472d560da5765093b8b50645a4345de646c99d69387d442",
	"ec3077ddf1f65b34354e40d00de35dd50b7c95a846fd5f9bc4e965bec22facea27fc5fab0c"
		"93af7f4cd5e09aae95080609720ecac24b8f93e517015dded669e0",
	"48d5f089e848d75a5e8badee289b6be5895d15b0f8c418a8d6d4da7781fa05a7031ca754e5"
		"896d5e84eb21866439e1b631225193619734f364de90f228485f94",
	"a4b9ca4f8bf7679b297c6e6a230733868ac525b15c690ba008d742b001385d93b1fcd02a40"
		"da1e342f2c8404c7438e24d673666fe8160e5d23c7278244abc085"};

#endif  // ALPENHORN_CONFIG_H
