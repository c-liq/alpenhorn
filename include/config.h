#ifndef ALPENHORN_CONFIG_H
#define ALPENHORN_CONFIG_H

#define USE_PBC 0
#include <sodium.h>
#include <sys/types.h>

#if USE_PBC
#include <pbc/pbc.h>
#define g1_serialized_bytes 33U
#define g2_serialized_bytes 65U
#else
#include "bn256.h"
#define g1_serialized_bytes 64U
#define g2_serialized_bytes 128U
#endif

#define CLI_AUTH_REQ 50
#define CLIENT_DIAL_MSG 27
#define CLIENT_AF_MSG 28
#define CLIENT_DIAL_MB_REQUEST 152
#define CLIENT_AF_MB_REQUEST 153
#define CLIENT_REG_REQUEST 666
#define CLIENT_REG_CONFIRM 786
#define PKG_BR_MSG 70
#define PKG_AUTH_RES_MSG 80

#define crypto_ghash_BYTES crypto_generichash_BYTES
#define crypto_maxhash_BYTES crypto_generichash_BYTES_MAX
#define crypto_MACBYTES crypto_aead_chacha20poly1305_ietf_ABYTES
#define crypto_NBYTES crypto_aead_chacha20poly1305_ietf_NPUBBYTES
// PBC constants


#define intent_BYTES 4U
#define mb_BYTES 4U
#define round_BYTES 8U
#define dialling_token_BYTES 32U
#define num_pkg_servers 2U
#define num_mix_servers 2U
#define num_INTENTS 5
#define user_id_BYTES 60U
#define net_msg_type_BYTES 4U

#define net_header_BYTES 24U
#define net_client_connect_BYTES (num_mix_servers * crypto_box_PUBLICKEYBYTES)

#define af_request_BYTES (user_id_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES + g1_serialized_bytes + crypto_box_PUBLICKEYBYTES + round_BYTES)
#define af_ibeenc_request_BYTES (af_request_BYTES + g1_serialized_bytes + crypto_MACBYTES + crypto_NBYTES)
#define onion_layer_BYTES (crypto_NBYTES + crypto_box_PUBLICKEYBYTES + crypto_MACBYTES)
#define onionenc_friend_request_BYTES (mb_BYTES + af_ibeenc_request_BYTES + (num_mix_servers * onion_layer_BYTES))
#define onionenc_dial_token_BYTES (mb_BYTES + dialling_token_BYTES + (num_mix_servers * onion_layer_BYTES))
#define cli_pkg_single_auth_req_BYTES (round_BYTES + user_id_BYTES + crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES)
#define cli_pkg_reg_request_BYTES (user_id_BYTES + crypto_sign_PUBLICKEYBYTES)
#define cli_pkg_reg_confirm_BYTES (user_id_BYTES + crypto_sign_BYTES)
#define pkg_auth_res_BYTES (g1_serialized_bytes + g2_serialized_bytes)
#define pkg_enc_auth_res_BYTES (pkg_auth_res_BYTES + crypto_MACBYTES + crypto_NBYTES)
#define pkg_broadcast_msg_BYTES (g1_serialized_bytes + crypto_box_PUBLICKEYBYTES)
#define pkg_sig_message_BYTES (user_id_BYTES + crypto_box_PUBLICKEYBYTES + round_BYTES)

#define mix_num_dial_mbs_stored 5

#define start_timer(x) double x = get_time()
#define end_timer_print(x, msg) double x_end = get_time(); printf("Time elapsed for %s: %f\n", msg, x_end - x)

#define mix_num_buffer_elems 100000U

#define AF_BATCH 1U
#define DIAL_BATCH 9U
#define NEW_DIAL_ROUND 3U
#define NEW_AF_ROUND 4U
#define DIAL_MB 40
#define AF_MB 41
#define MIX_SYNC 1337
#define NEW_DMB_AVAIL 188
#define NEW_AFMB_AVAIL 189



static const uint8_t
	user_ids[10][user_id_BYTES] = {"chris", "alice", "bob", "eve", "charlie", "jim", "megan", "john", "jill", "steve"};

static const uint8_t user_publickeys[10][64] = {"dce2ce56f88900d2fc09128fd308954ece30fbda56b1202fd21ece8cb8e231bf",
                                                "a11a8d3b6325efa5b6b5372f1a54783bf5b9b0816e7aad6c848bd4936b19a493",
                                                "deb27d637dbb5e82234439dc6410dcff2720412affe09d69adaafeb775ca6eb1",
                                                "cbf9aa2432aa0b7ed86fd4cee2e54f998b4019e0e1d2194d207553082bd3dd5e",
                                                "2ddb31f8c4cf162218eb5b897c33c0002de8b7fc3fd6edb8be9d0c4b2a4f385a",
                                                "2c13f995d0c403014e58309c5b24cdd13fb90b68e1f60f187e3ecebf936b78b0",
                                                "f9f8f4330c77763cb472d560da5765093b8b50645a4345de646c99d69387d442",
                                                "27fc5fab0c93af7f4cd5e09aae95080609720ecac24b8f93e517015dded669e0",
                                                "031ca754e5896d5e84eb21866439e1b631225193619734f364de90f228485f94",
                                                "b1fcd02a40da1e342f2c8404c7438e24d673666fe8160e5d23c7278244abc085"};

static const uint8_t user_lt_secret_sig_keys[10][128] =
	{"6581ce40d6971c2fd1d2ca07fe5280be823a327bca5bb8d3d110ec906247493cdce2ce56f88900d2fc09128fd308954ece30fbda56b1202fd21ece8cb8e231bf",
	 "112425a435b38a6867722004400e228157a3b7722925c90db891ed31fd018ab9a11a8d3b6325efa5b6b5372f1a54783bf5b9b0816e7aad6c848bd4936b19a493",
	 "458d01cfc4f208aebe02a07f84214be38d0a6a858c80af5a8d04b76241907d06deb27d637dbb5e82234439dc6410dcff2720412affe09d69adaafeb775ca6eb1",
	 "7d6fe8126eb4fb33768d6df90101bc2f9a267339fd1161f9056fcb2fea920a28cbf9aa2432aa0b7ed86fd4cee2e54f998b4019e0e1d2194d207553082bd3dd5e",
	 "07c02ccbd210d5b52a55a4227d18e02aec4d23b1ac7a5606a9161b7c370753472ddb31f8c4cf162218eb5b897c33c0002de8b7fc3fd6edb8be9d0c4b2a4f385a",
	 "cad06e122e4600f617a65c5a67294c3a93d96c68c129ff7a382beb484f77a5992c13f995d0c403014e58309c5b24cdd13fb90b68e1f60f187e3ecebf936b78b0",
	 "2563472f38a1b997b411d7584efc6937a5a07fc638f600004a9238f7293d6850f9f8f4330c77763cb472d560da5765093b8b50645a4345de646c99d69387d442",
	 "ec3077ddf1f65b34354e40d00de35dd50b7c95a846fd5f9bc4e965bec22facea27fc5fab0c93af7f4cd5e09aae95080609720ecac24b8f93e517015dded669e0",
	 "48d5f089e848d75a5e8badee289b6be5895d15b0f8c418a8d6d4da7781fa05a7031ca754e5896d5e84eb21866439e1b631225193619734f364de90f228485f94",
	 "a4b9ca4f8bf7679b297c6e6a230733868ac525b15c690ba008d742b001385d93b1fcd02a40da1e342f2c8404c7438e24d673666fe8160e5d23c7278244abc085"};


#endif //ALPENHORN_CONFIG_H
