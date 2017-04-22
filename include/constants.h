#ifndef ALPENHORN_CONSTANTS_H
#define ALPENHORN_CONSTANTS_H

// Network protocol message types
#define CLIENT_AUTH_REQ 1U
#define CLIENT_DIAL_MSG 2U
#define CLIENT_AF_MSG 3U
#define CLIENT_DIAL_MB_REQUEST 4U
#define CLIENT_AF_MB_REQUEST 5U
#define CLIENT_REG_REQUEST 6U
#define CLIENT_REG_CONFIRM 7U
#define CLIENT_AUTH_REQUEST 19U
#define PKG_BR_MSG 8U
#define PKG_AUTH_RES_MSG 9U
#define MIX_AF_BATCH 10U
#define MIX_DIAL_BATCH 11U
#define NEW_DIAL_ROUND 12U
#define NEW_AF_ROUND 13U
#define DIAL_MB 14U
#define AF_MB 15U
#define MIX_SYNC 16U
#define NEW_DMB_AVAIL 17U
#define NEW_AFMB_AVAIL 18U
#define MIX_NEW_AF_KEY 20U
#define MIX_NEW_DIAL_KEY 21U

#define crypto_ghash_BYTES crypto_generichash_BYTES
#define crypto_pk_BYTES crypto_box_PUBLICKEYBYTES
#define crypto_maxhash_BYTES crypto_generichash_BYTES_MAX
#define crypto_MACBYTES crypto_aead_chacha20poly1305_ietf_ABYTES
#define crypto_NBYTES crypto_aead_chacha20poly1305_ietf_NPUBBYTES

#define net_msg_type_BYTES 4U
#define mix_num_buffer_elems 100000U
#define net_header_BYTES 24U






#endif //ALPENHORN_CONSTANTS_H
