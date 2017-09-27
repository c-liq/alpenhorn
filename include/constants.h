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
#define PKG_BR_MSG 8U
#define PKG_AUTH_RES_MSG 9U
#define PKG_CONFIRM_CLIENT_REG 25U
#define MIX_AF_BATCH 10U
#define MIX_DIAL_BATCH 11U
#define NEW_DIAL_ROUND 12U
#define NEW_AF_ROUND 13U
#define DIAL_MB 14U
#define AF_MB 15U
#define MIX_SYNC 16U
#define NEW_DMB_AVAIL 17U
#define NEW_AFMB_AVAIL 18U
#define PKG_REG_REQUEST_RECEIVED 66U
#define AF_START_GEN_KEYS 99U
#define MIX_AF_SETTINGS 31UL
#define MIX_DIAL_SETTINGS 32LU

#define net_msg_type_BYTES 8U
#define net_msg_len_BYTES 8U
#define mix_num_buffer_elems 1000000U
#define header_BYTES 32U






#endif //ALPENHORN_CONSTANTS_H
