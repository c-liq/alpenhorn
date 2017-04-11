#ifndef ALPENHORN_PKG_H
#define ALPENHORN_PKG_H

#include "config.h"
#include "utils.h"
#if USE_PBC
#include "ibe.h"
#include "pbc_sign.h"
#else
#include "bn256_ibe.h"
#include "bn256_bls.h"
#endif
struct pkg_server;
struct pkg_client;

typedef struct pkg_pending_client pkg_pending_client;
struct pkg_pending_client
{
	uint8_t user_id[user_id_BYTES];
	uint8_t sig_key[crypto_sign_PUBLICKEYBYTES];
	char confirmation_key[crypto_ghash_BYTES * 2 + 1];
	time_t timeout;
	pkg_pending_client *next;
	pkg_pending_client *prev;
};

typedef struct pkg_server pkg_server;

typedef struct pkg_client pkg_client;
struct pkg_server
{
	int srv_id;
	uint32_t num_clients;
	uint32_t client_buf_capacity;
	uint64_t current_round;
	pkg_client *clients;
	// Long term BLS signatures, used to sign messages aiding verifying friend requests by recipients
	// Epheremal IBE keypair - public key_state is broadcast to clients, secret key_state used to extract clients' secret keys
	uint8_t eph_secret_dh_key[crypto_box_SECRETKEYBYTES];
	// Broadcast message buffer - contains fresh IBE public key_state + fresh DH key_state + signature
	uint8_t eph_broadcast_message[net_header_BYTES + pkg_broadcast_msg_BYTES];
	uint8_t *broadcast_dh_pkey_ptr;  // Pointer into message buffer where public dh key_state will be stored
	#if USE_PBC
	pairing_t pairing;
	element_t lt_sig_pk_elem;
	element_t lt_sig_sk_elem;
	element_t eph_pub_key_elem_g1;
	element_t eph_secret_key_elem_zr;
	element_s bls_gen_elem_g2;
	element_s ibe_gen_elem_g1;
	#else
	bn256_bls_keypair lt_keypair;
	curvepoint_fp_t eph_pub_key_elem_g1;
	scalar_t eph_secret_key_elem_zr;
	#endif
	uint32_t num_threads;
	pkg_pending_client *pending_registration_requests;
};

struct pkg_client
{
	uint8_t user_id[user_id_BYTES];
	uint8_t lt_sig_pk[crypto_sign_PUBLICKEYBYTES];
	uint8_t auth_msg_from_client[crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES];
	uint8_t eph_symmetric_key[crypto_generichash_BYTES];
	uint8_t rnd_sig_msg[pkg_sig_message_BYTES];
	uint8_t eph_client_data[net_header_BYTES + pkg_enc_auth_res_BYTES];
	uint8_t *auth_response_ibe_key_ptr; // Pointer into response buffer where secret key_state will be placed
	#if USE_PBC
	element_t hashed_id_elem_g2; // Permanent
	element_t eph_sig_elem_G1;
	element_t eph_sig_hash_elem_g1;// Round-specific sig_lts of (user_id, lts-sig-key_state, round number)
	element_t eph_sk_G2; // Round-specific IBE secret key_state for client_s
	#else
	twistpoint_fp2_t hashed_id_elem_g2; // Permanent
	curvepoint_fp_t eph_sig_elem_G1;
	curvepoint_fp_t eph_sig_hash_elem_g1;// Round-specific sig_lts of (user_id, lts-sig-key_state, round number)
	twistpoint_fp2_t eph_sk_G2; // Round-specific IBE secret key_state for client_s
	#endif
};

void pkg_client_init(pkg_client *client, const uint8_t *user_id, const uint8_t *lt_sig_key);
void pkg_new_ibe_keypair(pkg_server *server);
int pkg_server_init(pkg_server *server, uint32_t id, uint32_t num_clients, uint32_t num_threads);
void pkg_new_ibe_keypair(pkg_server *server);
void pkg_extract_client_sk(pkg_server *server, pkg_client *client);
void pkg_sign_for_client(pkg_server *server, pkg_client *client);
void pkg_encrypt_client_response(pkg_server *server, pkg_client *client);
void pkg_client_free(pkg_client *client);
void pkg_new_round(pkg_server *server);
int pkg_auth_client(pkg_server *server, pkg_client *client);
void pkg_encrypt_client_response(pkg_server *server, pkg_client *client);
int pkg_client_lookup(pkg_server *server, uint8_t *user_id);
int pkg_parallel_extract(pkg_server *server);
int pkg_registration_request(pkg_server *server, const char *user_id, uint8_t *sig_key);
int pkg_confirm_registration(pkg_server *server, uint8_t *user_id, uint8_t *sig);

static const char *pkg_cl_listen_ports[] = {"7500", "7501", "7502"};

#if USE_PBC
static const char pbc_params[] = "type f\n"
	"q 16283262548997601220198008118239886027035269286659395419233331082106632227801\n"
	"r 16283262548997601220198008118239886026907663399064043451383740756301306087801\n"
	"b 5609134383314096343821706060255766178230076423505829753232013255731730969768\n"
	"beta 14585451571835279174057707111090228078498559752534690688696725860687037093655\n"
	"alpha0 7384246685346944302521498672963794600906063696465161604937782621154370513339\n"
	"alpha1 4048507381538522394091069408895150360561946621565222584287381102665313783955\n";

static const char *sk[3] = {"10778343094975392135581974247340460372164289692929233030125470550571339685912",
							"9688549132935229128161053765094784437559599536117169899827480125341223824030",
							"14754489302236821884533158176717016782900034847354657195783194213647848389200"};

static const char *pk[3] =
	{"[[6086379828989660989028314078811395552519168740126492884410228417657741197505, 8144852052844972129099269274667998534513045130276301011761818051955232294764],"
		 " [12905311036091495766560354314955717180785052939814771374732216405908083158588, 12206468764955976902377549492754113261152529825339665500250747177941759322877]]",
	 "[[8160164483073707263225494293658012847814401105023844402795912842754138236016, 3507539360481855979953507669121673921828426608186041809832896241678538524487], "
		 "[2935004434206231188893390984062827282093819072637730926703958281099939979728, 1429257052468430779387305210231691157810800546837261775958933730699263478158]]",
	 "[[13390979854465689884004374630321832512410728995089304572891318452815493144503, 11615922255584207485349740186764476249491844309988473417920830909660991527655],"
		 " [11775135681555340005729773445724583755638324261572440444821270512920972679189, 21057092324234584843398020514715179172990825209983929208054184231184362858]]"};

static const char bls_generator[] = "[[15724257330924097062160683695880250933232554430187007470915263732860196404841,"
	" 11675890099551911688180980551831034403007152045230694854797640069104655082534], "
	"[13349283408131010710625633177944918626847137179157740569651489234485272434916,"
	" 14614450416672873406836739706484919090526432906183872742307134718470620099277]]";

static const char ibe_generator[] =
	"[13445309910996477276498115007761070335613715482521447244233072900478772718670, 1756633159976726073430018948123414634726480138612936748031091597585345575016]";

#else
static scalar_t pkg_lt_sks[2] =
	{{18278220357555044870ULL, 10178222900370061244ULL, 11444934429233922452ULL, 824085380572658870ULL},
	 {979939089226258815ULL, 3053653148008306585ULL, 2835228076264966692ULL, 5843250564837170266ULL}};

static twistpoint_fp2_t pkg_lt_pks[2] =
	{{{{{{2982039.000000, -125313.000000, 477854.000000, -378582.000000, 590425.000000, 393584.000000, -2153536.000000,
	      -41024.000000, 59630.000000, 45653.000000, -503286.000000, 406703.000000, 138945.000000, 224185.000000,
	      -181334.000000,
	      -390185.000000, -766688.000000, -421218.000000, 3399884.000000, -129290.000000, 220754.000000, 4658.000000,
	      -405676.000000, 47059.000000}}},
	   {{{2554957.000000, 867376.000000, 262494.000000, 147607.000000, -215232.000000, -192289.000000, 4201036.000000,
	      696129.000000, -649118.000000,
	      706251.000000, 524022.000000, -328583.000000, 2239101.000000, -425845.000000, 898815.000000, 841996.000000,
	      -199275.000000, 728293.000000,
	      -919133.000000, 120308.000000, 576615.000000, -361530.000000, -258671.000000, -329332.000000}}},
	   {{{1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.}}},
	   {{{0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.}}}}},

	 {{{{{2238882.000000, 715150.000000, -472163.000000, -254613.000000, 380111.000000, -654750.000000, 1121353.000000,
	      333599.000000, 562977.000000,
	      -364970.000000, 208560.000000, -274321.000000, 4100552.000000, -318989.000000, 41503.000000, -925300.000000,
	      -743004.000000, 901396.000000,
	      4467926.000000, 164199.000000, -430601.000000, 317188.000000, -697022.000000, 454586.000000}}},
	   {{{-3571032.000000, -485708.000000, 314485.000000, 885018.000000, -732198.000000, -11775.000000, -5561149.000000,
	      355678.000000, -385941.000000,
	      -190762.000000, 885342.000000, 454979.000000, 102678.000000, -113855.000000, 413209.000000, 312329.000000,
	      36928.000000, 540936.000000,
	      3211412.000000, 648399.000000, 279886.000000, -664455.000000, 153032.000000, 922704.000000}}},
	   {{{1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.}}},
	   {{{0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.}}}}}};
#endif

#endif //ALPENHORN_PKG_H
