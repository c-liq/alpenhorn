#define PBC_DEBUG
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <sodium.h>
#include "alpenhorn.h"
#include "ibe_basic.h"

static const char *sk[] = {"10778343094975392135581974247340460372164289692929233030125470550571339685912",
                           "9688549132935229128161053765094784437559599536117169899827480125341223824030",
                           "14754489302236821884533158176717016782900034847354657195783194213647848389200"
};

static const char *pk[] =
    {"[[6086379828989660989028314078811395552519168740126492884410228417657741197505, 8144852052844972129099269274667998534513045130276301011761818051955232294764], [12905311036091495766560354314955717180785052939814771374732216405908083158588, 12206468764955976902377549492754113261152529825339665500250747177941759322877]]",
     "[[8160164483073707263225494293658012847814401105023844402795912842754138236016, 3507539360481855979953507669121673921828426608186041809832896241678538524487], [2935004434206231188893390984062827282093819072637730926703958281099939979728, 1429257052468430779387305210231691157810800546837261775958933730699263478158]]",
     "[[13390979854465689884004374630321832512410728995089304572891318452815493144503, 11615922255584207485349740186764476249491844309988473417920830909660991527655], [11775135681555340005729773445724583755638324261572440444821270512920972679189, 21057092324234584843398020514715179172990825209983929208054184231184362858]]"};

const char *g = "[[15724257330924097062160683695880250933232554430187007470915263732860196404841,"
    " 11675890099551911688180980551831034403007152045230694854797640069104655082534], "
    "[13349283408131010710625633177944918626847137179157740569651489234485272434916,"
    " 14614450416672873406836739706484919090526432906183872742307134718470620099277]]";

void pbc_sum(element_t elem_sum, element_t *elem_ar, size_t n, pairing_t pairing) {
  if (!elem_sum || !elem_ar || !pairing) {
    return;
  }
  for (int i = 0; i < n; i++) {
    element_add(elem_sum, elem_sum, elem_ar[i]);
  }
}

void pb_sum_bytes(element_t elem_sum, byte_t **elem_bytes_ar, size_t n, pairing_t pairing) {
  element_t tmp;
  element_init_G1(tmp, pairing);
  for (int i = 0; i < n; i++) {
    element_from_bytes(tmp, elem_bytes_ar[i]);
    element_add(elem_sum, elem_sum, tmp);
  }
  element_clear(tmp);
}

void sign_message(element_t sig, byte_t *hash, int hash_len, element_t secret_key, pairing_t pairing) {
  element_t elem_from_hash;
  element_init_G1(elem_from_hash, pairing);
  element_from_hash(elem_from_hash, hash, hash_len);
  element_pow_zn(sig, elem_from_hash, secret_key);
  element_clear(elem_from_hash);
}

void signature_to_bytes(element_t sig,
                        byte_t *sig_buf,
                        byte_t *hash,
                        int hash_len,
                        element_t secret_key,
                        pairing_t pairing) {
  sign_message(sig, hash, hash_len, secret_key, pairing);
  element_to_bytes_x_only(sig_buf, sig);
}

int verify_signature(element_t sig, byte_t *hash, int hash_len, element_t public_key, element_t g, pairing_t pairing) {
  element_t u;
  element_t v;
  element_t hash_elem;
  int res = 0;
  element_init_G1(hash_elem, pairing);
  element_from_hash(hash_elem, hash, hash_len);
  element_init_GT(u, pairing);
  element_init_GT(v, pairing);
  element_pairing(u, sig, g);
  element_pairing(v, hash_elem, public_key);
  if (!element_cmp(u, v)) {
    res = 1;
  } else {
    element_invert(u, u);
    res = !(element_cmp(u, v));
  }
  element_clear(u);
  element_clear(v);
  element_clear(hash_elem);
  return res;
}


int main(int argc, char **argv) {
  pairing_t pairing;
  pbc_demo_pairing_init(pairing, argc, argv);
  element_t g_elem;
  element_t public_keys[3];
  element_t secret_keys[3];
  element_init(g_elem, pairing->G2);
  element_init(public_keys[0], pairing->G2);
  element_init(public_keys[1], pairing->G2);
  element_init(public_keys[2], pairing->G2);
  element_init(secret_keys[0], pairing->Zr);
  element_init(secret_keys[1], pairing->Zr);
  element_init(secret_keys[2], pairing->Zr);
  element_set_str(public_keys[0], pk[0], 10);
  element_set_str(public_keys[1], pk[1], 10);
  element_set_str(public_keys[2], pk[2], 10);
  element_set_str(secret_keys[0], sk[0], 10);
  element_set_str(secret_keys[1], sk[1], 10);
  element_set_str(secret_keys[2], sk[2], 10);
  int res = element_set_str(g_elem, g, 10);
  byte_t *msg = (byte_t *) "test message";
  byte_t hash[crypto_generichash_BYTES];
  crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg, NULL, 0);
  element_t sigs[3];
  element_init(sigs[0], pairing->G1);
  element_init(sigs[1], pairing->G1);
  element_init(sigs[2], pairing->G1);
  sign_message(sigs[0], hash, crypto_generichash_BYTES, secret_keys[0], pairing);
  sign_message(sigs[1], hash, crypto_generichash_BYTES, secret_keys[1], pairing);
  sign_message(sigs[2], hash, crypto_generichash_BYTES, secret_keys[2], pairing);
  element_t sig_sum;
  element_init(sig_sum, pairing->G1);
  pbc_sum(sig_sum, sigs, 3, pairing);
  element_t pk_sum;

  element_init(pk_sum, pairing->G2);
  pbc_sum(pk_sum, public_keys, 3, pairing);
  int x = verify_signature(sigs[0], hash, crypto_generichash_BYTES, pk_sum, g_elem, pairing);
  printf("%d\n", x);
  for (int i = 0; i < 3; i++) {
    element_clear(secret_keys[i]);
    element_clear(public_keys[i]);
    element_clear(sigs[i]);
  }
  element_clear(g_elem);
  element_clear(pk_sum);
  element_clear(sig_sum);
  pairing_clear(pairing);
  return 0;
}
