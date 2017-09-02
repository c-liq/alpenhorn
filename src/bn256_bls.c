#include <stdint.h>
#include <bn256/curvepoint_fp.h>
#include <bn256/twistpoint_fp2.h>
#include <bn256_bls.h>

twistpoint_fp2_t twistgen = {{{{{490313, 4260028, -821156, -818020, 106592, -171108, 757738, 545601, 597403,
                                 366066, -270886, -169528, 3101279, 2043941, -726481, 382478, -650880, -891316,
                                 -13923, 327200, -110487, 473555, -7301, 608340}}},
                              {{{-4628877, 3279202, 431044, 459682, -606446, -924615, -927454, 90760, 13692,
                                 -225706, -430013, -373196, 3004032, 4097571, 380900, 919715, -640623, -402833,
                                 -729700, -163786, -332478, -440873, 510935, 593941}}},
                              {{{1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
                                 0., 0.}}},
                              {{{0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
                                 0., 0.}}}}};

void bn256_bls_keygen(bn256_bls_keypair *kp)
{
	bn256_scalar_random(kp->secret_key);
	bn256_scalarmult_base_g2(kp->public_key, kp->secret_key);
	twistpoint_fp2_makeaffine(kp->public_key);
}

void bn256_bls_sign_message(uint8_t *out_buf, uint8_t *msg, uint32_t msg_len, scalar_t secret_key)
{
	curvepoint_fp_t sig_g1;
	bn256_hash_g1(sig_g1, msg, msg_len);
	curvepoint_fp_scalarmult_vartime(sig_g1, sig_g1, secret_key);
	curvepoint_fp_makeaffine(sig_g1);
	bn256_serialize_g1_xonly(out_buf, sig_g1);
}

int bn256_bls_verify_message(twistpoint_fp2_t p, uint8_t *signature, uint8_t *msg, size_t msg_len)
{
	curvepoint_fp_t h;
	bn256_hash_g1(h, msg, msg_len);
	curvepoint_fp_makeaffine(h);
	curvepoint_fp_t sig2;
	bn256_deserialize_g1_xonly(sig2, signature);
	fp12e_t u, v;
	bn256_pair(u, twistgen, sig2);
	bn256_pair(v, p, h);
	int v1 = fp12e_iseq(u, v);
	fp12e_invert(v, v);
	int v2 = fp12e_iseq(u, v);
	return v1 || v2;
}

int bn256_bls_verify_from_point(twistpoint_fp2_t public_key, curvepoint_fp_t signature,
                                uint8_t *msg,
                                size_t msg_len)
{
	curvepoint_fp_t sig_from_msg;
	bn256_hash_g1(sig_from_msg, msg, msg_len);
	fp12e_t u, v;
	bn256_pair(u, twistgen, signature);
	bn256_pair(v, public_key, sig_from_msg);
	return fp12e_iseq(u, v);
}

int bn256_bls_verify_multisig(twistpoint_fp2_t *public_keys,
                              size_t num_participants,
                              uint8_t *signatures,
                              uint8_t *msg,
                              size_t msg_len)
{
	twistpoint_fp2_t combined_key;
	bn256_sum_g2(combined_key, public_keys, num_participants);
	curvepoint_fp_t sig_from_msg;
	bn256_hash_g1(sig_from_msg, msg, msg_len);
	curvepoint_fp_t combined_sig;
	bn256_deserialize_and_sum_g1(combined_sig, signatures, num_participants);
	fp12e_t u, v;
	bn256_pair(u, twistgen, combined_sig);
	bn256_pair(v, combined_key, sig_from_msg);
	return fp12e_iseq(u, v);
}

