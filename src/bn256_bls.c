#include <stdint.h>
#include "bn256_bls.h"

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
	bn256_scalarmult_bg2(kp->public_key, kp->secret_key);
}

void bn256_bls_sign_message(uint8_t *out_buf, uint8_t *msg, uint32_t msg_len, scalar_t secret_key)
{
	curvepoint_fp_t sig_g1;
	bn256_hash_g1(sig_g1, msg, msg_len);
	curvepoint_fp_scalarmult_vartime(sig_g1, sig_g1, secret_key);
	bn256_serialize_g1(out_buf, sig_g1);
}

int bn256_bls_verify_message(twistpoint_fp2_t public_key, uint8_t *signature, uint8_t *msg, size_t msg_len)
{
	curvepoint_fp_t sig1;
	bn256_hash_g1(sig1, msg, msg_len);
	curvepoint_fp_t sig2;
	bn256_deserialize_g1(sig2, signature);

	fp12e_t u, v;
	bn256_pair(u, twistgen, sig1);
	bn256_pair(v, public_key, sig2);

	return fp12e_iseq(u, v);
}

int bn256_bls_verify_multisig(twistpoint_fp2_t *public_keys,
                              size_t num_keys,
                              uint8_t *signatures,
                              uint8_t *msg,
                              size_t msg_len)
{
	twistpoint_fp2_t combined_key;
	bn256_sum_g2(combined_key, public_keys, num_keys);
	curvepoint_fp_t sig_from_msg;
	bn256_hash_g1(sig_from_msg, msg, msg_len);
	curvepoint_fp_t combined_sig;
	bn256_deserialize_and_sum_g1(combined_sig, signatures, num_keys);

	fp12e_t u, v;
	bn256_pair(u, twistgen, sig_from_msg);
	bn256_pair(v, combined_key, combined_sig);

	return fp12e_iseq(u, v);
}

void main()
{
	bn_init();
	bn256_bls_keypair kp;
	bn256_bls_keygen(&kp);

	uint8_t msg[60] = "test message";
	uint8_t sig_buf[g1_bytes];
	bn256_bls_sign_message(sig_buf, msg, sizeof msg, kp.secret_key);

	int res = bn256_bls_verify_message(kp.public_key, sig_buf, msg, sizeof msg);
	printf("%d\n", res);

}
