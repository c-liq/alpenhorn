#include <bn256_bls.h>
void main()
{
	bn_init();
	bn256_bls_keypair kp;
	bn256_bls_keygen(&kp);

	uint8_t msg[60] = "test message";
	uint8_t sig_buf[2][g1_bytes];
	bn256_bls_sign_message(sig_buf[0], msg, sizeof msg, kp.secret_key);
	twistpoint_fp2_t keys[2];
	bn256_bls_keypair kp2;
	bn256_bls_keygen(&kp2);
	bn256_bls_sign_message(sig_buf[1], msg, sizeof msg, kp2.secret_key);
	twistpoint_fp2_set(keys[0], kp.public_key);
	twistpoint_fp2_set(keys[1], kp2.public_key);

	twistpoint_fp2_t combined_key;
	twistpoint_fp2_add_vartime(combined_key, kp.public_key, kp2.public_key);
	twistpoint_fp2_makeaffine(combined_key);
	curvepoint_fp_t sig1;
	curvepoint_fp_t sig2;
	bn256_deserialize_g1(sig1, sig_buf[0]);
	bn256_deserialize_g1(sig2, sig_buf[1]);

	curvepoint_fp_t combined_sig;
	curvepoint_fp_add_vartime(combined_sig, sig1, sig2);
	curvepoint_fp_makeaffine(combined_sig);
	uint8_t serializedsig[g1_bytes];
	bn256_serialize_g1(serializedsig, combined_sig);
	int res;

	res = bn256_bls_verify_message(combined_key, serializedsig, msg, sizeof msg);
	printf("result: %d\n", res);
	res = bn256_bls_verify_multisig(keys, 2, sig_buf[0], msg, sizeof msg);
	printf("result: %d\n", res);
	//res = bn256_bls_verify_from_point(combined_key, combined_sig, msg, sizeof msg);
	printf("result: %d\n", res);

	res = bn256_bls_verify_message(kp.public_key, sig_buf[0], msg, sizeof msg);
	printf("result: %d\n", res);
	res = bn256_bls_verify_message(kp2.public_key, sig_buf[1], msg, sizeof msg);
	printf("result: %d\n", res);
}
