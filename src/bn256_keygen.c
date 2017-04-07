#include "bn256.h"
#include "bn256_bls.h"
int main()
{

	for (int i = 0; i < 2; i++) {
		bn256_bls_keypair kp;
		bn256_bls_keygen(&kp);
		scalar_print2(kp.secret_key);
		twistpoint_fp2_print(stdout, kp.public_key);
		printf("\n");
	}
}
