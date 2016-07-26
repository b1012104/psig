#include <stdio.h>
#include <stdlib.h>
#include "psig.h"

int
main(int argc, char *argv[])
{
	char *message = argv[1];
	PRIVATE_KEY prikey;
	PUBLIC_KEY pubkey;
	SIGNATURE sig;

	if (argc < 2)
		return 1;

	private_key_init(prikey);
	public_key_init(pubkey);
	sig_init(sig);

	keygen(prikey, pubkey);

	printf("------------ SIGN ------------\n");
	printf("message: %s\n", message);
	sign(sig, prikey, message);

#ifdef DEBUG
	printf("---------------- Private Key ----------------\n");
	gmp_printf("s = %Zd\n", prikey->s);
	printf("---------------- Public Key  ----------------\n");
	printf("P ");
	point_print(pubkey->P);
	printf("Q ");
	point_print(pubkey->Q);
	printf("----------------- Signature -----------------\n");
	printf("sM ");
	point_print(sig->sM);
#endif

#ifdef VERFAILED
	message[0]++;
#endif

	printf("-------- VERIFICATION --------\n");
	printf("message: %s\n", message);
	if (verify(sig, pubkey, message))
		printf("Verification Success\n");
	else
		printf("Verification failed\n");

	public_key_clear(pubkey);
	private_key_clear(prikey);
	sig_clear(sig);

	return 0;
}
