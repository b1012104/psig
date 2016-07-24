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

	private_key_set_rand(prikey);
	public_key_set(pubkey, prikey);

	printf("------------ SIGN ------------\n");
	printf("message: %s\n", message);
	sign(sig, prikey, message);

	printf("-------- VERIFICATION --------\n");
	printf("message: %s\n", message);
	/*
	 * verification test
	 */
	//message[5]++;
	if (verify(sig, pubkey, message) == 0)
		printf("Verification Success\n");
	else
		printf("Verification Failure\n");

	public_key_clear(pubkey);
	private_key_clear(prikey);
	sig_clear(sig);

	return 0;
}
