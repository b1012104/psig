#include <stdio.h>
#include <stdlib.h>
#include "psig.h"

int
main(int argc, char *argv[])
{
	char *message = argv[1];
	PUBLIC_KEY pubkey;
	PRIVATE_KEY prikey;
	SIGNATURE sig;

	public_key_init(pubkey);
	private_key_init(prikey);
	sig_init(sig);

	printf("message: %s\n", message);

	private_key_set_rand(prikey);
	public_key_set(pubkey, prikey);

	sign(sig, prikey, message);

	printf("message: %s\n", message);
	if (verify(sig, pubkey, message) == 0)
		printf("Verification Success\n");
	else
		printf("Verification Failure\n");

	public_key_clear(pubkey);
	private_key_clear(prikey);
	sig_clear(sig);

	return 0;
}
