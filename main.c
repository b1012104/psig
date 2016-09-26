#include <stdio.h>
#include <stdlib.h>
#include "psig.h"

extern EC_PAIRING p;

int
main(int argc, char *argv[])
{
	char *message = argv[1];
	PRIVATE_KEY prikey;
	PUBLIC_KEY pubkey;
	SIGNATURE sig;

	if (argc < 2)
		return 1;

	p_init();

	private_key_init(prikey);
	public_key_init(pubkey);
	sig_init(sig);

	keygen(prikey, pubkey);

	sign(sig, prikey, message);

	if(verify_public_key(sig, pubkey) != 0)
		printf("public key is incorrect\n");

	if (verify_message(sig, pubkey, message) != 0)
		printf("message is incorrect");

	public_key_clear(pubkey);
	private_key_clear(prikey);
	sig_clear(sig);

	p_clear();

	return 0;
}
