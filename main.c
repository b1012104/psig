#include <stdio.h>
#include <stdlib.h>
#include "psig.h"

int
main(int argc, char *argv[])
{
	char *message = argv[1];
	PRIVATE_KEY prik;
	PUBLIC_KEY pubk;
	SIGNATURE sig;

	if (argc < 2)
		return 1;

	p_init();

	private_key_init(prik);
	public_key_init(pubk);
	sig_init(sig);

	keygen(prik, pubk, message);

	sign(sig, prik, message);

	if (verify(sig, pubk, message) == 0)
		printf("message is correct\n");
	else
		printf("message is incorrect\n");

	public_key_clear(pubk);
	private_key_clear(prik);
	sig_clear(sig);

	p_clear();

	return 0;
}
