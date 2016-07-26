#include "psig.h"
#include <gmp.h>
#include <tepla/ec.h>
#include <string.h>

void
set_random(mpz_t x, unsigned long secbit)
{
	gmp_randstate_t state;

	gmp_randinit_default(state);
	gmp_randseed_ui(state, (int)time(NULL));
	mpz_rrandomb(x, state, secbit);
	gmp_randclear(state);
}

/*
 * SIGNATURE
 */
void
sig_init(SIGNATURE sig)
{
	pairing_init(sig->p, "ECBN254a");
	point_init(sig->sM, sig->p->g2);
}

void
sig_clear(SIGNATURE sig)
{
	point_clear(sig->sM);
	pairing_clear(sig->p);
}

/*
 * PUBLIC_KEY
 */
void
public_key_init(PUBLIC_KEY k)
{
	pairing_init(k->p, "ECBN254a");
	point_init(k->P, k->p->g1);
	point_init(k->Q, k->p->g1);
}

void
public_key_set(PUBLIC_KEY pubk, PRIVATE_KEY prik)
{
	point_random(pubk->P);
	/* Q = sP */
	point_mul(pubk->Q, prik->s, pubk->P);
}

void
public_key_clear(PUBLIC_KEY k)
{
	point_clear(k->P);
	point_clear(k->Q);
	pairing_clear(k->p);
}

/*
 * PRIVATE_KEY
 */
void
private_key_init(PRIVATE_KEY k)
{
	mpz_init(k->s);
}

void
private_key_set_rand(PRIVATE_KEY k)
{
	set_random(k->s, 256);
}

void
private_key_clear(PRIVATE_KEY k)
{
	mpz_clear(k->s);
}

/*
 * Keygen, Sign and Verify
 */

void
keygen(PRIVATE_KEY prik, PUBLIC_KEY pubk)
{
	private_key_set_rand(prik);
	public_key_set(pubk, prik);
}

void
sign(SIGNATURE sig, PRIVATE_KEY k, char *message)
{
	point_map_to_point(sig->sM, message, strlen(message), 80);
	point_mul(sig->sM, k->s, sig->sM);
}

int
verify(SIGNATURE sig, PUBLIC_KEY k, char *message)
{
	int result = 1;

	EC_POINT M;
	Element x;
	Element y;

	point_init(M, k->p->g2);
	element_init(x, k->p->g3);
	element_init(y, k->p->g3);
	point_map_to_point(M, message, strlen(message), 80);

	pairing_map(x, k->P, sig->sM, k->p);
	pairing_map(y, k->Q, M, k->p);

	/* e(P, sM) = e(Q, M) */
	if (element_cmp(x, y) == 0)
		result = 1;
	else
		result = 0;

	point_clear(M);
	element_clear(x);
	element_clear(y);

	return result;
}
