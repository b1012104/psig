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
	point_init(sig->S1, sig->p->g1);
	point_init(sig->S2, sig->p->g2);
	mpz_init(sig->r);
}

void
sig_clear(SIGNATURE sig)
{
	point_clear(sig->S1);
	point_clear(sig->S2);
	pairing_clear(sig->p);
	mpz_clear(sig->r);
}

/*
 * PUBLIC_KEY
 */
void
public_key_init(PUBLIC_KEY k)
{
	pairing_init(k->p, "ECBN254a");
	point_init(k->Q, k->p->g1);
}

void
public_key_set(PUBLIC_KEY pubk, PRIVATE_KEY prik)
{
	/* Q = sP */
	point_mul(pubk->Q, prik->s, prik->P);
}

void
public_key_clear(PUBLIC_KEY k)
{
	point_clear(k->Q);
	pairing_clear(k->p);
}

/*
 * PRIVATE_KEY
 */
void
private_key_init(PRIVATE_KEY k)
{
	pairing_init(k->p, "ECBN254a");
	point_init(k->P, k->p->g1);
	mpz_init(k->s);
}

void
private_key_set_rand(PRIVATE_KEY k)
{
	set_random(k->s, 256);
	point_random(k->P);
}

void
private_key_clear(PRIVATE_KEY k)
{
	point_clear(k->P);
	pairing_clear(k->p);
	mpz_clear(k->s);
}

void
sign(SIGNATURE sig, PRIVATE_KEY k, char *message)
{
	EC_GROUP ec;
	EC_POINT M;

	curve_init(ec, "ec_bn254_twa");
	point_init(M, ec);

	point_map_to_point(M, message, strlen(message), 80);

	set_random(sig->r, 256);
	/* S1 = rP in G1*/
	point_mul(sig->S1, sig->r, k->P);
	/* S2 = sM in G2*/
	point_mul(sig->S2, k->s, M);

	point_clear(M);
	curve_clear(ec);
}

int
verify(SIGNATURE sig, PUBLIC_KEY k, char *message)
{
	int result = 1;

	Element e1;
	Element e2;
	EC_GROUP ec;
	EC_POINT tmp;
	EC_POINT M;

	curve_init(ec, "ec_bn254_twa");
	point_init(tmp, ec);
	point_init(M, ec);
	point_map_to_point(M, message, strlen(message), 80);

	element_init(e1, k->p->g3);
	element_init(e2, k->p->g3);

	point_mul(tmp, sig->r, M);
	pairing_map(e1, k->Q, tmp, k->p);

	pairing_map(e2, sig->S1, sig->S2, sig->p);

	if (element_cmp(e1, e2) == 0)
		result = 0;
	else
		result = 1;

	element_clear(e1);
	element_clear(e2);

	point_clear(tmp);
	point_clear(M);
	curve_clear(ec);

	return result;
}
