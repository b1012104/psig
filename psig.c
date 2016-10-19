#include "psig.h"
#include <gmp.h>
#include <tepla/ec.h>
#include <string.h>

EC_PAIRING p;

void
p_init()
{
	pairing_init(p, "ECBN254a");
}

void
p_clear()
{
	pairing_clear(p);
}

void
mpz_set_random(mpz_t x, unsigned long secbit)
{
	static gmp_randstate_t state;
	static char ch = 0;

	if (!ch++) {
		gmp_randinit_default(state);
		gmp_randseed_ui(state, (unsigned long int)time(NULL));
	}
	mpz_rrandomb(x, state, secbit);
}

/*
 * SIGNATURE
 */
void
sig_init(SIGNATURE sig)
{
	point_init(sig->sP, p->g1);
}

void
sig_clear(SIGNATURE sig)
{
	point_clear(sig->sP);
}

/*
 * PUBLIC_KEY
 */
void
public_key_init(PUBLIC_KEY pubk)
{
	point_init(pubk->Q, p->g2);
	element_init(pubk->d1, p->g3);
	element_init(pubk->d2, p->g3);
}

void
public_key_set(PUBLIC_KEY pubk, PRIVATE_KEY prik, char *msg)
{
	EC_POINT tP;
	point_init(tP, p->g1);

	point_random(pubk->Q);
	/* e(P, Q)^s */
	point_mul(tP, prik->s, prik->P);
	pairing_map(pubk->d1, tP, pubk->Q, p);
	/* e(P, Q)^r */
	point_mul(tP, prik->r, prik->P);
	pairing_map(pubk->d2, tP, pubk->Q, p);

	point_clear(tP);
}

void
public_key_clear(PUBLIC_KEY pubk)
{
	point_clear(pubk->Q);
	element_clear(pubk->d1);
	element_clear(pubk->d2);
}

/*
 * PRIVATE_KEY
 */
void
private_key_init(PRIVATE_KEY prik)
{
	mpz_init(prik->s);
	mpz_init(prik->r);
	point_init(prik->P, p->g1);
}

void
private_key_set_random(PRIVATE_KEY prik)
{
	mpz_set_random(prik->s, 256);
	mpz_set_random(prik->r, 256);
	point_random(prik->P);
}

void
private_key_clear(PRIVATE_KEY prik)
{
	mpz_clear(prik->s);
	mpz_clear(prik->r);
	point_clear(prik->P);
}

/*
 * Keygen, Sign and Verify
 */
void
keygen(PRIVATE_KEY prik, PUBLIC_KEY pubk, char *msg)
{
	private_key_set_random(prik);
	public_key_set(pubk, prik, msg);
}

void
sign(SIGNATURE sig, PRIVATE_KEY prik, char *msg)
{
	mpz_t tmp;
	mpz_init(tmp);

	/* (s/m - r)P */
	IHF1_SHA(tmp, msg, strlen(msg), *curve_get_order(p->g1), 80);
	mpz_invert(tmp, tmp, *curve_get_order(p->g1));
	mpz_mul(tmp, tmp, prik->s);
	mpz_mod(tmp, tmp, *curve_get_order(p->g1));
	mpz_sub(tmp, tmp, prik->r);
	mpz_mod(tmp, tmp, *curve_get_order(p->g1));
	point_mul(sig->sP, tmp, prik->P);

	mpz_clear(tmp);
}

int
verify(SIGNATURE sig, PUBLIC_KEY pubk, char *msg)
{
	Element d;
	mpz_t m;
	int status = 1;

	mpz_init(m);
	element_init(d, p->g3);

	IHF1_SHA(m, msg, strlen(msg), *curve_get_order(p->g1), 80);
	pairing_map(d, sig->sP, pubk->Q, p);
	element_mul(d, d, pubk->d2);
	element_pow(d, d, m);

	if (element_cmp(d, pubk->d1) == 0)
		status--;

	mpz_clear(m);
	element_clear(d);

	return status;
}
