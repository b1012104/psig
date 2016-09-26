#include "psig.h"
#include <gmp.h>
#include <tepla/ec.h>
#include <string.h>

extern EC_PAIRING p;

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
	point_init(sig->R, p->g2);
}

void
sig_clear(SIGNATURE sig)
{
	point_clear(sig->R);
}

/*
 * PUBLIC_KEY
 */
void
public_key_init(PUBLIC_KEY k)
{
	point_init(k->Q, p->g1);
	element_init(k->d, p->g3);
}

void
public_key_set(PUBLIC_KEY pubk, PRIVATE_KEY prik, char *message)
{
	EC_POINT tP;

	point_init(tP, p->g2);

	/* Q = sP */
	point_mul(pubk->Q, prik->P, prik->s);
	/* use SHA1 */
	point_map_to_point(tP, message, strlen(message), 80);
	point_mul(tP, tP, prik->r);
	/* d = e(P, rH(M)) */
	pairing_map(pubk->d, prik->P, tP, p);

	point_clear(tP);
}

void
public_key_clear(PUBLIC_KEY k)
{
	point_clear(k->Q);
	element_clear(k->d);
}

/*
 * PRIVATE_KEY
 */
void
private_key_init(PRIVATE_KEY k)
{
	mpz_init(k->s);
	mpz_init(k->r);
	point_init(k->P, p->g1);
}

void
private_key_set_random(PRIVATE_KEY k)
{
	set_random(k->s, 256);
	set_random(k->r, 256);
	point_random(k->P);
}

void
private_key_clear(PRIVATE_KEY k)
{
	mpz_clear(k->s);
	mpz_clear(k->r);
	point_clear(k->P);
}

/*
 * Keygen, Sign and Verify
 */

void
keygen(PRIVATE_KEY prik, PUBLIC_KEY pubk)
{
	private_key_set_random(prik);
	public_key_set(pubk, prik);
}

void
sign(SIGNATURE sig, PRIVATE_KEY k, char *message)
{
	mpz_t tmp;
	mpz_init(tmp);

	point_map_to_point(sig->R, message, strlen(message), 80);
	mpz_divexact(tmp, r, s);
	point_mul(sig->R, k->P, tmp);

	mpz_clear(tmp);
}

int
verify_public_key(SIGNATURE sig, PUBLIC_KEY k)
{
	int result = 1;
	Element tmp;
	element_init(tmp, p->g3);

	pairing_map(tmp, k->Q, sig->R, p);
	if (element_cmp(tmp, k->d) == 0)
		result = 0;

	element_clear(tmp);

	return result;
}

int
verify_message(SIGNATURE sig, PUBLIC_KEY k, char *message)
{
	int result = 1;
	Element td;
	Element ver;
	Element tmp;
	EC_POINT tP;

	point_init(tP, p->g2);
	element_init(td, p->g3);
	element_init(ver, p->g3);
	element_init(tmp, p->g3);

	point_map_to_point(tP, message, strlen(message), 80);

	/* e(sP, H(M)) */
	pairing_map(ver, k->Q ,tP, p);

	/* r/s H(M) + H(M) = (s + r) / s H(M) */
	point_add(tP, sig->R, tP);
	/* e(sP, (s+r)/s H(M)) = e(P, H(M))^(s+r)*/
	pairing_map(td, k->Q, tP, p);
	element_inv(tmp, k->d);
	element_mul(td, td, tmp);

	if (element_cmp(td, ver) == 0)
		result = 0;

	point_clear(tP);
	element_clear(td);
	element_clear(ver);
	element_clear(tmp);

	return result;
}
