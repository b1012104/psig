#ifndef PSIG_H
#define PSIG_H

#include <gmp.h>
#include <tepla/ec.h>

typedef struct public_key_st {
	EC_POINT Q;
	Element d1;
	Element d2;
} PUBLIC_KEY[1];

typedef struct private_key_st {
	mpz_t s;
	mpz_t r;
	EC_POINT P;
} PRIVATE_KEY[1];

typedef struct signature_st {
	EC_POINT sP;
} SIGNATURE[1];

#endif
