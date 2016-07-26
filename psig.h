#ifndef PSIG_H
#define PSIG_H

#include <gmp.h>
#include <tepla/ec.h>

typedef struct public_key_st {
	EC_PAIRING p;
	EC_POINT P;
	EC_POINT Q;
} PUBLIC_KEY[1];

typedef struct private_key_st {
	// EC_PAIRING p;
	mpz_t s;
} PRIVATE_KEY[1];

typedef struct signature_st {
	EC_PAIRING p;
	EC_POINT sM;
} SIGNATURE[1];

#endif
