#include "stdafx.h"

#include <cassert>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/srp.h>

#include <srp/SRPCommon.h>

// ============================================================================
// ==============================================================================
CSRPCommon::CSRPCommon(int nMFrom) : m_nMFrom(nMFrom)
{
	m_pA = NULL;
	m_pB = NULL;
	m_pg = NULL;
	m_pK = NULL;
	m_pM1 = NULL;
	m_pM2 = NULL;
	m_pN = NULL;
	m_pS = NULL;
	m_pSalt = NULL;

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	SRP_gN *pGN = SRP_get_default_gN("1024");
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	assert(pGN);
	m_pg = BN_dup(pGN->g);
	m_pN = BN_dup(pGN->N);
}

// ============================================================================
// ==============================================================================
CSRPCommon::~CSRPCommon()
{
	BN_free(m_pA);
	BN_free(m_pB);
	BN_clear_free(m_pg);
	BN_clear_free(m_pK);
	BN_free(m_pM1);
	BN_free(m_pM2);
	BN_clear_free(m_pN);
	BN_clear_free(m_pS);
	BN_free(m_pSalt);
}

// ============================================================================
// ==============================================================================
const BIGNUM *CSRPCommon::CalcM1(void)
{
	assert(GetS());
	switch (m_nMFrom) {
	case M_FROM_K:	CalcM1FromK(); break;
	case M_FROM_S:	CalcM1FromS(); break;
	default:		assert(0); break;
	}

	assert(m_pM1);
	return m_pM1;
}

// ============================================================================
// ==============================================================================
const BIGNUM *CSRPCommon::CalcM1FromK(void)
{
	// K = H(S) and M1 = H[H(N) XOR H(g) | H(I) | s | A | B | K]
	assert(GetN());
	assert(Getg());
	assert(GetSalt());
	assert(GetA());
	assert(GetB());
	assert(GetS());
	BN_free(m_pK);
	BN_free(m_pM1);
	m_pK = NULL;
	m_pM1 = NULL;

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	EVP_MD_CTX *ctxt = EVP_MD_CTX_new();
	unsigned char dig[SHA_DIGEST_LENGTH];
	unsigned char dig2[SHA_DIGEST_LENGTH];
	unsigned char dig3[SHA_DIGEST_LENGTH];
	unsigned char *cs = (unsigned char *)OPENSSL_malloc(BN_num_bytes(GetN()));
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	assert(ctxt);
	assert(cs);
	if (ctxt && cs && EVP_DigestInit_ex(ctxt, EVP_sha1(), NULL)) {

		// H(N)
		BN_bn2bin(GetN(), cs);
		if (EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetN())) && EVP_DigestFinal_ex(ctxt, dig, NULL)) {

			// H(g) -> dig2
			BN_bn2bin(Getg(), cs);
			if (EVP_DigestInit_ex(ctxt, EVP_sha1(), NULL)
			&& EVP_DigestUpdate(ctxt, cs, BN_num_bytes(Getg()) && EVP_DigestFinal_ex(ctxt, dig2, NULL))) {

				// H(N) ^ H(g)
				for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
					dig[i] ^= dig2[i];
				}

				// H(I) -> dig2
				if (EVP_DigestInit_ex(ctxt, EVP_sha1(), NULL) && EVP_DigestUpdate(ctxt, GetI(), strlen(GetI()))
				&& EVP_DigestFinal_ex(ctxt, dig2, NULL)) {

					// H(S) -> dig3
					BN_bn2bin(GetS(), cs);
					if (EVP_DigestInit_ex(ctxt, EVP_sha1(), NULL) && EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetS()))
					&& EVP_DigestFinal_ex(ctxt, dig3, NULL)) {

						// H(N) ^ H(g) | H(I)
						if (EVP_DigestInit_ex(ctxt, EVP_sha1(), NULL) && EVP_DigestUpdate(ctxt, dig, sizeof(dig))
						&& EVP_DigestUpdate(ctxt, dig2, sizeof(dig2))) {

							// | s
							BN_bn2bin(GetSalt(), cs);
							if (EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetSalt()))) {

								// | A
								BN_bn2bin(GetA(), cs);
								if (EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetA()))) {

									// | B | H(S)
									BN_bn2bin(GetB(), cs);
									if (EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetB()))
									&& EVP_DigestUpdate(ctxt, dig3, sizeof(dig3)) && EVP_DigestFinal_ex(ctxt, dig, NULL)) {
										m_pM1 = BN_bin2bn(dig, sizeof(dig), NULL);
										assert(m_pM1);
										m_pK = BN_bin2bn(dig3, sizeof(dig3), NULL);
										assert(m_pK);
									}
								}
							}
						}
					}
				}
			}
		}
	}

	OPENSSL_free(cs);
	EVP_MD_CTX_free(ctxt);
	assert(m_pK);
	assert(m_pM1);
	return m_pM1;
}

// ============================================================================
// ==============================================================================
const BIGNUM *CSRPCommon::CalcM1FromS(void)
{
	// M1 = H(A | B | S)
	assert(GetN());
	assert(GetA());
	assert(GetB());
	assert(GetS());
	BN_free(m_pM1);
	m_pM1 = NULL;

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	EVP_MD_CTX *ctxt = EVP_MD_CTX_new();
	unsigned char dig[SHA_DIGEST_LENGTH];
	unsigned char *cs = (unsigned char *)OPENSSL_malloc(BN_num_bytes(GetN()));
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	assert(ctxt);
	assert(cs);
	if (ctxt && cs && EVP_DigestInit_ex(ctxt, EVP_sha1(), NULL)) {
		BN_bn2bin(GetA(), cs);
		if (EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetA()))) {
			BN_bn2bin(GetB(), cs);
			if (EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetB()))) {
				BN_bn2bin(GetS(), cs);
				if (EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetS())) && EVP_DigestFinal_ex(ctxt, dig, NULL)) {
					m_pM1 = BN_bin2bn(dig, sizeof(dig), NULL);
					assert(m_pM1);
				}
			}
		}
	}

	OPENSSL_free(cs);
	EVP_MD_CTX_free(ctxt);
	assert(m_pM1);
	return m_pM1;
}

// ============================================================================
// ==============================================================================
const BIGNUM *CSRPCommon::CalcM2(void)
{
	// M2 = H(A | M1 | K) or H(A | M1 | S)
	assert(GetN());
	assert(GetA());
	assert(m_pM1);
	BN_free(m_pM2);
	m_pM2 = NULL;

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	EVP_MD_CTX *ctxt = EVP_MD_CTX_new();
	unsigned char dig[SHA_DIGEST_LENGTH];
	unsigned char *cs = (unsigned char *)OPENSSL_malloc(BN_num_bytes(GetN()));
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	assert(ctxt);
	assert(cs);
	if (ctxt && cs && EVP_DigestInit_ex(ctxt, EVP_sha1(), NULL)) {
		BN_bn2bin(GetA(), cs);
		if (EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetA()))) {
			BN_bn2bin(m_pM1, cs);
			if (EVP_DigestUpdate(ctxt, cs, BN_num_bytes(m_pM1))) {
				switch (m_nMFrom) {
				case M_FROM_K:
					assert(m_pK);
					BN_bn2bin(m_pK, cs);
					EVP_DigestUpdate(ctxt, cs, BN_num_bytes(m_pK));
					break;
				case M_FROM_S:
					assert(GetS());
					BN_bn2bin(GetS(), cs);
					EVP_DigestUpdate(ctxt, cs, BN_num_bytes(GetS()));
					break;
				default:
					assert(0);
					break;
				}

				if (EVP_DigestFinal_ex(ctxt, dig, NULL)) {
					m_pM2 = BN_bin2bn(dig, sizeof(dig), NULL);
					assert(m_pM2);
				}
			}
		}
	}

	OPENSSL_free(cs);
	EVP_MD_CTX_free(ctxt);
	assert(m_pM2);
	return m_pM2;
}

// ============================================================================
// ==============================================================================
void CSRPCommon::SetA(BIGNUM *pA)
{
	assert(pA);
	BN_free(m_pA);
	m_pA = pA;
}

// ============================================================================
// ==============================================================================
void CSRPCommon::SetB(BIGNUM *pB)
{
	assert(pB);
	BN_free(m_pB);
	m_pB = pB;
}

// ============================================================================
// ==============================================================================
void CSRPCommon::SetI(const char *pszUserName)
{
	assert(pszUserName);
	m_strUserName = pszUserName;
}

// ============================================================================
// ==============================================================================
void CSRPCommon::SetS(BIGNUM *pS)
{
	assert(pS);
	BN_free(m_pS);
	m_pS = pS;
}

// ============================================================================
// ==============================================================================
void CSRPCommon::SetSalt(BIGNUM *pSalt)
{
	assert(pSalt);
	BN_free(m_pSalt);
	m_pSalt = pSalt;
}
