#include "stdafx.h"

#include <cassert>
#include <openssl/rand.h>
#include <openssl/srp.h>

#include <srp/SRPClient.h>

// ============================================================================
// ==============================================================================
CSRPClient::CSRPClient(int nMFrom) : CSRPCommon(nMFrom)
{
	m_pa = NULL;
	m_pU = NULL;
}

// ============================================================================
// ==============================================================================
CSRPClient::~CSRPClient()
{
	BN_clear_free(m_pa);
	BN_clear_free(m_pU);
}

// ============================================================================
// ==============================================================================
const BIGNUM *CSRPClient::CalcA(void)
{
	assert(GetN());
	assert(Getg());

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	unsigned char rand_tmp[RANDOM_SIZE];
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	RAND_bytes(rand_tmp, sizeof(rand_tmp));
	BN_free(m_pa);
	m_pa = BN_bin2bn(rand_tmp, sizeof(rand_tmp), NULL);
	assert(m_pa);
	SetA(SRP_Calc_A(m_pa, GetN(), Getg()));
	assert(GetA());
	return GetA();
}

// ============================================================================
// ==============================================================================
const BIGNUM *CSRPClient::CalculateM1(void)
{
	assert(GetSalt());
	assert(!m_strPassword.empty());
	assert(m_pU);
	assert(!BN_is_zero(m_pU));
	assert(GetN());
	assert(Getg());
	assert(m_pa);
	assert(GetB());

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	BIGNUM *x = SRP_Calc_x(GetSalt(), GetI(), m_strPassword.c_str());
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	assert(x);
	SetS(SRP_Calc_client_key(GetN(), GetB(), Getg(), x, m_pa, m_pU));
	BN_clear_free(x);
	assert(GetS());
	return CalcM1();
}

// ============================================================================
// ==============================================================================
void CSRPClient::Init(const char *pszUserName, const char *pszPassword)
{
	assert(pszUserName);
	assert(pszPassword);
	SetI(pszUserName);
	m_strPassword = pszPassword;
}

// ============================================================================
// ==============================================================================
bool CSRPClient::VerifyBAndU(const BIGNUM *pB, const BIGNUM *pSalt)
{
	assert(pB);
	assert(pSalt);
	assert(GetN());
	if (SRP_Verify_B_mod_N(pB, GetN())) {
		BN_free(m_pU);
		m_pU = SRP_Calc_u(GetA(), pB, GetN());
		assert(m_pU);
		if (!BN_is_zero(m_pU)) {
			SetB(BN_dup(pB));
			SetSalt(BN_dup(pSalt));
			assert(GetB());
			assert(GetSalt());
			return true;
		}

		assert(0);
		BN_free(m_pU);
		m_pU = NULL;
	} else {
		assert(0);
	}

	return false;
}

// ============================================================================
// ==============================================================================
bool CSRPClient::VerifyM2(const BIGNUM *pM2)
{
	assert(pM2);
	return !BN_cmp(pM2, CalcM2());
}
