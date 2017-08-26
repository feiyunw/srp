#include "stdafx.h"

#include <cassert>
#include <openssl/rand.h>
#include <openssl/srp.h>

#include <srp/SRPServer.h>

// ============================================================================
// ==============================================================================
CSRPServer::CSRPServer(int nMFrom) : CSRPCommon(nMFrom)
{
	m_pb = NULL;
	m_pV = NULL;
}

// ============================================================================
// ==============================================================================
CSRPServer::~CSRPServer()
{
	BN_clear_free(m_pb);
	BN_clear_free(m_pV);
}

// ============================================================================
// ==============================================================================
const BIGNUM *CSRPServer::CalcB(void)
{
	assert(GetN());
	assert(Getg());
	assert(m_pV);

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	unsigned char rand_tmp[RANDOM_SIZE];
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	RAND_bytes(rand_tmp, sizeof(rand_tmp));
	BN_free(m_pb);
	m_pb = BN_bin2bn(rand_tmp, sizeof(rand_tmp), NULL);
	assert(m_pb);
	SetB(SRP_Calc_B(m_pb, GetN(), Getg(), m_pV));
	assert(GetB());
	return GetB();
}

// ============================================================================
// ==============================================================================
bool CSRPServer::CalcV(BIGNUM **ppSalt, const char *pszPassword)
{
	assert(ppSalt);
	assert(pszPassword);
	assert(GetN());
	assert(Getg());
	BN_clear_free(m_pV);
	m_pV = NULL;
	if (SRP_create_verifier_BN(GetI(), pszPassword, ppSalt, &m_pV, GetN(), Getg())) {
		assert(*ppSalt);
		assert(m_pV);
		SetSalt(BN_dup(*ppSalt));
		assert(GetSalt());
		return true;
	}

	assert(0);
	return false;
}

// ============================================================================
// ==============================================================================
void CSRPServer::SetSaltAndV(BIGNUM *pSalt, BIGNUM *pV)
{
	assert(pSalt);
	assert(pV);
	SetSalt(pSalt);
	BN_clear_free(m_pV);
	m_pV = pV;
	assert(GetSalt());
}

// ============================================================================
// ==============================================================================
bool CSRPServer::VerifyA(const BIGNUM *pA)
{
	assert(pA);
	assert(GetN());
	if (SRP_Verify_A_mod_N(pA, GetN())) {
		SetA(BN_dup(pA));
		assert(GetA());
		return true;
	}

	assert(0);
	return false;
}

// ============================================================================
// ==============================================================================
bool CSRPServer::VerifyM1(const BIGNUM *pM1)
{
	assert(GetN());
	assert(GetA());
	assert(GetB());
	assert(m_pV);
	assert(m_pb);

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	bool bRet = false;
	BIGNUM *u = SRP_Calc_u(GetA(), GetB(), GetN());
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	if (!BN_is_zero(u)) {
		SetS(SRP_Calc_server_key(GetA(), m_pV, u, m_pb, GetN()));
		assert(GetS());
		BN_clear_free(u);
		return !BN_cmp(pM1, CalcM1());
	}

	assert(0);
	BN_clear_free(u);
	return bRet;
}
