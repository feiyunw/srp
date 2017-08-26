#pragma once
#include "SRPCommon.h"

class CSRPServer : public CSRPCommon
{
private:
	BIGNUM *m_pb;
	BIGNUM *m_pV;
public:
	CSRPServer(int nMFrom = M_FROM_K);
	virtual ~CSRPServer();

	// non-const method
	const BIGNUM *CalcB(void);
	bool CalcV(BIGNUM **ppSalt, const char *pszPassword);
	void SetSaltAndV(BIGNUM *pSalt, BIGNUM *pV);
	bool VerifyA(const BIGNUM *pA);
	bool VerifyM1(const BIGNUM *pM1);
};
