#pragma once
#include "SRPCommon.h"

class CSRPClient : public CSRPCommon
{
private:
	BIGNUM *m_pa;
	BIGNUM *m_pU;
	std::string m_strPassword;
public:
	CSRPClient(int nMFrom = M_FROM_K);
	virtual ~CSRPClient();

	// non-const method
	const BIGNUM *CalcA(void);
	const BIGNUM *CalculateM1(void);
	void Init(const char *pszUserName, const char *pszPassword);
	bool VerifyBAndU(const BIGNUM *pB, const BIGNUM *pSalt);
	bool VerifyM2(const BIGNUM *pM2);
};
