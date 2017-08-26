#pragma once
#include <string>
#include <openssl/bn.h>

class CSRPCommon
{
public:
	enum { RANDOM_SIZE = 32, };
	enum { M_FROM_K, M_FROM_S, };
private:
	int m_nMFrom;
	BIGNUM *m_pA;
	BIGNUM *m_pB;
	BIGNUM *m_pg;
	BIGNUM *m_pK;
	BIGNUM *m_pM1;
	BIGNUM *m_pM2;
	BIGNUM *m_pN;
	BIGNUM *m_pS;
	BIGNUM *m_pSalt;
	std::string m_strUserName;
private:
	// non-const method
	const BIGNUM *CalcM1FromK(void);
	const BIGNUM *CalcM1FromS(void);
public:
	CSRPCommon(int nMFrom = M_FROM_K);
	virtual ~CSRPCommon();

	// non-const method
	const BIGNUM *CalcM1(void);
	const BIGNUM *CalcM2(void);
	void SetA(BIGNUM *pA);
	void SetB(BIGNUM *pB);
	void SetI(const char *pszUserName);
	void SetMFrom(int nMFrom);
	void SetS(BIGNUM *pS);
	void SetSalt(BIGNUM *pSalt);

	// const method
	const BIGNUM *GetA(void) const;
	const BIGNUM *GetB(void) const;
	const BIGNUM *Getg(void) const;
	const char *GetI(void) const;
	const BIGNUM *GetK(void) const;
	int GetMFrom(void) const;
	const BIGNUM *GetN(void) const;
	const BIGNUM *GetS(void) const;
	const BIGNUM *GetSalt(void) const;
};

// ============================================================================
// ==============================================================================
inline const BIGNUM *CSRPCommon::GetA(void) const
{
	return m_pA;
}

// ============================================================================
// ==============================================================================
inline const BIGNUM *CSRPCommon::GetB(void) const
{
	return m_pB;
}

// ============================================================================
// ==============================================================================
inline const BIGNUM *CSRPCommon::Getg(void) const
{
	return m_pg;
}

// ============================================================================
// ==============================================================================
inline const char *CSRPCommon::GetI(void) const
{
	return m_strUserName.c_str();
}

// ============================================================================
// ==============================================================================
inline const BIGNUM *CSRPCommon::GetK(void) const
{
	return m_pK;
}

// ============================================================================
// ==============================================================================
inline const BIGNUM *CSRPCommon::GetN(void) const
{
	return m_pN;
}

// ============================================================================
// ==============================================================================
inline const BIGNUM *CSRPCommon::GetS(void) const
{
	return m_pS;
}

// ============================================================================
// ==============================================================================
inline const BIGNUM *CSRPCommon::GetSalt(void) const
{
	return m_pSalt;
}

// ============================================================================
// ==============================================================================
inline void CSRPCommon::SetMFrom(int nMFrom)
{
	m_nMFrom = nMFrom;
}
