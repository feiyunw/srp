#include "stdafx.h"

#include <cassert>
#include <string>
#pragma warning(disable : 4996)
#include <openssl/applink.c>
#include <openssl/bio.h>
#include <srp/SRPClient.h>
#include <srp/SRPServer.h>

// ============================================================================
// ==============================================================================
static void showbn(const char *name, const BIGNUM *bn)
{
	fputs(name, stdout);
	fputs(" = ", stdout);
	BN_print_fp(stdout, bn);
	putc('\n', stdout);
}

// ============================================================================
// ==============================================================================
static int run_srp(const char *username, const char *client_pass, const char *server_pass)
{
	//~~~~~~~~~~~~~~
	CSRPClient client;
	CSRPServer server;
	//~~~~~~~~~~~~~~

	client.Init(username, client_pass);

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	const BIGNUM *A = client.CalcA();
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// 1. Carol -> Steve: I and A
	assert(A);
	fputs("client:\n", stdout);
	showbn("N", client.GetN());
	showbn("g", client.Getg());
	showbn("A", client.GetA());
	fputs("I = ", stdout);
	fputs(client.GetI(), stdout);
	fputs("\n\n", stdout);

	// 2. Steve will abort if he receives A (mod N) = 0
	if (!server.VerifyA(A)) {
		return -1;
	}

	// server will abort if it cannot find identity I
	server.SetI(username);

	if (1) {

		//~~~~~~~~~~~~~~~~
		BIGNUM *salt = NULL;
		//~~~~~~~~~~~~~~~~

		// Calculate verifier from password. If leave salt as NULL, CalcV()
		// will make a random one.
		BN_hex2bn(&salt, "BEB25379D1A8581EB5A727673A2441EE");
		if (!server.CalcV(&salt, server_pass)) {
			return -1;
		}

		BN_free(salt);
	} else {

		//~~~~~~~~~~~~~~~~
		BIGNUM *salt = NULL;
		BIGNUM *v = NULL;
		//~~~~~~~~~~~~~~~~

		// Get the salt and verifier from registration DB. Here is an
		// example for user "alice" and password "password123".
		BN_hex2bn(&salt, "BEB25379D1A8581EB5A727673A2441EE");
		BN_hex2bn(&v,
				  "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB");
		server.SetSaltAndV(salt, v);
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	const BIGNUM *salt = server.GetSalt();
	const BIGNUM *B = server.CalcB();
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// 3. Steve -> Carol : s and B
	assert(salt);
	assert(B);
	fputs("server:\n", stdout);
	showbn("N", server.GetN());
	showbn("g", server.Getg());
	showbn("A", server.GetA());
	fputs("I = ", stdout);
	fputs(server.GetI(), stdout);
	fputs("\n", stdout);
	showbn("Salt", server.GetSalt());
	showbn("B", server.GetB());
	fputs("\n\n", stdout);

	// 4. Carol will abort if she receives B (mod N) = 0 or u = 0
	if (!client.VerifyBAndU(B, salt)) {
		return -1;
	}

	fputs("client:\n", stdout);
	showbn("Salt", client.GetSalt());
	showbn("B", client.GetB());
	fputs("\n\n", stdout);

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	const BIGNUM *M1 = client.CalculateM1();
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// 5. Carol -> Steve : M1
	assert(M1);
	fputs("client:\n", stdout);
	showbn("M1", M1);
	showbn("S", client.GetS());
	showbn("K", client.GetK());
	fputs("\n\n", stdout);

	// 6. Steve verifies M1
	if (!server.VerifyM1(M1)) {
		fputs("server:\n", stdout);
		showbn("S", server.GetS());
		showbn("K", server.GetK());
		fputs("\n\n", stdout);
		fputs("run_srp() failed!\n\n", stdout);
		return -1;
	}

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	const BIGNUM *M2 = server.CalcM2();
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	// 7. Steve -> Carol : M2
	assert(M2);
	fputs("server:\n", stdout);
	showbn("M2", M2);
	showbn("S", server.GetS());
	showbn("K", server.GetK());
	fputs("\n\n", stdout);

	// 8. Carol verifies M2
	if (!client.VerifyM2(M2)) {
		return -1;
	}

	fputs("run_srp() exits successfully!\n\n", stdout);
	return 0;
}

// ============================================================================
// ==============================================================================
int main()
{
#ifdef _DEBUG
	_set_error_mode(_OUT_TO_MSGBOX);
#endif

	//~~~~~~~~~
	BIO *bio_err;
	//~~~~~~~~~

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
	CRYPTO_set_mem_debug(1);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	// "Negative" test, expect a mismatch
	if (run_srp("alice", "password", "password123") == 0) {
		fprintf(stderr, "Mismatched SRP run failed\n");
		return 1;
	}

	// "Positive" test, should pass
	if (run_srp("alice", "password123", "password123") != 0) {
		fprintf(stderr, "Plain SRP run failed\n");
		return 1;
	}

	BIO_free(bio_err);
	return 0;
}
