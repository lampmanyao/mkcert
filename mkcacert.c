/*
 * Build with gcc:
 * $ gcc -Wall -o mkcacert mkcacert.c -lssl -lcrypto
 *
 * Copyright (C) 2015 Lampman Yao (lampmanyao@gmail.com)
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

void mkcacert(X509_REQ* req, EVP_PKEY* pkey);
void mkreq(X509_REQ** x509p, EVP_PKEY** pkeyp, int bits, int serial, int days);

int main(int argc, char **argv)
{
	if (argc > 2) {
		printf("./%s\n", argv[0]);
		printf("or", argv[0]);
		printf("./%s passwd\n", argv[0]);
		return -1;
	}

	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();

	BIO* bio_err;
	X509_REQ* req = NULL;
	EVP_PKEY* pkey = NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	mkreq(&req, &pkey, 1024, 0, 365);

	mkcacert(req, pkey);

	FILE* f = fopen("rootkey.pem", "wb");
	if (argc == 1) {
		PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
	} else if (argc == 2) {
		PEM_write_PrivateKey(f, pkey, EVP_des_ede3_cbc(), NULL, 0, NULL, argv[1]);
	}
	fclose(f);
	RSA_print_fp(stdout, pkey->pkey.rsa, 0);
	PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);

	f = fopen("rootreq.pem", "wb");
	PEM_write_X509_REQ(f, req);
	fclose(f);
	X509_REQ_print_fp(stdout, req);
	PEM_write_X509_REQ(stdout, req);

	X509_REQ_free(req);
	EVP_PKEY_free(pkey);

	CRYPTO_cleanup_all_ex_data();
	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);

	return 0;
}

void mkcacert(X509_REQ* req, EVP_PKEY* pkey)
{
	X509* x = X509_new();
	X509_set_version(x, 3);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1024);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * 365);

	X509_set_pubkey(x, X509_PUBKEY_get(req->req_info->pubkey));

	X509_set_subject_name(x, X509_REQ_get_subject_name(req));

	X509_NAME* name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"Openssl", -1, -1, 0);
	X509_set_issuer_name(x, name);

	assert(X509_sign(x, pkey, EVP_sha1()) > 0);

	FILE* f = fopen("rootcert.pem", "wb");
	PEM_write_X509(f, x);
	fclose(f);

	X509_print_fp(stdout, x);
	PEM_write_X509(stdout, x);
}

void mkreq(X509_REQ** req, EVP_PKEY** pkeyp, int bits, int serial, int days)
{
	X509_REQ* x = X509_REQ_new();
	assert(x != NULL);

	EVP_PKEY* pk = EVP_PKEY_new();
	assert(pk != NULL);
	RSA* rsa;
	X509_NAME* name = NULL;

	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	assert(EVP_PKEY_assign_RSA(pk, rsa) > 0);

	rsa = NULL;

	X509_REQ_set_pubkey(x, pk);

	name = X509_REQ_get_subject_name(x);

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN",
				MBSTRING_ASC, (const unsigned char *)"OpenSSL Group", -1, -1, 0);

	assert(X509_REQ_sign(x, pk, EVP_sha1()) > 0);

	*req = x;
	*pkeyp = pk;
}

