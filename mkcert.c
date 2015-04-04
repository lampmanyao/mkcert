/*
 * Create client certificate demo using openssl API.
 *
 * First, there's a trusted rootcert.pem and a rootkey.pem.
 * They can be created by two steps:
 *   a) create root CA certificate
 *     $ openssl req -nodes -newkey rsa:1024 -sha1 -keyout rootkey.pem -out rootreq.pem
 *     $ openssl x509 -req -in rootreq.pem -sha1 -signkey rootkey.pem -out rootcert.pem
 *   b) install CA certificate as trusted certificate
 *     $ sudo mkdir -p /usr/share/ca-certificates/extra
 *     $ sudo cp rootcert.pem /usr/share/ca-certificates/extra/rootcert.crt
 *     $ sudo dpkg-reconfigure ca-certificates
 *     $ sudo update-ca-certificates
 *
 * Build with gcc:
 * $ gcc -Wall -o mkcert mkcert.c -lssl -lcrypto
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

int mkcert(X509_REQ* req, const char* rootkey, const char* rootcert);
int mkreq(X509_REQ** x509, EVP_PKEY** pkey, int bits, int serial, int days);

int main(int argc, char **argv)
{
	BIO* bio_err;
	X509_REQ* req = NULL;
	EVP_PKEY* pkey = NULL;

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	mkreq(&req, &pkey, 1024, 0, 365);
	mkcert(req, "rootkey.pem", "rootcert.pem");

	RSA_print_fp(stdout, pkey->pkey.rsa, 0);
	X509_REQ_print_fp(stdout, req);
	PEM_write_X509_REQ(stdout, req);

	X509_REQ_free(req);
	EVP_PKEY_free(pkey);

	CRYPTO_cleanup_all_ex_data();
	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);

	return 0;
}

static void callback(int p, int n, void *arg)
{
	char c = 'B';

	if (p == 0)
		c = '.';
	if (p == 1)
		c = '+';
	if (p == 2)
		c = '*';
	if (p == 3)
		c = '\n';
	fputc(c, stderr);
}

static void load_cakey(EVP_PKEY** cakey, const char* keypem)
{
	FILE* f = fopen(keypem, "r");
	assert(f != NULL);
	PEM_read_PrivateKey(f, cakey, NULL, NULL);
	fclose(f);
}

static void load_cacert(X509** cacert, const char* certpem)
{
	FILE* f = fopen(certpem, "r");
	assert(f != NULL);
	PEM_read_X509(f, cacert, NULL, NULL);
	fclose(f);
}

int mkcert(X509_REQ* req, const char* rootkey, const char* rootcert)
{
	X509* cacert = X509_new();
	assert(cacert != NULL);

	load_cacert(&cacert, rootcert);

	EVP_PKEY* cakey = EVP_PKEY_new();
	load_cakey(&cakey, rootkey);

	PEM_write_PrivateKey(stdout, cakey, NULL, NULL, 0, NULL, NULL);
	PEM_write_PUBKEY(stdout, cakey);

	X509* x = X509_new();
	X509_set_version(x, 3);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1024);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * 365);

	X509_set_pubkey(x, X509_PUBKEY_get(req->req_info->pubkey));

	X509_set_subject_name(x, X509_REQ_get_subject_name(req));
	X509_set_issuer_name(x, X509_get_subject_name(cacert));

	assert(X509_sign(x, cakey, EVP_sha1()) > 0);

	FILE* f = fopen("usercert.pem", "wb");
	PEM_write_X509(f, x);
	fclose(f);

	X509_print_fp(stdout, x);
	PEM_write_X509(stdout, x);

	X509_free(cacert);
	EVP_PKEY_free(cakey);

	return 0;
}

int mkreq(X509_REQ** reqp, EVP_PKEY** pkeyp, int bits, int serial, int days)
{
	X509_REQ* req = X509_REQ_new();
	assert(req != NULL);

	EVP_PKEY* userpkey = EVP_PKEY_new();
	assert(userpkey != NULL);

	RSA* rsa;
	X509_NAME* name = NULL;

	rsa = RSA_generate_key(bits, RSA_F4, callback, NULL);
	assert(EVP_PKEY_assign_RSA(userpkey, rsa) > 0);

	rsa = NULL;

	X509_REQ_set_pubkey(req, userpkey);

	name = X509_REQ_get_subject_name(req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"OpenSSL Group", -1, -1, 0);

	assert(X509_REQ_sign(req, userpkey, EVP_sha1()) > 0);

	*reqp = req;
	*pkeyp = userpkey;

	return 0;
}

