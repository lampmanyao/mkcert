/*
 * Verify client certificate which created by mkcert demo using openssl API.
 *
 * Build with gcc:
 * $ gcc -Wall -o verify verify.c -lssl -lcrypto
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

static int verify(const char* cacert, const char* usercert);
static X509* load_cert(const char* usercert);
static int check(X509_STORE* ctx, const char* usercert);

int main(int argc, char** argv)
{
	if (argc != 3) {
		printf("usage: %s cacert usercert\n", argv[0]);
		return -1;
	}

	if (verify(argv[1], argv[2]) == 0) {
		fprintf(stderr, "verify failed\n");
	} else {
		fprintf(stderr, "verify done\n");
	}

	return 0;
}

int verify(const char* cacert, const char* usercert)
{
	int ret = 0;
	X509_STORE* cert_ctx = NULL;
 	X509_LOOKUP* lookup = NULL;

	cert_ctx = X509_STORE_new();
	assert(cert_ctx != NULL);

	OpenSSL_add_all_algorithms();

	lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
	assert(lookup != NULL);

	assert(X509_LOOKUP_load_file(lookup, cacert, X509_FILETYPE_PEM) > 0);

	lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
	assert(lookup != NULL);

	X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

	ret = check(cert_ctx, usercert);
	X509_STORE_free(cert_ctx);

	return ret;
}

static X509* load_cert(const char* usercert)
{
	X509* x = NULL;
	BIO* cert = BIO_new(BIO_s_file());
	assert(cert != NULL);

	assert(BIO_read_filename(cert, usercert) > 0);
	x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
	BIO_free(cert);

	return x;
}

static int check(X509_STORE* ctx, const char* usercert)
{
	X509* x = NULL;
	int i = 0;
	X509_STORE_CTX* csc;

	x = load_cert(usercert);
	assert(x != NULL);

	csc = X509_STORE_CTX_new();
	assert(csc != NULL);

	X509_STORE_set_flags(ctx, 0);
	assert(X509_STORE_CTX_init(csc, ctx, x, 0) > 0);

	i = X509_verify_cert(csc);
	X509_STORE_CTX_free(csc);

	X509_free(x);

	return i > 0;
}

