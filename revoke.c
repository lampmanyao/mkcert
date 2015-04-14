/*
 * Verify client certificate which created by mkcert demo using openssl API.
 *
 * Build with gcc:
 * $ gcc -Wall -o revoke revoke.c -lssl -lcrypto
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
#include <string.h>
#include <assert.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define DB_NUMBER   6
#define DB_name     5
#define DB_file     4
#define DB_serial   3
#define DB_rev_date 2
#define DB_exp_date 1
#define DB_type     0

static char* make_revocation_str();
static int revoke(const char* dbfile, X509* x);
static X509* load_cert(const char* usercert);

int main(int argc, char** argv)
{
	X509* x = load_cert(argv[2]);
	int ret = revoke(argv[1], x);
	if (ret == -1) {
		printf("error\n");
	} else {
		printf("done\n");
	}

	X509_free(x);
	return 0;
}


/*
 * This func copy from openssl/apps/ca.c
 */
static char* make_revocation_str()
{
	char* str;
	ASN1_UTCTIME* revtm = NULL;
	int i;

	revtm = X509_gmtime_adj(NULL, 0);

	if (!revtm)
		return NULL;

	i = revtm->length + 1;

	str = OPENSSL_malloc(i);

	if (!str)
		return NULL;

	BUF_strlcpy(str, (char *)revtm->data, i);
	ASN1_UTCTIME_free(revtm);

	return str;
}

static int revoke(const char* dbfile, X509* x)
{
	ASN1_UTCTIME* tm = NULL;
	char* rev_str = NULL;
	BIGNUM* bn = NULL;
	int i;
	char* row[DB_NUMBER];

	for (i = 0; i < DB_NUMBER; i++)
		row[i] = NULL;
	row[DB_name] = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
	bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x), NULL);
	assert(bn != NULL);
	if (BN_is_zero(bn))
		row[DB_serial] = BUF_strdup("00");
	else
		row[DB_serial] = BN_bn2hex(bn);

	BN_free(bn);


	assert(row[DB_name] != NULL);
	assert(row[DB_serial] != NULL);

	FILE* f = fopen(dbfile, "a+");
	assert(f != NULL);
	char line[512] = {0};

	while (fgets(line, 512, f)) {
		char* sep = "\t";
		char* token;
		int i = 0;

		char* p = line;
		while ((token = strsep(&p, sep)) != NULL) {
			i++;
			if (i == DB_serial + 1) {
				if (strcmp(row[DB_serial], token) == 0) {
					fprintf(stderr, "ERROR:Already revoked, serial number %s\n", row[DB_serial]);
					fclose(f);
					return -1;
				}
			}
		}
	}

	row[DB_type] = (char *)OPENSSL_malloc(2);

	tm = X509_get_notAfter(x);
	row[DB_exp_date] = (char *)OPENSSL_malloc(tm->length + 1);
	memcpy(row[DB_exp_date], tm->data, tm->length);
	row[DB_exp_date][tm->length] = '\0';

	row[DB_rev_date] = NULL;
	row[DB_file] = (char *)OPENSSL_malloc(8);

	assert(row[DB_type] != NULL);
	assert(row[DB_exp_date] != NULL);
	assert(row[DB_file] != NULL);
	BUF_strlcpy(row[DB_file], "unknown", 8);
	row[DB_type][0] = 'V';
	row[DB_type][1] = '\0';

	fprintf(stderr, "Revoking Certificate %s.\n", row[DB_serial]);
	rev_str = make_revocation_str();
	assert(rev_str != NULL);
	row[DB_type][0] = 'R';
	row[DB_type][1] = '\0';
	row[DB_rev_date] = rev_str;

	for (i = 0; i < DB_NUMBER; i++) {
		if (row[i] != NULL) {
			fwrite(row[i], strlen(row[i]), 1, f);
			fwrite("\t", 1, 1, f);
			OPENSSL_free(row[i]);
		}
	}

	fclose(f);
	return 0;
}

static X509* load_cert(const char* usercert)
{
	/* read usercert from file */
	X509* x = NULL;
	BIO* bio = BIO_new(BIO_s_file());
	assert(bio != NULL);
	assert(BIO_read_filename(bio, usercert) > 0);
	x = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
	BIO_free(bio);
	assert(x != NULL);

	return x;
}

