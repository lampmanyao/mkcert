/*
 * Verify client certificate which created by mkcert demo using openssl API.
 *
 * Build with gcc:
 * $ gcc -Wall -o gencrl gencrl.c -lssl -lcrypto
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
#include <errno.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


#define OCSP_REVOKED_STATUS_NOSTATUS         -1
#define OCSP_REVOKED_STATUS_KEYCOMPROMISE     1
#define OCSP_REVOKED_STATUS_CACOMPROMISE      2
#define OCSP_REVOKED_STATUS_CERTIFICATEHOLD   6
#define OCSP_REVOKED_STATUS_REMOVEFROMCRL     8

#define DB_NUMBER   6
#define DB_name     5
#define DB_file     4
#define DB_serial   3
#define DB_rev_date 2
#define DB_exp_date 1
#define DB_type     0

#define BSIZE            256
#define SERIAL_RAND_BITS 64

#define BASE_SECTION          "ca"
#define ENV_DEFAULT_CA        "default_ca"
#define ENV_CRLNUMBER         "crlnumber"
#define ENV_DEFAULT_CRL_DAYS  "default_crl_days"
#define ENV_DEFAULT_CRL_HOURS "default_crl_hours"
#define ENV_DATABASE          "database"
#define ENV_DEFAULT_MD        "default_md"

static const char* crl_reasons[] = {
	/* CRL reason strings */
	"unspecified",
	"keyCompromise",
	"CACompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"certificateHold",
	"removeFromCRL",
	/* Additional pseudo reasons */
	"holdInstruction",
	"keyTime",
	"CAkeyTime"
};

#define NUM_REASONS (sizeof(crl_reasons) / sizeof(char *))

static CONF* load_conf(const char* config)
{
	long errorline = -1;
	CONF* conf = NCONF_new(NULL);
	assert(conf != NULL);

	if (NCONF_load(conf, config, &errorline) <= 0) {
		if (errorline <= 0) {
			fprintf(stderr, "error loading the config file '%s'\n", config);
			NCONF_free(conf);
			return NULL;
		}
	}

	return conf;
}

static int pkey_ctrl_string(EVP_PKEY_CTX* ctx, char* value)
{
	int rv;
	char* stmp, *vtmp = NULL;
	stmp = BUF_strdup(value);
	if (!stmp)
		return -1;
	vtmp = strchr(stmp, ':');
	if (vtmp) {
		*vtmp = 0; 
		vtmp++;
	}	
	rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
	OPENSSL_free(stmp);
	return rv;
}

static int do_sign_init(BIO* err, EVP_MD_CTX* ctx, EVP_PKEY* pkey,
			const EVP_MD* md, STACK_OF(OPENSSL_STRING)* sigopts)
{
	EVP_PKEY_CTX* pkctx = NULL;
	int i;
	EVP_MD_CTX_init(ctx);
	if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
		return 0;
	for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
		char* sigopt = sk_OPENSSL_STRING_value(sigopts, i);
		if (pkey_ctrl_string(pkctx, sigopt) <= 0) { 
			BIO_printf(err, "parameter error \"%s\"\n", sigopt);
			return 0;
		}	
	}	
	return 1;
}

static int do_X509_CRL_sign(BIO* err, X509_CRL* x, EVP_PKEY* pkey, const EVP_MD* md, 
					 STACK_OF(OPENSSL_STRING)* sigopts)
{
	int rv;
	EVP_MD_CTX mctx;
	EVP_MD_CTX_init(&mctx);
	rv = do_sign_init(err, &mctx, pkey, md, sigopts);
	if (rv > 0) 
		rv = X509_CRL_sign_ctx(x, &mctx);
	EVP_MD_CTX_cleanup(&mctx);
	return rv > 0 ? 1 : 0; 
}

static int rand_serial(BIGNUM* b, ASN1_INTEGER* ai)
{
	BIGNUM* btmp;
	int ret = 0;
	if (b)
		btmp = b;
	else
		btmp = BN_new();

	if (!btmp)
		return 0;

	if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
		goto err;
	if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
		goto err;

	ret = 1;

err:
	if (!b)
		BN_free(btmp);

	return ret;
}


static BIGNUM* load_serial(char* serialfile, int create, ASN1_INTEGER** retai)
{
	BIO* in = NULL;
	BIGNUM* ret = NULL;
	ASN1_INTEGER* ai = NULL;
	char buf[1024];

	ai = ASN1_INTEGER_new();
	if (ai == NULL)
		goto err; 

	if ((in = BIO_new(BIO_s_file())) == NULL) {
		goto err; 
	}	

	if (BIO_read_filename(in, serialfile) <= 0) { 
		if (!create) {
			perror(serialfile);
			goto err; 
		} else {
			ret = BN_new();
			if (ret == NULL || !rand_serial(ret, ai)) 
				fprintf(stderr, "Out of memory\n");
		}	
	} else {
		if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
			fprintf(stderr, "unable to load number from %s\n", serialfile);
			goto err; 
		}	
		ret = ASN1_INTEGER_to_BN(ai, NULL);
		if (ret == NULL) {
			fprintf(stderr, "error converting number from bin to BIGNUM\n");
			goto err; 
		}
	}

	if (ret && retai) {
		*retai = ai;
		ai = NULL;
	}	
 err: 
	BIO_free(in);
	if (ai != NULL)
		ASN1_INTEGER_free(ai);
	return ret;
}

static int save_serial(char* serialfile, char* suffix, BIGNUM* serial,
				ASN1_INTEGER** retai)
{
	char buf[1][BSIZE];
	BIO* out = NULL;
	int ret = 0;
	ASN1_INTEGER* ai = NULL;
	int j;

	if (suffix == NULL)
		j = strlen(serialfile);
	else
		j = strlen(serialfile) + strlen(suffix) + 1;
	if (j >= BSIZE) {
		fprintf(stderr, "file name too long\n");
		goto err;
	}

	if (suffix == NULL)
		BUF_strlcpy(buf[0], serialfile, BSIZE);
	else {
#ifndef OPENSSL_SYS_VMS
		j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, suffix);
#else
		j = BIO_snprintf(buf[0], sizeof buf[0], "%s-%s", serialfile, suffix);
#endif
	}
#ifdef RL_DEBUG
	fprintf(stderr, "DEBUG: writing \"%s\"\n", buf[0]);
#endif
	out = BIO_new(BIO_s_file());
	if (out == NULL) {
		goto err;
	}
	if (BIO_write_filename(out, buf[0]) <= 0) {
		perror(serialfile);
		goto err;
	}

	if ((ai = BN_to_ASN1_INTEGER(serial, NULL)) == NULL) {
		fprintf(stderr, "error converting serial to ASN.1 format\n");
		goto err;
	}
	i2a_ASN1_INTEGER(out, ai);
	BIO_puts(out, "\n");
	ret = 1;
	if (retai) {
		*retai = ai;
		ai = NULL;
	}

err:
	BIO_free_all(out);
	if (ai != NULL)
		ASN1_INTEGER_free(ai);
	return ret;
}

static int rotate_serial(char* serialfile, char* new_suffix, char* old_suffix)
{
	char buf[5][BSIZE];
	int i, j;

	i = strlen(serialfile) + strlen(old_suffix);
	j = strlen(serialfile) + strlen(new_suffix);
	if (i > j)
		j = i;
	if (j + 1 >= BSIZE) {
		fprintf(stderr, "file name too long\n");
		goto err;
	}
#ifndef OPENSSL_SYS_VMS
	j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, new_suffix);
#else
	j = BIO_snprintf(buf[0], sizeof buf[0], "%s-%s", serialfile, new_suffix);
#endif
#ifndef OPENSSL_SYS_VMS
	j = BIO_snprintf(buf[1], sizeof buf[1], "%s.%s", serialfile, old_suffix);
#else
	j = BIO_snprintf(buf[1], sizeof buf[1], "%s-%s", serialfile, old_suffix);
#endif
#ifdef RL_DEBUG
	fprintf(stderr, "DEBUG: renaming \"%s\" to \"%s\"\n",
			   serialfile, buf[1]);
#endif
	if (rename(serialfile, buf[1]) < 0 && errno != ENOENT
#ifdef ENOTDIR
		&& errno != ENOTDIR
#endif
		) {
		fprintf(stderr, "unable to rename %s to %s\n", serialfile, buf[1]);
		perror("reason");
		goto err;
	}
#ifdef RL_DEBUG
	fprintf(stderr, "DEBUG: renaming \"%s\" to \"%s\"\n", buf[0], serialfile);
#endif
	if (rename(buf[0], serialfile) < 0) {
		fprintf(stderr, "unable to rename %s to %s\n", buf[0], serialfile);
		perror("reason");
		rename(buf[1], serialfile);
		goto err;
	}
	return 1;
 err:
	return 0;
}


static int unpack_revinfo(ASN1_TIME** prevtm, int* preason, ASN1_OBJECT** phold,
				   ASN1_GENERALIZEDTIME** pinvtm, const char* str)
{
	char* tmp = NULL;
	char* rtime_str, *reason_str = NULL, *arg_str = NULL, *p;
	int reason_code = -1;
	int ret = 0;
	unsigned int i;
	ASN1_OBJECT* hold = NULL;
	ASN1_GENERALIZEDTIME* comp_time = NULL;
	tmp = BUF_strdup(str);

	if(!tmp) {
		fprintf(stderr, "memory allocation failure\n");
		goto err;
	}

	p = strchr(tmp, ',');
	rtime_str = tmp;

	if (p) {
		*p = '\0';
		p++;
		reason_str = p;
		p = strchr(p, ',');
		if (p) {
			*p = '\0';
			arg_str = p + 1;
		}
	}

	if (prevtm) {
		*prevtm = ASN1_UTCTIME_new();
		if(!*prevtm) {
			fprintf(stderr, "memory allocation failure\n");
			goto err;
		}
		if (!ASN1_UTCTIME_set_string(*prevtm, rtime_str)) {
			fprintf(stderr, "invalid revocation date %s\n", rtime_str);
			goto err;
		}
	}
	if (reason_str) {
		for (i = 0; i < NUM_REASONS; i++) {
			if (!strcasecmp(reason_str, crl_reasons[i])) {
				reason_code = i;
				break;
			}
		}
		if (reason_code == OCSP_REVOKED_STATUS_NOSTATUS) {
			fprintf(stderr, "invalid reason code %s\n", reason_str);
			goto err;
		}

		if (reason_code == 7)
			reason_code = OCSP_REVOKED_STATUS_REMOVEFROMCRL;
		else if (reason_code == 8) { /* Hold instruction */
			if (!arg_str) {
				fprintf(stderr, "missing hold instruction\n");
				goto err;
			}
			reason_code = OCSP_REVOKED_STATUS_CERTIFICATEHOLD;
			hold = OBJ_txt2obj(arg_str, 0);

			if (!hold) {
				fprintf(stderr, "invalid object identifier %s\n", arg_str);
				goto err;
			}
			if (phold)
				*phold = hold;
		} else if ((reason_code == 9) || (reason_code == 10)) {
			if (!arg_str) {
				fprintf(stderr, "missing compromised time\n");
				goto err;
			}
			comp_time = ASN1_GENERALIZEDTIME_new();
			if(!comp_time) {
				fprintf(stderr, "memory allocation failure\n");
				goto err;
			}
			if (!ASN1_GENERALIZEDTIME_set_string(comp_time, arg_str)) {
				fprintf(stderr, "invalid compromised time %s\n", arg_str);
				goto err;
			}
			if (reason_code == 9)
				reason_code = OCSP_REVOKED_STATUS_KEYCOMPROMISE;
			else
				reason_code = OCSP_REVOKED_STATUS_CACOMPROMISE;
		}
	}

	if (preason)
		*preason = reason_code;
	if (pinvtm)
		*pinvtm = comp_time;
	else
		ASN1_GENERALIZEDTIME_free(comp_time);

	ret = 1;

 err:
	if (tmp)
		OPENSSL_free(tmp);
	if (!phold)
		ASN1_OBJECT_free(hold);
	if (!pinvtm)
		ASN1_GENERALIZEDTIME_free(comp_time);

	return ret;
}


/*
 * Convert revocation field to X509_REVOKED entry
 * return code:
 * 0 error
 * 1 OK
 * 2 OK and some extensions added (i.e. V2 CRL)
 */
int make_revoked(X509_REVOKED* rev, const char* str)
{
	char* tmp = NULL;
	int reason_code = -1;
	int i, ret = 0; 
	ASN1_OBJECT* hold = NULL;
	ASN1_GENERALIZEDTIME* comp_time = NULL;
	ASN1_ENUMERATED* rtmp = NULL;

	ASN1_TIME* revDate = NULL;

	i = unpack_revinfo(&revDate, &reason_code, &hold, &comp_time, str);

	if (i == 0)
		goto err; 

	if (rev && !X509_REVOKED_set_revocationDate(rev, revDate))
		goto err; 

	if (rev && (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)) {
		rtmp = ASN1_ENUMERATED_new();
		if (!rtmp || !ASN1_ENUMERATED_set(rtmp, reason_code))
			goto err; 
		if (!X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, rtmp, 0, 0))
			goto err; 
	}	

	if (rev && comp_time) {
		if (!X509_REVOKED_add1_ext_i2d(rev, NID_invalidity_date, comp_time, 0, 0))
			goto err; 
	}	
	if (rev && hold) {
		if (!X509_REVOKED_add1_ext_i2d
			(rev, NID_hold_instruction_code, hold, 0, 0))
			goto err; 
	}	

	if (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)
		ret = 2; 
	else 
		ret = 1; 

err:
	if (tmp)
		OPENSSL_free(tmp);
	ASN1_OBJECT_free(hold);
	ASN1_GENERALIZEDTIME_free(comp_time);
	ASN1_ENUMERATED_free(rtmp);
	ASN1_TIME_free(revDate);

	return ret;
}

int main(int argc, char** argv)
{
	if (argc != 5 && argc != 6) {
		printf("usage: %s openssl.cnf cacert.pem cakey.pem crl.pem [passwd]\n", argv[0]);
		return -1;
	}

	OpenSSL_add_all_digests();

	long crldays = 0;
	long crlhours = 0;
	long crlsec = 0;

	/* need to be free */
	CONF* conf = NULL;
	X509* cacert = NULL;
	EVP_PKEY* pkey = NULL;
	X509_CRL* crl = NULL;
	ASN1_TIME* tmptm = NULL;
	BIO* sout = NULL;
	BIGNUM* crlnumber = NULL;


	BIGNUM* serial = NULL;

	char* index = NULL;
	char* md = NULL;
	char* section = NULL;
	char* crlnumberfile = NULL;
	const EVP_MD* dgst = NULL;


	/* load config */
	conf = load_conf(argv[1]);
	assert(conf != NULL);

	/* load cacert */
	cacert = X509_new();
	assert(cacert != NULL);
	FILE* f = fopen(argv[2], "r");
	assert(f != NULL);
	PEM_read_X509(f, &cacert, NULL, NULL);
	fclose(f);

	/* load cakey */
	pkey = EVP_PKEY_new();
	assert(pkey != NULL);
	f = fopen(argv[3], "r");
	assert(f != NULL);
	if (argc == 6) {
		PEM_read_PrivateKey(f, &pkey, NULL, argv[5]);
	} else {
		PEM_read_PrivateKey(f, &pkey, NULL, NULL);
	}
	fclose(f);


	section = NCONF_get_string(conf, BASE_SECTION, ENV_DEFAULT_CA);
	assert(section != NULL);

	crlnumberfile = NCONF_get_string(conf, section, ENV_CRLNUMBER);
	assert(crlnumberfile);

	crlnumber = load_serial(crlnumberfile, 0, NULL);
	assert(crlnumber);

	if (!NCONF_get_number(conf, section, ENV_DEFAULT_CRL_DAYS, &crldays))
		crldays = 0;

	if (!NCONF_get_number(conf, section, ENV_DEFAULT_CRL_HOURS, &crlhours))
		crlhours = 0;
	
	assert((crldays > 0) || (crlhours > 0) || (crlsec > 0));

	crl = X509_CRL_new();
	assert(crl != NULL);

	assert(X509_CRL_set_issuer_name(crl, X509_get_subject_name(cacert)) > 0);

	tmptm = ASN1_TIME_new();
	assert(tmptm != NULL);
	X509_gmtime_adj(tmptm, 0);
	X509_CRL_set_lastUpdate(crl, tmptm);
	assert(X509_time_adj_ex(tmptm, crldays, crlhours * 60 * 60 + crlsec, NULL) > 0);
	X509_CRL_set_nextUpdate(crl, tmptm);


	/*
	 * Read every serial number from `index.txt` and create a 
	 * X509_REVOKED: r with serial number, and insert r to CRL.
	 * TODO: If there's already a CRL, how to update it?
	 */
	index = NCONF_get_string(conf, section, ENV_DATABASE);
	assert(index != NULL);
	FILE* f1 = fopen(index, "r");
	assert(f1 != NULL);

	char line[512];
	while (fgets(line, 512, f1)) {
		if (line[0] != 'R')
			continue;

		char fileds[6][64];
		char* sep = "\t";
		char* token;
		int k = 0;
		char* p = line;
		while ((token = strsep(&p, sep)) != NULL) {
			strcpy(fileds[k++], token);
		}

		X509_REVOKED* r = X509_REVOKED_new();
		assert(r != NULL);

		assert(make_revoked(r, fileds[DB_rev_date]) > 0);
		assert(BN_hex2bn(&serial, fileds[DB_serial]) > 0);

		ASN1_INTEGER* tmpser = BN_to_ASN1_INTEGER(serial, NULL);
		BN_free(serial);
		serial = NULL;
		assert(tmpser != NULL);
		X509_REVOKED_set_serialNumber(r, tmpser);
		ASN1_INTEGER_free(tmpser);
		X509_CRL_add0_revoked(crl, r);
	}

	X509_CRL_sort(crl);

	assert(save_serial(crlnumberfile, "new", crlnumber, NULL) > 0);
	assert(rotate_serial(crlnumberfile, "new", "old") > 0);

	md = NCONF_get_string(conf, section, ENV_DEFAULT_MD);
	assert(md != NULL);

	if (strcmp(md, "default") == 0) {
		int def_nid;
		assert(EVP_PKEY_get_default_digest_nid(pkey, &def_nid) > 0);
		md = (char *)OBJ_nid2sn(def_nid);
	}

	dgst = EVP_get_digestbyname(md);
	if (dgst == NULL) {
		fprintf(stderr, "%s is an unsupported message digest type\n", md);
		exit(-1);
	}

	assert(do_X509_CRL_sign(NULL, crl, pkey, dgst, NULL) > 0);

	sout = BIO_new(BIO_s_file());
	assert(sout != NULL);

	BIO_write_filename(sout, argv[4]);
	PEM_write_bio_X509_CRL(sout, crl);


	/* free */
	NCONF_free(conf);
	X509_free(cacert);
	EVP_PKEY_free(pkey);
	X509_CRL_free(crl);
	ASN1_TIME_free(tmptm);
	BIO_free(sout);
	BN_free(crlnumber);

	return 0;
}

