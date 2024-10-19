/* NOCW */
/* cc -o ssdemo -I../include selfsign.c ../libcrypto.a */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

int mkit(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days, time_t *in_tm, const char * domain);

/*-- wuzh modify 2008-4-21 --*/
#if 0
 static const char keyfile[] = "/tmp/privkeySrv.pem";
 static const char certfile[] = "/tmp/certSrv.pem";
#else
 static const char keyfile[] = "/tmp/key.pem";
 static const char certfile[] = "/tmp/cert.pem";
#endif

//Zhijian add usage
void usage()
{
	printf("\tUsage: selfsign domain\n\n");
}

int main(int argc, char ** argv)
	{
	BIO *bio_err;
	X509 *x509=NULL;
	EVP_PKEY *pkey=NULL;
	FILE *fp;
	//add by michael to fix the https can't be used at firefox 3.5.2 on Windows Vista Ultimate OS at 20090821
	unsigned int serial;
	struct tm stm;
	time_t ttm;

	if(argc != 2)
	{
		usage();
		return -1;
	}
	{
		int fd = -1;
		int seed;
		fd = open("dev/urandom", 0);
		if(fd < 0 || read(fd,&seed,sizeof(seed)) < 0 )
		{
			seed = time(0);
		}
		if(fd >0) close(fd);
		srand(seed);
		serial = rand();
	}

	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);

	//add by michael to fix the https can't be used at firefox 3.5.2 on Windows Vista Ultimate OS at 20090821
	//mkit(&x509,&pkey,512,0,365);

	//Zhijian set valid date to 2010.10.10 10:10:10
	stm.tm_year = 2010;
	stm.tm_mon = 10;
	stm.tm_mday = 10;
	stm.tm_hour = 10;
	stm.tm_min = 10;
	stm.tm_sec = 10;

	stm.tm_year -= 1900;
	stm.tm_mon --;
	stm.tm_isdst=-1;
	
	ttm = mktime(&stm);
	
	//Zhijian make our domain be trusted
	mkit(&x509,&pkey,512,serial, 5 * 365 * 24 * 60 * 60, &ttm, argv[1]);

	RSA_print_fp(stdout,pkey->pkey.rsa,0);
	X509_print_fp(stdout,x509);

	fp = fopen(keyfile, "w");
	if(fp != NULL)
	{
		PEM_write_PrivateKey(fp,pkey,NULL,NULL,0,NULL, NULL);
		fclose(fp);
	}
	else
	PEM_write_PrivateKey(stdout,pkey,NULL,NULL,0,NULL, NULL);
	fp = fopen(certfile, "w");
	if(fp != NULL)
	{
		PEM_write_X509(fp,x509);
		fclose(fp);
	}
	else
	PEM_write_X509(stdout,x509);

	X509_free(x509);
	EVP_PKEY_free(pkey);

#ifdef CUSTOM_EXT
	/* Only needed if we add objects or custom extensions */
	X509V3_EXT_cleanup();
	OBJ_cleanup();
#endif

	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);
	return(0);
	}

#ifdef WIN16
#  define MS_CALLBACK   _far _loadds
#  define MS_FAR        _far
#else
#  define MS_CALLBACK
#  define MS_FAR
#endif

static void MS_CALLBACK callback(p, n, arg)
int p;
int n;
void *arg;
	{
	char c='B';

	if (p == 0) c='.';
	if (p == 1) c='+';
	if (p == 2) c='*';
	if (p == 3) c='\n';
	fputc(c,stderr);
	}

//Zhijian add parameter for trusted domain and begin date
int mkit(x509p,pkeyp,bits,serial,days, in_tm, domain)
X509 **x509p;
EVP_PKEY **pkeyp;
int bits;
int serial;
int days;
time_t *in_tm;
const char * domain;
	{
	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name=NULL;
	X509_EXTENSION *ex=NULL;

	
	if ((pkeyp == NULL) || (*pkeyp == NULL))
		{
		if ((pk=EVP_PKEY_new()) == NULL)
			{
			abort(); 
			return(0);
			}
		}
	else
		pk= *pkeyp;

	if ((x509p == NULL) || (*x509p == NULL))
		{
		if ((x=X509_new()) == NULL)
			goto err;
		}
	else
		x= *x509p;

	rsa=RSA_generate_key(bits,RSA_F4,callback,NULL);
	if (!EVP_PKEY_assign_RSA(pk,rsa))
		{
		abort();
		goto err;
		}
	rsa=NULL;

	/*-- wuzh modify 2008-4-21 --*/
#if 0
	X509_set_version(x,3);
#else
	X509_set_version(x,2);
#endif
	ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
#if 0
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)days);
#else
	X509_time_adj(X509_get_notBefore(x),0, in_tm);
	X509_time_adj(X509_get_notAfter(x),(long)days, in_tm);
#endif
	X509_set_pubkey(x,pk);

	name=X509_get_subject_name(x);

	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
#if 0
	X509_NAME_add_entry_by_txt(name,"C",
				MBSTRING_ASC, "UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"CN",
				MBSTRING_ASC, "OpenSSL Group", -1, -1, 0);
#else
	X509_NAME_add_entry_by_txt(name,"C",
				MBSTRING_ASC, "US", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"CN",
				MBSTRING_ASC, domain ? domain : "Linksys", -1, -1, 0);
	
	//wuzh add 2008-4-21
	X509_NAME_add_entry_by_txt(name,"E",
				MBSTRING_ASC, "support@linksys.com", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"OU",
				MBSTRING_ASC, "Division", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"O",
				MBSTRING_ASC, "Cisco-Linksys,LCC", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"L",
				MBSTRING_ASC, "Irvine", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name,"ST",
				MBSTRING_ASC, "California", -1, -1, 0);
#endif
	X509_set_issuer_name(x,name);

	/* Add extension using V3 code: we can set the config file as NULL
	 * because we wont reference any other sections. We can also set
         * the context to NULL because none of these extensions below will need
	 * to access it.
	 */
#if 0  //wuzh delete these
	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, "server");
	X509_add_ext(x,ex,-1);
	X509_EXTENSION_free(ex);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment,
						"server for cert");
	X509_add_ext(x,ex,-1);
	X509_EXTENSION_free(ex);

	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_ssl_server_name,
							"www.linksys.com");
#endif
	X509_add_ext(x,ex,-1);
	X509_EXTENSION_free(ex);

#if 0
	/* might want something like this too.... */
	ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
							"critical,CA:TRUE");


	X509_add_ext(x,ex,-1);
	X509_EXTENSION_free(ex);
#endif

#ifdef CUSTOM_EXT
	/* Maybe even add our own extension based on existing */
	{
		int nid;
		nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		ex = X509V3_EXT_conf_nid(NULL, NULL, nid,
						"example comment alias");
		X509_add_ext(x,ex,-1);
		X509_EXTENSION_free(ex);
	}
#endif
	
	if (!X509_sign(x,pk,EVP_md5()))
		goto err;

	*x509p=x;
	*pkeyp=pk;
	return(1);
err:
	return(0);
	}
