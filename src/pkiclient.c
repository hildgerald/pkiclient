/*
 * pkiclient
 * client for getting certificate with scep and est protocol
 * 
 * This work is based on the folowing project :
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* Main routine */
#include <syslog.h>
#include "pkiclient.h"
#include "scep/scep_actions.h"
#include "est/est_actions.h"

char *pname;
int timeout;

/* configuration options, defined in cmd.h */
int a_flag_PATH_Trust_Anchor;
char * a_char_PATH_Trust_Anchor;
int c_flag;
char *c_char_CA_certificate;
int C_flag;
char *C_char_CA_certificate_chain;
//int v_flag > 1;
int e_flag;
char *e_char_CA_encryption_certificate;
char *E_char_encryption_algorythm;
int E_flag;
int f_flag;
char *f_char_configuration_file;
char *F_char_fingerprint_algorythm;
int F_flag;
char *g_char;
#ifdef WITH_ENGINES
int g_flag;
#endif
//int h_flag;
//int H_flag;
int j_flag;
char *l_char_local_certificate;
int l_flag;
char *L_char_local_self_signed_certificate;
int L_flag;
char *i_char_CA_identifier;
int i_flag;
char *k_char_private_key;
int k_flag;
char *K_char_Private_key_of_already_existing_certificate;
int K_flag;
int m_flag;
char *m_char_test_mode;
int M_flag;
char *M_char_Monitor_Information_HTTP_get_parameter_style;
int n_flag;
int n_num_Request_count;
char *O_char_Already_existing_certificate;
int O_flag;
char *p_char_proxy;
int p_flag;
int P_flag_fingerprint_filename;
char *P_char_fingerprint_filename;
char *r_char_Certificate_request_file;
int r_flag;
int R_flag;
char *s_char_Certificate_serial_number;
int s_flag;
char *S_char_Signature_algorithm;
int S_flag;
int t_num_Polling_interval;
int t_flag;
int T_num_MAX_Polling_interval;
int T_flag;
int u_flag;
char *url_char;
int v_flag;
int w_flag;
char *w_char_GetCert_certificate;
int W_flag;
int x_flag;
char *x_char_certificate_template_filename;

int operation_flag;
int protocol_flag;

const EVP_MD *fp_alg;
const EVP_MD *sig_alg;
const EVP_CIPHER *enc_alg;

//struct stConfig pkiclientconfiguration = {0};



/**
 * @fn		const EVP_CIPHER *get_cipher_alg(const char *arg, int ca_caps)
 * @brief	 Cette fonction permet de choisir l'algorithme de chiffrement
 * 			en fonction des capacités du serveur
 * @param 	arg	const char * : valeur par défaut à appliquer
 * @param 	ca_caps int : capacité du serveur
 * @return	const EVP_CIPHER * : pointeur vers la fonction de chiffrement adoptée. NULL si pas trouvé
 */
const EVP_CIPHER *get_cipher_alg(const char *arg, int ca_caps)
{
#if 0
	// Methode d'origine de sscep pour choisir l'algorythme
	// celui passé en parametre est celui choisi par sscep
	if (!arg) {
		if (SUP_CAP_AES(ca_caps))
			return EVP_aes_128_cbc();
		else if (SUP_CAP_3DES(ca_caps))
			return EVP_des_ede3_cbc();
		else
			return EVP_des_cbc();
	} else if (!strncmp(arg, "blowfish", 8)) {
		return EVP_bf_cbc();
	} else if (!strncmp(arg, "des", 3)) {
		return EVP_des_cbc();
	} else if (!strncmp(arg, "3des", 4)) {
		return EVP_des_ede3_cbc();
	} else if (!strncmp(arg, "aes128", 6)) {
		return EVP_aes_128_cbc();
	} else if (!strncmp(arg, "aes192", 6)) {
		return EVP_aes_192_cbc();
	} else if (!strncmp(arg, "aes256", 6)) {
		return EVP_aes_256_cbc();
	} else if (!strncmp(arg, "aes", 3)) {
		/* per RFC8894 "AES" represents "AES128-CBC" */
		return EVP_aes_128_cbc();
	} else {
		return NULL;
	}
#endif
	// Methode du best cipher
	if (SUP_CAP_AES(ca_caps))
	{
		if (v_flag)
		{
			fprintf(stdout, "%s: The best cipher in the reply of the server is aes256\n", pname);
		}
		return EVP_aes_256_cbc();
	}
	else if (SUP_CAP_3DES(ca_caps))
	{
		if (v_flag)
		{
			fprintf(stdout, "%s: The best cipher in the reply of the server is 3des\n", pname);
		}
		return EVP_des_ede3_cbc();
	}
	else
	{
		// L'algorithme n'apparait pas dans le retour, on prend celui transmi
		if (!arg) {
			if (SUP_CAP_AES(ca_caps))
			{
				if (v_flag)
				{
					fprintf(stdout, "%s: The best cipher in the reply of the server is aes128\n", pname);
				}
				return EVP_aes_128_cbc();
			}
			else if (SUP_CAP_3DES(ca_caps))
			{
				if (v_flag)
				{
					fprintf(stdout, "%s: The best cipher in the reply of the server is 3des\n", pname);
				}
				return EVP_des_ede3_cbc();
			}
			else
			{
				if (v_flag)
				{
					fprintf(stdout, "%s: The cipher by default is des\n", pname);
				}
				return EVP_des_cbc();
			}
		}	if (!strncmp(arg, "blowfish", 8)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is blowfish\n", pname);
			}
			return EVP_bf_cbc();
		} else if (!strncmp(arg, "des", 3)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is des\n", pname);
			}
			return EVP_des_cbc();
		} else if (!strncmp(arg, "3des", 4)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is 3des\n", pname);
			}
			return EVP_des_ede3_cbc();
		} else if (!strncmp(arg, "aes128", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is aes128\n", pname);
			}
			return EVP_aes_128_cbc();
		} else if (!strncmp(arg, "aes192", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is aes192\n", pname);
			}
			return EVP_aes_192_cbc();
		} else if (!strncmp(arg, "aes256", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is aes256\n", pname);
			}
			return EVP_aes_256_cbc();
		} else if (!strncmp(arg, "aes", 3)) {
			/* per RFC8894 "AES" represents "AES128-CBC" */
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is aes (aes128)\n", pname);
			}
			return EVP_aes_128_cbc();
		} else if (!strncmp(arg, "DES3", 4)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is 3des\n", pname);
			}
			return EVP_des_ede3_cbc();
		} else if (!strncmp(arg, "AES-128", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is aes128\n", pname);
			}
			return EVP_aes_128_cbc();
		} else if (!strncmp(arg, "AES-192", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is aes192\n", pname);
			}
			return EVP_aes_192_cbc();
		} else if (!strncmp(arg, "AES-256", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is aes256\n", pname);
			}
			return EVP_aes_256_cbc();
		} else if (!strncmp(arg, "AES", 3)) {
			/* per RFC8894 "AES" represents "AES128-CBC" */
			if (v_flag)
			{
				fprintf(stdout, "%s: The cipher select in command line is aes (aes128)\n", pname);
			}
			return EVP_aes_128_cbc();
		} else {
			if (v_flag)
			{
				fprintf(stdout, "%s: No cipher select in command line and CA capabilities\n", pname);
			}
			return NULL;
		}
	}
}

/**
 * @fn		const EVP_MD *get_digest_alg(const char *arg, int ca_caps)
 * @brief	Cette fonction permet de choisir la meilleur capacité de signature
 * @param 	arg	const char * : valeur par défaut à appliquer
 * @param 	ca_caps int : capacité du serveur
 * @return	const EVP_MD * : pointeur vers la fonction de hash adoptée. NULL si pas trouvé
 */
const EVP_MD *get_digest_alg(const char *arg, int ca_caps)
{
	if (!arg) {
		if (SUP_CAP_SHA_512(ca_caps))
		{
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 512\n", pname);
			}
			return EVP_sha512();
		}
		else if (SUP_CAP_SHA_384(ca_caps)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 384\n", pname);
			}
			return EVP_sha384();
		}
		else if (SUP_CAP_SHA_256(ca_caps)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 256\n", pname);
			}
			return EVP_sha256();
		}
		else if (SUP_CAP_SHA_224(ca_caps)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 224\n", pname);
			}
			return EVP_sha224();
		}
		else if (SUP_CAP_SHA_1(ca_caps)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 1\n", pname);
			}
			return EVP_sha1();
		}
		else
		{
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest selected in command line is md5\n", pname);
			}
			return EVP_md5();
		}
	} else if (!strncmp(arg, "md5", 3)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is md5\n", pname);
		}
		return EVP_md5();
	} else if (!strncmp(arg, "sha1", 4)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA 1\n", pname);
		}
		return EVP_sha1();
	} else if (!strncmp(arg, "sha224", 6)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA 224\n", pname);
		}
		return EVP_sha224();
	} else if (!strncmp(arg, "sha256", 6)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA 256\n", pname);
		}
		return EVP_sha256();
	} else if (!strncmp(arg, "sha384", 6)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA 384\n", pname);
		}
		return EVP_sha384();
	} else if (!strncmp(arg, "sha512", 6)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA512\n", pname);
		}
		return EVP_sha512();
	}
    else if (!strncmp(arg, "MD5", 3)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is md5\n", pname);
		}
		return EVP_md5();
	} else if (!strncmp(arg, "SHA-1", 5)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA 1\n", pname);
		}
		return EVP_sha1();
	} else if (!strncmp(arg, "SHA-224", 7)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA 224\n", pname);
		}
		return EVP_sha224();
	} else if (!strncmp(arg, "SHA-256", 7)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA 256\n", pname);
		}
		return EVP_sha256();
	} else if (!strncmp(arg, "SHA-384", 7)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA 384\n", pname);
		}
		return EVP_sha384();
	} else if (!strncmp(arg, "SHA-512", 7)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest selected in command line is SHA512\n", pname);
		}
		return EVP_sha512();
	} else {
		if (v_flag)
		{
			fprintf(stdout, "%s: No digest selected in command line and server capabilities\n", pname);
		}
		return NULL;
	}
}

/**
 * @fn		const EVP_MD *get_digest_best_alg(const char *arg, int ca_caps)
 * @brief	Cette fonction permet de choisir la meilleur capacité de signature
 * @param 	arg	const char * : valeur par défaut à appliquer
 * @param 	ca_caps int : capacité du serveur
 * @return	const EVP_MD * : pointeur vers la fonction de hash adoptée. NULL si pas trouvé
 */
const EVP_MD *get_digest_best_alg(const char *arg, int ca_caps)
{
#if 0
	// Ancienne méthode de sscep
	if (!arg) {
		if (SUP_CAP_SHA_512(ca_caps))
			return EVP_sha512();
		else if (SUP_CAP_SHA_384(ca_caps))
			return EVP_sha384();
		else if (SUP_CAP_SHA_256(ca_caps))
			return EVP_sha256();
		else if (SUP_CAP_SHA_224(ca_caps))
			return EVP_sha224();
		else if (SUP_CAP_SHA_1(ca_caps))
			return EVP_sha1();
		else
			return EVP_md5();
	} else if (!strncmp(arg, "md5", 3)) {
		return EVP_md5();
	} else if (!strncmp(arg, "sha1", 4)) {
		return EVP_sha1();
	} else if (!strncmp(arg, "sha224", 6)) {
		return EVP_sha224();
	} else if (!strncmp(arg, "sha256", 6)) {
		return EVP_sha256();
	} else if (!strncmp(arg, "sha384", 6)) {
		return EVP_sha384();
	} else if (!strncmp(arg, "sha512", 6)) {
		return EVP_sha512();
	} else {
		return NULL;
	}
#endif
	if (SUP_CAP_SHA_512(ca_caps)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The best digest select by server scep capabilities is SHA 512\n", pname);
		}
		return EVP_sha512();
	}
	else if (SUP_CAP_SHA_384(ca_caps)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 384\n", pname);
		}
		return EVP_sha384();
	}
	else if (SUP_CAP_SHA_256(ca_caps)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 256\n", pname);
		}
		return EVP_sha256();
	}
	else if (SUP_CAP_SHA_224(ca_caps)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 224\n", pname);
		}
		return EVP_sha224();
	}
	else if (SUP_CAP_SHA_1(ca_caps)) {
		if (v_flag)
		{
			fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 1\n", pname);
		}
		return EVP_sha1();
	}
	else
	{
		if (!arg) {
			if (SUP_CAP_SHA_512(ca_caps)) {
				if (v_flag)
				{
					fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 512\n", pname);
				}
				return EVP_sha512();
			}
			else if (SUP_CAP_SHA_384(ca_caps)) {
				if (v_flag)
				{
					fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 384\n", pname);
				}
				return EVP_sha384();
			}
			else if (SUP_CAP_SHA_256(ca_caps)) {
				if (v_flag)
				{
					fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 256\n", pname);
				}
				return EVP_sha256();
			}
			else if (SUP_CAP_SHA_224(ca_caps)) {
				if (v_flag)
				{
					fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 224\n", pname);
				}
				return EVP_sha224();
			}
			else if (SUP_CAP_SHA_1(ca_caps)) {
				if (v_flag)
				{
					fprintf(stdout, "%s: The digest select by server scep capabilities is SHA 1\n", pname);
				}
				return EVP_sha1();
			}
			else
			{
				if (v_flag)
				{
					fprintf(stdout, "%s: The digest select by default is md5\n", pname);
				}
				return EVP_md5();
			}
		} else	if (!strncmp(arg, "md5", 3)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is md5\n", pname);
			}
			return EVP_md5();
		} else if (!strncmp(arg, "sha1", 4)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 1\n", pname);
			}
			return EVP_sha1();
		} else if (!strncmp(arg, "sha224", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 224\n", pname);
			}
			return EVP_sha224();
		} else if (!strncmp(arg, "sha256", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 256\n", pname);
			}
			return EVP_sha256();
		} else if (!strncmp(arg, "sha384", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 384\n", pname);
			}
			return EVP_sha384();
		} else if (!strncmp(arg, "sha512", 6)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 512\n", pname);
			}
			return EVP_sha512();
		} else if (!strncmp(arg, "MD5", 3)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is MD5\n", pname);
			}
			return EVP_md5();
		} else if (!strncmp(arg, "SHA-1", 5)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 1\n", pname);
			}
			return EVP_sha1();
		} else if (!strncmp(arg, "SHA-224", 7)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 224\n", pname);
			}
			return EVP_sha224();
		} else if (!strncmp(arg, "SHA-256", 7)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 256\n", pname);
			}
			return EVP_sha256();
		} else if (!strncmp(arg, "SHA-384", 7)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 384\n", pname);
			}
			return EVP_sha384();
		} else if (!strncmp(arg, "SHA-512", 7)) {
			if (v_flag)
			{
				fprintf(stdout, "%s: The digest select by command line is SHA 512\n", pname);
			}
			return EVP_sha512();
		} else {
			if (v_flag)
			{
				fprintf(stdout, "%s: No digest select by command line and capabilities\n", pname);
			}
			return NULL;
		}
	}

}

/**
 * @fn		static char *handle_serial (char * serial)
 * @brief	Convert serial to a decimal serial when input is a hexidecimal
 * 			representation of the serial
 * @param	*serial : char
 * @return  char* : pointeur sur la chaine de caractère du numéro de série convertie
 */
static char *handle_serial (char *serial)
{
	int hex = NULL != strchr (serial, ':');

	/* Convert serial to a decimal serial when input is
	   a hexidecimal representation of the serial */
	if (hex)
	{
		unsigned int i,ii;
		char *tmp_serial = (char*) calloc (strlen (serial) + 1,1);

		for (i=0,ii=0; '\0'!=serial[i];i++)
		{
			if (':'!=serial[i])
				tmp_serial[ii++]=serial[i];
		}
		serial=tmp_serial;
	}
	else
	{
		unsigned int i;
		for (i=0; ! hex && '\0' != serial[i]; i++)
			hex = 'a'==serial[i]||'b'==serial[i]||'c'==serial[i]||'d'==serial[i]||'e'==serial[i]||'f'==serial[i];
	}

	if (hex)
	{
		ASN1_INTEGER* ai;
 		BIGNUM *ret;
 		BIO* in = BIO_new_mem_buf(serial, -1);
  		char buf[1025];
  		ai=ASN1_INTEGER_new();
  		if (ai == NULL) return NULL;
   		if (!a2i_ASN1_INTEGER(in,ai,buf,1024))
   		{
			return NULL;
   		}
   		ret=ASN1_INTEGER_to_BN(ai,NULL);
   		if (ret == NULL)
   		{
			return NULL;
   		}
   		else
   		{
    		 serial = BN_bn2dec(ret);
   		}
  	}

	return serial;
} /* handle_serial */

/**
 * @fn		int check_cmd_parameter()
 * @return  int: 0 if no error; !=0 if error
 */
int check_cmd_parameter()
{
	int ret = 0;

	if(f_char_configuration_file){
		scep_conf_init(f_char_configuration_file, operation_flag);
	}else{
		scep_conf = NULL;    //moved init to here otherwise compile error on windows
	}

	if (v_flag)
		fprintf(stdout, "%s: starting pkiclient, version %s\n",	pname, VERSION);


	/*
	 * Check argument logic.
	 */
	if (!c_flag && operation_flag != SCEP_OPERATION_GETCAPS) {
		if (operation_flag == SCEP_OPERATION_GETCA) {
			//fprintf(stderr,"%s: missing CA certificate filename (-c)\n", pname);
			error("missing CA certificate filename (-c)");
			return (SCEP_PKISTATUS_ERROR);
		} else {
			//fprintf(stderr,"%s: missing CA certificate (-c)\n", pname);
			error("missing CA certificate (-c)");
			return (SCEP_PKISTATUS_ERROR);
		}
		if (operation_flag == SCEP_OPERATION_GETNEXTCA) {
			//fprintf(stderr,"%s: missing nextCA certificate target filename (-c)\n", pname);
			error("missing nextCA certificate target filename(-c)");
			return (SCEP_PKISTATUS_ERROR);
		} else {
			//fprintf(stderr,"%s: missing nextCA certificate target filename(-c)\n", pname);
			error("missing nextCA certificate target filename(-c)");
			return (SCEP_PKISTATUS_ERROR);
		}
	}
	if (!C_flag) {
		if (operation_flag == SCEP_OPERATION_GETNEXTCA) {
			//fprintf(stderr,"%s: missing nextCA certificate chain filename (-C)\n", pname);
			error("missing nextCA certificate chain filename (-C)");
			return (SCEP_PKISTATUS_ERROR);
		}
	}
	if (operation_flag == SCEP_OPERATION_ENROLL) {
		if (!k_flag) {
			//fprintf(stderr, "%s: missing private key (-k)\n",pname);
			error("missing private key (-k)");
			return (SCEP_PKISTATUS_ERROR);
		}
		if (!r_flag) {
			//fprintf(stderr, "%s: missing request (-r)\n",pname);
			error("missing request (-r)");
			return (SCEP_PKISTATUS_ERROR);

		}
		if (!l_flag) {
			//fprintf(stderr, "%s: missing local cert (-l)\n",pname);
			error("missing local cert (-l)");
			return (SCEP_PKISTATUS_ERROR);
		}
		/* Set polling limits */
		if (!n_flag)
			n_num_Request_count = MAX_POLL_COUNT;
		if (!t_flag)
			t_num_Polling_interval = POLL_TIME;
		if (!T_flag)
			T_num_MAX_Polling_interval = MAX_POLL_TIME;
	}
	if (operation_flag == SCEP_OPERATION_GETCERT) {
		if (!l_flag) {
			//fprintf(stderr, "%s: missing local cert (-l)\n",pname);
			error("missing local cert (-l)");
			return (SCEP_PKISTATUS_ERROR);
		}
		if (!s_flag) {
			//fprintf(stderr, "%s: missing serial no (-s)\n", pname);
			error("missing serial no (-s)");
			return (SCEP_PKISTATUS_ERROR);
		}
		if (!w_flag) {
			//fprintf(stderr, "%s: missing cert file (-w)\n",pname);
			error("missing cert file (-w)");
			return (SCEP_PKISTATUS_ERROR);
		}
		if (!k_flag) {
			//fprintf(stderr, "%s: missing private key (-k)\n",pname);
			error("missing private key (-k)");
			return (SCEP_PKISTATUS_ERROR);
		}
	}
	if (operation_flag == SCEP_OPERATION_GETCRL) {
		if (!l_flag) {
			//fprintf(stderr, "%s: missing local cert (-l)\n",pname);
			error("missing local cert (-l)");
			return (SCEP_PKISTATUS_ERROR);
		}
		if (!w_flag) {
			//fprintf(stderr, "%s: missing crl file (-w)\n",pname);
			error("missing crl file (-w)");
			return (SCEP_PKISTATUS_ERROR);
		}
		if (!k_flag) {
			//fprintf(stderr, "%s: missing private key (-k)\n",pname);
			error("missing private key (-k)");
			return (SCEP_PKISTATUS_ERROR);
		}
	}

	/* Break down the URL */
	if (!u_flag) {
		//fprintf(stderr, "%s: missing URL (-u)\n", pname);
		error("missing URL (-u)");
		return (SCEP_PKISTATUS_ERROR);
	}

	if (protocol_flag == PROTOCOL_EST)
	{
		if (strncmp(url_char, "https://", 8) && !p_flag)
		{
			//fprintf(stderr, "%s: illegal URL %s\n", pname, url_char);
			error("illegal URL %s", pname, url_char);
			return (SCEP_PKISTATUS_ERROR);
		}
	} else
	{
		if (strncmp(url_char, "http://", 7) && !p_flag)
		{
			//fprintf(stderr, "%s: illegal URL %s\n", pname, url_char);
			error("illegal URL %s", pname, url_char);
			return (SCEP_PKISTATUS_ERROR);
		}
	}

	return (ret);
}

/**
 * @fn
 * @brief	Cette fonction permet de convertir l'url en hostname, repertoire et
 * 			port de connexion. l'url est préalablement mise dans hostname
 * @param 	host_name
 * @param 	dir_name
 * @param 	host_port
 */
void hostname2dirname_port(char *h_name, char **d_name, int *h_port)
{
	char *p;
	int c;
	int cnt;

	p = h_name;
	c = 0;
	cnt =0;
	while (*p != '\0') {
		if (*p == '/' && !p_flag && !c) {
			*p = '\0';
			if (*(p+1)) *d_name = p + 1;
			c = 1;
		}
		if (*p == '[') { //For IPv6 starts from here
			*d_name =  (p+1);
			h_name = *d_name;
			while (*p != '\0') {
				if (*p == ']') {
					*p = '\0';
					if (*(p+1) == ':') {
						*(p+1)  = '\0';
						*h_port = atoi(p+2);
					}
				}
				p++;
			}
		} else {
			if (!cnt && !p_flag && !c) {
				*d_name = p;
				cnt = 1;
			}
			if (*p == ':') {
				*p = '\0';
				if (*(p+1)) *h_port = atoi(p+1);
			}
		}
		p++;
	}
}

/**
 * @fn		int ping(char * domain)
 * @brief	Cette fonction envoit un ping à l'adresse de domaine
 * @param 	domain char *: pointeur sur le nom de domaine à interroger
 * @return int : retourne 0 si le ping n'a pas abouti et 1 si c'est OK
 */
int ping(char * domain)
{
	int rc;
	char cmd[1024] = {0};
	snprintf(cmd, sizeof(cmd), "ping -w 30 -c 5 %s", domain);
	rc = system(cmd);
	rc = WEXITSTATUS(rc);
	if (rc != 0)
	{
		rc = 0; // le ping ne s'est pas bien passé
		if (v_flag)
		{
			//fprintf(stderr, "%s: The scep server is NOK\n", pname);
			error("The scep server is NOK");
		}
	}
	else
	{
		rc = 1; // Le ping est OK
		if (v_flag)
		{
			//fprintf(stdout, "%s: The scep server is OK\n", pname);
			notice("The scep server is OK");
		}
	}
	return(rc);
}

/**
 * @fn		int main(int argc, char **argv)
 * @brief	Fonction principale du programme
 * @param	argc int : indisque le nombre d'argument
 * @param 	**argv char : pointeurs sur les differents arguments
 * @return  int : code d'erreur =0 si OK
 */
int main(int argc, char **argv) {
	//ENGINE *e = NULL;
	int	ret;
	int	c;
	int host_port = 80;

	char *host_name;
	char *dir_name = NULL;
	struct http_reply	reply;

	struct scep	scep_t= {0};

	size_t required_option_space;
	int ca_caps = 0;
	int pkistatus = 0;
	char str[1024] = {0};


#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
	//printf("Starting sscep\n");
	//fprintf(stdout, "%s: starting sscep on WIN32, sscep version %s\n",	pname, VERSION);
       
	wVersionRequested = MAKEWORD( 2, 2 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 )
	{
	  /* Tell the user that we could not find a usable */
	  /* WinSock DLL.                                  */
	  return;
	}
 
	/* Confirm that the WinSock DLL supports 2.2.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.2 in addition to 2.2, it will still return */
	/* 2.2 in wVersion since that is the version we      */
	/* requested.                                        */
 
	if ( LOBYTE( wsaData.wVersion ) != 2 ||
	        HIBYTE( wsaData.wVersion ) != 2 )
	{
	    /* Tell the user that we could not find a usable */
	    /* WinSock DLL.                                  */
	    WSACleanup( );
	    return; 
	}

#endif
	/* Initialize scep layer */
	init_scep();

	/* Set program name */
	pname = argv[0];

	/* Set timeout */
	timeout = TIMEOUT;


	/* Check operation parameter */
	if (!argv[1]) {
		usage();
	}
	// Commande lié au protocole scep
	else if (!strncmp(argv[1], "getca", 5)) {
		operation_flag = SCEP_OPERATION_GETCA;
		protocol_flag = PROTOCOL_SCEP;
		if (!strncmp(argv[1], "getcaps", 7))
		{
			operation_flag = SCEP_OPERATION_GETCAPS;
		}
	} else if (!strncmp(argv[1], "enroll", 6)) {
		operation_flag = SCEP_OPERATION_ENROLL;
		protocol_flag = PROTOCOL_SCEP;
	} else if (!strncmp(argv[1], "getcert", 7)) {
		operation_flag = SCEP_OPERATION_GETCERT;
		protocol_flag = PROTOCOL_SCEP;
	} else if (!strncmp(argv[1], "getcrl", 6)) {
		operation_flag = SCEP_OPERATION_GETCRL;
		protocol_flag = PROTOCOL_SCEP;
	} else if (!strncmp(argv[1], "getnextca", 9)) {
		operation_flag = SCEP_OPERATION_GETNEXTCA;
		protocol_flag = PROTOCOL_SCEP;
	}
	// Commande lié au protocole EST

	else if (!strncmp(argv[1], "cacerts", 5)) {
		operation_flag = EST_OPERATION_CACERTS;
		protocol_flag = PROTOCOL_EST;
	}
	else if (!strncmp(argv[1], "simpleenroll", 7)) {
		operation_flag = EST_OPERATION_SIMPLEENROLL;
		protocol_flag = PROTOCOL_EST;
	}
	else if (!strncmp(argv[1], "simplereenroll", 6)) {
		operation_flag = EST_OPERATION_SIMPLEREENROLL;
		protocol_flag = PROTOCOL_EST;
	}
#if 0
	else if (!strncmp(argv[1], "fullcmc", 7)) {
		operation_flag = EST_OPERATION_FULLCMC;
		protocol_flag = PROTOCOL_EST;
	}
	else if (!strncmp(argv[1], "serverkeygen", 6)) {
		operation_flag = EST_OPERATION_SERVERKEYGEN;
		protocol_flag = PROTOCOL_EST;
	}
	else if (!strncmp(argv[1], "csrattrs", 9)) {
		operation_flag = EST_OPERATION_CSRATTRS;
		protocol_flag = PROTOCOL_EST;
	}
#endif
	// Sinon, erreur
	else {
		//fprintf(stderr, "%s: missing or illegal operation parameter\n",	argv[0]);
		error("missing or illegal operation parameter");
		usage();
	}
	/* Skip first parameter and parse the rest of the command */
	optind++;
	while ((c = getopt(argc, argv, "a:c:C:de:E:f:g:hF:i:jk:K:l:L:n:O:p:P:r:Rs:S:t:T:u:vw:W:m:HM:x:")) != -1)
      switch(c) {
            case 'a' :
            	a_flag_PATH_Trust_Anchor = 1;
            	a_char_PATH_Trust_Anchor = optarg;
            	break;
			case 'c':
				// -c <file>         CA certificate file or '-n' suffixed files (write if OPERATION is getca)
				// -c <file>         CA certificate file (write if OPERATION is getca or getnextca)
				c_flag = 1;
				c_char_CA_certificate = optarg;
				break;
			case 'C':
				// -C <file>         Local certificate chain file for signature verification in PEM format
				C_flag = 1;
				C_char_CA_certificate_chain = optarg;
				break;
			case 'd':
				// -d                Debug output (more verbose, for debugging the implementation)
				v_flag = 2;
				break;
			case 'e':
				// -e <file>         Use different CA cert for encryption OPTIONS enroll
				e_flag = 1;
				e_char_CA_encryption_certificate = optarg;
				break;
			case 'E':
				// -E <name>         PKCS#7 encryption algorithm (des|3des|blowfish|aes[128]|aes192|aes256)
				E_flag = 1;
				E_char_encryption_algorythm = optarg;
				break;
			case 'F':
				// -F <name>         Fingerprint algorithm (md5|sha1|sha224|sha256|sha384|sha512)
				F_flag = 1;
				F_char_fingerprint_algorythm = optarg;
				break;
			case 'f':
				// -f <file>         Use configuration file
				f_flag = 1;
				f_char_configuration_file = optarg;
				break;
#ifdef WITH_ENGINES
			case 'g':
				// -g <engine>       Use the given cryptographic engine
				g_flag = 1;
				g_char = optarg;
				break;
#endif
//			case 'h'://TODO change to eg. ID --inform=ID
//				// -h                Keyforme=ID.
//				h_flag = 1;
//				break;
//			case 'H':
//				H_flag = 1;
//				break;
			case 'i':
				// -i <string>       CA identifier string
				i_flag = 1;
				i_char_CA_identifier = optarg;
				break;
			case 'j':
				//  -j                Add CA certificate in the cert file
				j_flag = 1;
				break;
			case 'k':
				// -k <file>         Private key file
				// -k <file>         Signature private key file (getcrl or getcert)
				k_flag = 1;
				k_char_private_key = optarg;
				break;
			case 'K':
				// -K <file>         Signature private key file, use with -O
				K_flag = 1;
				K_char_Private_key_of_already_existing_certificate = optarg;
				break;
			case 'l':
				// -l <file>         Write enrolled certificate in file
				// -l <file>         Signature local certificate file (getcrl or getcert)
				l_flag = 1;
				l_char_local_certificate = optarg;
				break;
			case 'L':
				// -L <file>         Write selfsigned certificate in file
				L_flag = 1;
				L_char_local_self_signed_certificate = optarg;
				break;
			case 'm':
				m_flag = 1;
				m_char_test_mode = optarg;
				break;
			case 'M':
				// -M <string>       Monitor Information String name=value&name=value ...
				if(!M_flag) {
					/* if this is the first time the option appears, create a
					 * new string.
					 */
					required_option_space = strlen(optarg) + 1;
					M_char_Monitor_Information_HTTP_get_parameter_style = malloc(required_option_space);
					if(!M_char_Monitor_Information_HTTP_get_parameter_style)
						error_memory();
					strncpy(M_char_Monitor_Information_HTTP_get_parameter_style, optarg, required_option_space);
					// set the flag, so we already have a string
					M_flag = 1;
				} else {
					/* we already have a string, just extend it. */
					// old part + new part + &-sign + null byte
					required_option_space = strlen(M_char_Monitor_Information_HTTP_get_parameter_style) + strlen(optarg) + 2;
					M_char_Monitor_Information_HTTP_get_parameter_style = realloc(M_char_Monitor_Information_HTTP_get_parameter_style, required_option_space);
					if(!M_char_Monitor_Information_HTTP_get_parameter_style)
						error_memory();
					strcat(M_char_Monitor_Information_HTTP_get_parameter_style, "&");
					strcat(M_char_Monitor_Information_HTTP_get_parameter_style, optarg);
				}
				break;
			case 'n':
				// -n <count>        Max number of GetCertInitial requests
				n_flag = 1;
				n_num_Request_count = atoi(optarg);
				break;
			case 'O':
				// -O <file>         Signature certificate (used instead of self-signed)
				// -O <file>         Issuer Certificate of the certificate to query (requires -s) getcert
				// -O <file>         Certificate to get the CRL for (reads issuer and serial) getcrl
				O_flag = 1;
				O_char_Already_existing_certificate = optarg;
				break;
			case 'p':
				// -p <host:port>    Use proxy server at host:port
				p_flag = 1;
				p_char_proxy = optarg;
				break;
			case 'P':
				// "  -P <filename>     filename with the finger print to compare with the rootCA fingerprint\n"
				P_flag_fingerprint_filename = 1;
				P_char_fingerprint_filename = optarg;
				break;
			case 'r':
				// -r <file>         Certificate request file
				r_flag = 1;
				r_char_Certificate_request_file = optarg;
				break;
			case 'R':
				//  -R                Resume interrupted enrollment
				R_flag = 1;
				break;
			case 's':
				// -s <number>       Certificate serial number (decimal)
				s_flag = 1;
				/*s_char = optarg;*/
				s_char_Certificate_serial_number = handle_serial(optarg);
				break;
			case 'S':
				// -S <name>         PKCS#7 signature algorithm (md5|sha1|sha224|sha256|sha384|sha512)
				S_flag = 1;
				S_char_Signature_algorithm = optarg;
				break;
			case 't':
				// -t <secs>         Polling interval in seconds
				t_flag = 1;
				t_num_Polling_interval = atoi(optarg);
				break;
			case 'T':
				// -T <secs>         Max polling time in seconds
				T_flag = 1;
				T_num_MAX_Polling_interval = atoi(optarg);
				break;
			case 'u':
				// -u <url>          SCEP server URL
				u_flag = 1;
				url_char = optarg;
				break;
			case 'v':
				// -v                Verbose output (for debugging the configuration)
				v_flag = 1;
				break;
			case 'w':
				// -w <file>         Write signer certificate in file (optional)
				// -w <file>         Write CRL in file getcrl
				w_flag = 1;
				w_char_GetCert_certificate = optarg;
				break;
			case 'W':
				// -W <secs>         Wait for connectivity, up to <secs> seconds
				W_flag = atoi(optarg);
				break;
			case 'x':
				// -x <file>         filename of the certificate template rules
				x_flag = 1;
				x_char_certificate_template_filename = optarg;
				break;
			default:
			  printf("argv: %s\n", argv[optind]);
				usage();
                }
	argc -= optind;
	argv += optind;

	// Check the parameters of the command line
	ret = check_cmd_parameter();
	if (ret !=0 )
	{
		exit(ret);
	}
	
	/*
	* Create a new SCEP transaction and self-signed
	* certificate based on cert request
	*/
	if (v_flag)
		fprintf(stdout, "%s: new transaction\n", pname);
	new_transaction(&scep_t, operation_flag);

#ifdef WITH_ENGINES
	/*enable Engine Support */
	if (g_flag) {
		scep_t.e = scep_engine_init();
	}
#endif

	if (p_flag) {
		#ifdef WIN32
		host_name = _strdup(p_char_proxy);
		#else
		host_name = strdup(p_char_proxy);
		#endif
		dir_name = url_char;
	}
	else
	{
		if (protocol_flag == PROTOCOL_EST)
		{
#ifdef WIN32
			if (!(host_name = _strdup(url_char + 8)))
#else
			if (!(host_name = strdup(url_char + 8)))
#endif
				error_memory();
		}
		else
		{
#ifdef WIN32
			if (!(host_name = _strdup(url_char + 7)))
#else
			if (!(host_name = strdup(url_char + 7)))
#endif
				error_memory();
		}
	}
	// Configuration du port par défaut avec le protocole EST
    if (protocol_flag == PROTOCOL_EST)
    {
    	host_port = 443;
    }
	hostname2dirname_port(host_name, &dir_name, &host_port);

	if (!dir_name) {
		//fprintf(stderr, "%s: illegal URL %s\n", pname, url_char);
		error("illegal URL %s", url_char);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (host_port < 1 || host_port > 65550) {
		//fprintf(stderr, "%s: illegal port number %d\n", pname,host_port);
		error("illegal port number %d", host_port);
		exit (SCEP_PKISTATUS_ERROR);
	}

	if (v_flag) {
		fprintf(stdout, "%s: hostname: %s\n", pname, host_name);
		fprintf(stdout, "%s: directory: %s\n", pname, dir_name);
		fprintf(stdout, "%s: port: %d\n", pname, host_port);

	}

	/* ping before get capabilities  */
	//TODO: remettre le ping. Pour les essais avec demo.openxpki.org, le ping ne répond pas...
	if (ping(host_name) == 0)
	{
		//add_log("error host doesn't respond", LOG_WARNING);
		warning("error host doesn't respond");
		exit (SCEP_PKISTATUS_NET);
	}

	/* Get server capabilities */
	if (protocol_flag == PROTOCOL_SCEP)
	{
		if (v_flag) {
			fprintf(stdout, "%s: SCEP_OPERATION_GETCAPS\n",	pname);
		}
		ca_caps = scep_operation_get_cacaps(
				v_flag,
				&reply,
				host_name,
				host_port,
				dir_name);
	}
	//TODO: Faire l'algorithme permettant de choisir le meilleur algorithme de hash et de chiffrement et on prend celui donné par l'utilisateur si pas défini...

	/* Check algorithms */
	if ((enc_alg = get_cipher_alg(E_char_encryption_algorythm, ca_caps)) == NULL) {
		//fprintf(stderr, "%s: unsupported algorithm: %s\n", pname, E_char);
//		snprintf(buf, sizeof(buf)-1, "unsupported cipher algorithm: %s", E_char_encryption_algorythm);
//		add_log(buf, LOG_WARNING);
		//event_enroll_enedis(EVT_ENROL_02);
		warning("unsupported cipher algorithm: %s", E_char_encryption_algorythm);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if ((sig_alg = get_digest_best_alg(S_char_Signature_algorithm, ca_caps)) == NULL) {
		//fprintf(stderr, "%s: unsupported algorithm: %s\n", pname, S_char);
//		snprintf(buf, sizeof(buf)-1, "unsupported digest algorithm: %s", S_char_Signature_algorithm);
//		add_log(buf, LOG_WARNING);
		warning("unsupported digest algorithm: %s", S_char_Signature_algorithm);
		//event_enroll_enedis(EVT_ENROL_02);
		exit (SCEP_PKISTATUS_ERROR);
	}
	/* Fingerprint algorithm */
	if ((fp_alg = get_digest_alg(F_char_fingerprint_algorythm, ca_caps)) == NULL) {
		//fprintf(stderr, "%s: unsupported algorithm: %s\n", pname, F_char);
//		snprintf(buf, sizeof(buf)-1, "unsupported digest algorithm: %s", F_char_fingerprint_algorythm);
//		add_log(buf, LOG_WARNING);
		warning("unsupported digest algorithm: %s", F_char_fingerprint_algorythm);
		//event_enroll_enedis(EVT_ENROL_02);
		exit (SCEP_PKISTATUS_ERROR);
	}

	/**************************************************************************
	 * Switch to operation specific code
	 *************************************************************************/
	switch(operation_flag) {
		case SCEP_OPERATION_GETCA:
			if (v_flag)
				fprintf(stdout, "%s: SCEP_OPERATION_GETCA\n", pname);

			/* Set CA identifier */
			if (!i_flag)
				i_char_CA_identifier = CA_IDENTIFIER;

			pkistatus = scep_operation_get_ca(
					v_flag,
					&reply,
					M_char_Monitor_Information_HTTP_get_parameter_style,
					i_char_CA_identifier,
					strlen(i_char_CA_identifier),
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t);
			break;

		case SCEP_OPERATION_GETNEXTCA:
				if (v_flag)
					fprintf(stdout, "%s: SCEP_OPERATION_GETNEXTCA\n", pname);

				/* Set CA identifier */
				if (!i_flag)
					i_char_CA_identifier = CA_IDENTIFIER;

				pkistatus = scep_operation_get_next_ca(
					v_flag,
					&reply,
					M_char_Monitor_Information_HTTP_get_parameter_style,
					i_char_CA_identifier,
					strlen(i_char_CA_identifier),
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t);
				break;

		case SCEP_OPERATION_GETCERT:
			pkistatus = scep_operation_getcert(
					v_flag,
					&reply,
					M_char_Monitor_Information_HTTP_get_parameter_style,
					i_char_CA_identifier,
					strlen(i_char_CA_identifier),
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t,
					ca_caps);
			break;
		case SCEP_OPERATION_GETCRL:
			if (i_char_CA_identifier == NULL) c = 0; else c = strlen(i_char_CA_identifier);
			pkistatus = scep_operation_getcrl(
					v_flag,
					&reply,
					M_char_Monitor_Information_HTTP_get_parameter_style,
					i_char_CA_identifier,
					c,
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t,
					ca_caps);
			break;
		case SCEP_OPERATION_ENROLL:
			if (i_char_CA_identifier == NULL) c = 0; else c = strlen(i_char_CA_identifier);
			pkistatus = scep_operation_enroll(
					v_flag,    // verbose
					&reply,
					M_char_Monitor_Information_HTTP_get_parameter_style,    // Monitor Information String name=value&name=value ...
					i_char_CA_identifier,    // CA identifier string
					c,
					p_flag,    // -p <host:port>    Use proxy server at host:port
					host_name, // -u ->url
					host_port, // -u ->url
					dir_name,  // -u ->url
					&scep_t,
					ca_caps);  // automatic by the getcacaps
		break;

		case SCEP_OPERATION_GETCAPS:
			if (v_flag)
				fprintf(stdout, "%s: SCEP_OPERATION_GETCAPS\n",	pname);

			fprintf(stdout, "%s: scep capabilities: ", pname);
			cacaps2str(ca_caps, str, sizeof(str)-1);
			fprintf(stdout, "%s\n", str);
			scep_t.pki_status = pkistatus = SCEP_PKISTATUS_SUCCESS;
			break;

		case EST_OPERATION_CACERTS:
			if (v_flag)
				fprintf(stdout, "%s: EST_OPERATION_CACERTS\n",	pname);

			pkistatus = est_operation_cacerts(
					v_flag,
					&reply,
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t);
			break;
		case EST_OPERATION_SIMPLEENROLL:
			if (v_flag)
				fprintf(stdout, "%s: EST_OPERATION_SIMPLEENROLL\n",	pname);

			pkistatus = est_operation_simpleenroll(
					v_flag,
					&reply,
					r_char_Certificate_request_file,
					O_char_Already_existing_certificate,
					K_char_Private_key_of_already_existing_certificate,
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t,
					l_char_local_certificate);
			break;
		case EST_OPERATION_SIMPLEREENROLL:
			if (v_flag)
				fprintf(stdout, "%s: EST_OPERATION_SIMPLEREENROLL\n",	pname);

			pkistatus = est_operation_simplereenroll(
					v_flag,
					&reply,
					r_char_Certificate_request_file,
					O_char_Already_existing_certificate,
					K_char_Private_key_of_already_existing_certificate,
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t,
					l_char_local_certificate);
			break;
#if 0
		case EST_OPERATION_FULLCMC:
			if (v_flag)
				fprintf(stdout, "%s: EST_OPERATION_FULLCMC\n",	pname);

			/* Set CA identifier */
			if (!i_flag)
				i_char_CA_identifier = CA_IDENTIFIER;

			pkistatus = est_operation_fullcmc(
					v_flag,
					&reply,
					M_char_Monitor_Information_HTTP_get_parameter_style,
					i_char_CA_identifier,
					strlen(i_char_CA_identifier),
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t);
			break;
		case EST_OPERATION_SERVERKEYGEN:
			if (v_flag)
				fprintf(stdout, "%s: EST_OPERATION_SERVERKEYGEN\n",	pname);

			/* Set CA identifier */
			if (!i_flag)
				i_char_CA_identifier = CA_IDENTIFIER;

			pkistatus = est_operation_serverkeygen(
					v_flag,
					&reply,
					M_char_Monitor_Information_HTTP_get_parameter_style,
					i_char_CA_identifier,
					strlen(i_char_CA_identifier),
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t);
			break;
		case EST_OPERATION_CSRATTRS:
			if (v_flag)
				fprintf(stdout, "%s: EST_OPERATION_CSRATTRS\n",	pname);

			/* Set CA identifier */
			if (!i_flag)
				i_char_CA_identifier = CA_IDENTIFIER;

			pkistatus = est_operation_csrattrs(
					v_flag,
					&reply,
					M_char_Monitor_Information_HTTP_get_parameter_style,
					i_char_CA_identifier,
					strlen(i_char_CA_identifier),
					p_flag,
					host_name,
					host_port,
					dir_name,
					&scep_t);
			break;
#endif

	}

	//TODO
	//richtiger ort für disable??
//	if(e){
//		ENGINE_finish(*e);
//		ENGINE_free(*e);
//	    hwEngine = NULL;
//	    ENGINE_cleanup();
//	}
//
	return (pkistatus);
}

/**
 * @fn		void usage()
 * @brief	print usage of the software
 * @param	none
 * @return	none
 */
void usage() {
	fprintf(stdout, "\npkiclient version %s\n\n" , VERSION);
	fprintf(stdout, "Usage: %s OPERATION [OPTIONS]\n"
	"\nAvailable SCEP OPERATIONs are\n"
	"  getca             Get CA/RA certificate(s)\n"
	"  getnextca         Get next CA/RA certificate(s)\n"
	"  enroll            Enroll certificate\n"
	"  getcert           Query certificate\n"
	"  getcrl            Query CRL\n"
	"  getcaps           Query SCEP capabilities\n"
	"\nAvailable EST OPERATIONs are\n"
	"  cacerts           Get CA/RA certificate(s)\n"
	"  simpleenroll      Enroll certificate\n"
	"  simplereenroll    reEnroll certificate\n"
//	"  fullcmc           Enroll certificate\n"
//	"  serverkeygen      Query a private key to the server\n"
//	"  csrattrs          Query CSR attributes desired by the CA\n"
	"\nGeneral OPTIONS\n"
	"  -u <url>          SCEP/EST server URL\n"
	"  -p <host:port>    Use proxy server at host:port\n"
	"  -M <string>       Monitor Information String name=value&name=value ...\n"
#ifdef WITH_ENGINES
	"  -g <engine>       Use the given cryptographic engine\n"
#endif
	"  -h                Keyforme=ID. \n"//TODO
	"  -f <file>         Use configuration file\n"
	"  -c <file>         CA certificate file or '-n' suffixed files (write if OPERATION is getca)\n"
	"  -E <name>         PKCS#7 encryption algorithm (des|3des|blowfish|aes[128]|aes192|aes256)\n"
	"  -S <name>         PKCS#7 signature algorithm (md5|sha1|sha224|sha256|sha384|sha512)\n"
	"  -W <secs>         Wait for connectivity, up to <secs> seconds\n"
	"  -v                Verbose output (for debugging the configuration)\n"
	"  -d                Debug output (more verbose, for debugging the implementation)\n"
	"  -x <file>         filename of the certificate template rules\n"
	"\nOPTIONS for OPERATION getca are\n"
	"  -a <directory>    TA of actual CA\n"
	"  -i <string>       CA identifier string\n"
	"  -F <name>         Fingerprint algorithm (md5|sha1|sha224|sha256|sha384|sha512)\n"
	"  -P <filename>     filename with the finger print to compare with the rootCA fingerprint\n"
	"\nOPTIONS for OPERATION getnextca are\n"
	"  -C <file>         Local certificate chain file for signature verification in PEM format \n"
	"  -F <name>         Fingerprint algorithm (md5|sha1|sha224|sha256|sha384|sha512)\n"
	"  -c <file>         CA certificate file (write if OPERATION is getca or getnextca)\n"
	"  -w <file>         Write signer certificate in file (optional) \n"
	"\nOPTIONS for OPERATION enroll are\n"
	"  -k <file>         Private key file\n"
	"  -r <file>         Certificate request file\n"
	"  -K <file>         Signature private key file, use with -O\n"
	"  -O <file>         Signature certificate (used instead of self-signed)\n"
	"  -l <file>         Write enrolled certificate in file\n"
	"  -e <file>         Use different CA cert for encryption\n"
	"  -L <file>         Write selfsigned certificate in file\n"
	"  -t <secs>         Polling interval in seconds\n"
	"  -T <secs>         Max polling time in seconds\n"
	"  -n <count>        Max number of GetCertInitial requests\n"
	"  -R                Resume interrupted enrollment\n"
	"  -j                Add CA certificate in the cert file\n"
	"\nOPTIONS for OPERATION getcert are\n"
	"  -k <file>         Signature private key file\n"
	"  -l <file>         Signature local certificate file\n"
	"  -O <file>         Issuer Certificate of the certificate to query (requires -s)\n"
	"  -s <number>       Certificate serial number (decimal)\n"
	"  -w <file>         Write certificate in file\n"
	"\nOPTIONS for OPERATION getcrl are\n"
	"  -k <file>         Signature private key file\n"
	"  -l <file>         Signature local certificate file\n"
	"  -O <file>         Certificate to get the CRL for (reads issuer and serial)\n"
	"  -s <number>       Certificate serial number (decimal)\n"
	"  -w <file>         Write CRL in file\n\n"
	"\nOPTIONS for OPERATION simpleenroll are\n"
	//"  -k <file>         Private key file\n"
	"  -r <file>         Certificate request file\n"
	"  -K <file>         Signature private key file, use with -O\n"
	"  -O <file>         Signature certificate \n"
	"  -l <file>         Write enrolled certificate in file\n"
	"  -j                Add CA certificate in the cert file\n"
	//"  -e <file>         Use different CA cert for encryption\n"
	//"  -L <file>         Write selfsigned certificate in file\n"
	//"  -t <secs>         Polling interval in seconds\n"
	//"  -T <secs>         Max polling time in seconds\n"
	//"  -n <count>        Max number of GetCertInitial requests\n"
	//"  -R                Resume interrupted enrollment\n"
	, pname);
	exit(0);
}

/**
 * @fn		void catchalarm(int signo)
 * @brief	this function catch a timeout error and print the error on the screen
 * @param 	signo int: signal of alarm
 */
void catchalarm(int signo) {
	//fprintf(stderr, "%s: connection timed out\n", pname);
	error("connection timed out");
	exit (SCEP_PKISTATUS_TIMEOUT);
}
