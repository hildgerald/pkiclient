/*
 * cert_template.c
 *
 * Ce fichier contient toutes les fonction d'analyse du "template" des fichiers certificats en fonction de leur
 *
 *  Created on: 5 déc. 2022
 *      Author: gege
 */

#include <stdint.h>
#include <time.h>
#include <syslog.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
//#include <openssl/params.h>
//#include <openssl/param_build.h>
//#include <openssl/core_names.h>
#include "pkiclient.h"
#include "check.h"
//#include "enedis_error.h"
#include "cert_template.h"


/**
 * @fn		int32_t	check_template_crl(X509_CRL* x509)
 * @param 	x509 *: pointeur vers la CRL dont on doit vérifier le format
 * @return	int32_t : retourne la valeur de l'erreur suivant la liste check.h
 */
int32_t	check_template_crl(X509_CRL* x509crl)
{
	const int ExtensionCount = 2;
	int32_t ret = ERROR_OK;
	X509_NAME *x509_name;
	char str[1024];
	long int v;
	int i1,i2;
	int num;
	int num2;
	uint32_t ui1;

	ASN1_OBJECT * obj_asn;
	ASN1_INTEGER *int_asn;
	ASN1_TIME *time_asn;

	STACK_OF(X509_EXTENSION) *extensions;
	X509_EXTENSION *ext;

	STACK_OF(X509_REVOKED) *revs;
	X509_REVOKED *rev;

	// verification de la version
	v = X509_CRL_get_version(x509crl)+1;
	if (v<2)
	{
		return(ERROR_CRL_BAD_VERSION);
	}

	// verification du format de l'issuer
	x509_name = X509_CRL_get_issuer(x509crl);
	if (x509_name == NULL)
	{
		return(ERROR_ISSUER_UNREADABLE);
	}

	X509_NAME_oneline(x509_name, str, sizeof(str));
	if (strlen(str) == 0)
	{
		return(ERROR_ISSUER_UNREADABLE);
	}

	// On a notre chaine, on cherche ce que l'on veut
	if ((strstr(str,"/C=") == NULL)
		|| (strstr(str,"/O=") == NULL)
		|| (strstr(str,"/OU=") == NULL)
		|| (strstr(str,"/CN=") == NULL)
		)
	{
		return (ERROR_CRL_BAD_ISSUER);
	}

	// verification de la presence du champ revoked certificates avec le user certificate, revocationDate,crlentryextension et du reasonCode
	revs = X509_CRL_get_REVOKED(x509crl);
	num = sk_X509_REVOKED_num(revs);

	if (num > 0)
	{
		for (i1=0; i1 <num; i1++)
		{
			rev = sk_X509_REVOKED_value(revs, i1);
			if (rev != NULL)
			{
				// Verification de la presence du numero de série du certificat à révoquer
				int_asn = X509_REVOKED_get0_serialNumber(rev);
				if (int_asn == NULL)
				{
					return(ERROR_CRL_NO_REVOKED_SN);
				}

				// verification de la présence de la date de revocation
				time_asn = X509_REVOKED_get0_revocationDate(rev);
				if (time_asn == NULL)
				{
					return(ERROR_CRL_NO_REVOKED_DATE);
				}

				// Verification des extensions des certificats révoqués
				num2 = X509_REVOKED_get_ext_count(rev);
				if (num2 <= 0)
				{
					return(ERROR_CRL_NO_REVOKED_EXTENSION);
				}
				i2 = 0;
				for (ui1 = 0; ui1<num2;ui1++)
				{
					ext = X509_REVOKED_get_ext(rev,ui1);
					if (ext != NULL)
					{
						obj_asn = X509_EXTENSION_get_object(ext);
						if (obj_asn != NULL)
						{
							v = OBJ_obj2nid(obj_asn);
							if ((v == NID_crl_reason)
								)
							{
								i2++;
							}
						}
					}
				}
				if (i2 <1)
				{
					return(ERROR_CRL_NO_REVOKED_EXTENSION);
				}
			}
		}

	}
	else
	{
		//add_log("NO REVOKED CERTIFICATE", LOG_NOTICE);
		notice("NO REVOKED CERTIFICATE");
	}

	// verification des extensions
	extensions = X509_CRL_get0_extensions(x509crl);
	if (extensions == NULL)
	{
		return (ERROR_CRL_NO_EXTENSION);
	}
	num = sk_X509_EXTENSION_num(extensions); // i1 = X509v3_get_ext_count(extensions);
	i2 = 0;
	for (ui1=0; ui1<num; ui1++)
	{
		// On vérifie les extensions disponibles
		ext = X509_CRL_get_ext(x509crl, ui1);
		if (ext != NULL)
		{
			obj_asn = X509_EXTENSION_get_object(ext);
			if (obj_asn != NULL)
			{
				v = OBJ_obj2nid(obj_asn);
				if ((v == NID_authority_key_identifier)
					|| (v == NID_crl_number))
				{
					i2++;
				}
			}
		}
	}

	if (i2 < ExtensionCount)
	{
		return (ERROR_CRL_NOT_ENOUGH_EXTENSION);
	}

	// verification de l'algorythme de signature
	v = X509_CRL_get_signature_nid(x509crl);

	if (( v != NID_sha256 )
		&& ( v != NID_sha384 )
		&& ( v != NID_sha512 )
		&& ( v != NID_rsaEncryption)
		&& ( v != NID_ecdsa_with_Specified)
		&& ( v != NID_ecdsa_with_Recommended)
		&& ( v != NID_sha256WithRSAEncryption)
		&& ( v != NID_sha384WithRSAEncryption)
		&& ( v != NID_sha512WithRSAEncryption)
	   )
	{
		return (ERROR_CRL_BAD_SIGN_ALGO);
	}

	return(ret);
}

/**
 * @fn int32_t check_template_version(X509*, char*, char*)
 * @brief This function check the version of the certificate
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_version(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	long int liValue;
	int32_t i32Val = 0;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	// check if the parameter version is present
	// Verification de la version. Ther is systematicaly a version number
	liValue = X509_get_version(x509);
	if (*check_type == 'P')
	{
		return(1);
	}
	// Convert the options to a value
	i32Val = atoi(options);

	if (*check_type == 'V')
	{
		if (i32Val == liValue)
		{
			return(1);
		}
	}
	else if (*check_type == '>')
	{
		if (liValue >= i32Val)
		{
			return(1);
		}
	}

	return(ret);
}

/**
 * @fn int32_t check_template_serialnumber(X509*, char*, char*)
 * @brief This function check the serial number of the certificate
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter (TODO)
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_serialnumber(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	ASN1_INTEGER * ASN1_I = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	ASN1_I = X509_get_serialNumber(x509);
	if (ASN1_I == NULL)
	{
		return (0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}
	// TODO: faire la verification de valeur

	return(ret);
}

/**
 * @fn int32_t check_template_signalgorythm(X509*, char*, char*)
 * @brief This function check the algorythm of the key
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * @param options char* : pointer on the optionals parameter. the parameter can take the values :
 * 							sha256, sha384, sha512, rsa, ecdsa
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_signalgorythm(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	long int liValue;
	int i1,i2,i3;
	uint32_t ui1;
	char * pDeb = NULL;
	char * pFin = NULL;


	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	// here, i1 = mdnid, i2 = pknid, i3 = secbits, u1 = flags
	liValue = X509_get_signature_info(x509, &i1, &i2, &i3, &ui1);
	if (liValue >0)
	{
		// the signature informations are OK
		if ( *check_type == 'P')
		{
			 return(1);
		}
		if (*check_type == 'V')
		{
			// We need to check the options that are equal for example = sha256,sha384,sha512,rsa,ecdsa
			pDeb = options;
			for (;;)
			{
				if (strlen(pDeb) > 0)
				{
					pFin = strchr(pDeb, ',');
					if (pFin == NULL)
						pFin = pDeb + strlen(pDeb);
				    if (strncmp(pDeb,"sha256",6) == 0)
				    {
				    	if (i1 == NID_sha256)
				    	{
				    		return(1);
				    	}
				    }
				    else if (strncmp(pDeb,"sha384",6) == 0)
					{
						if (i1 == NID_sha384)
						{
							return(1);
						}
					}
				    else if (strncmp(pDeb,"sha512",6) == 0)
					{
						if (i1 == NID_sha512)
						{
							return(1);
						}
					}
				    else if (strncmp(pDeb,"rsa",3) == 0)
					{
						if (i2 == NID_rsaEncryption)
						{
							return(1);
						}
					}
				    else if (strncmp(pDeb,"ecdsa",5) == 0)
					{
						if ((i2 == NID_ecdsa_with_Specified)
							|| (i2 == NID_ecdsa_with_Recommended))
						{
							return(1);
						}
					}
				    if (strlen(pFin)>1)
				    {
				    	pDeb = pFin + 1;
				    }
				    else
				    {
				    	break;
				    }
				}
				else
				{
					break;
				}
			}
		}
	}

	return(ret);
}

/**
 * @fn int32_t check_template_issuercountry(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_issuercountry(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	X509_NAME *x509_name;
	char str[1024] = {0};
	char * pC = NULL;
	char * pF = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	x509_name = X509_get_issuer_name(x509);
	if (x509_name == NULL)
	{
		return(0);
	}

	X509_NAME_oneline(x509_name, str, sizeof(str));
	if (strlen(str) == 0)
	{
		return(0);
	}

	pC = strstr(str,"/C=");
	if (pC == NULL)
	{
		return(0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}

	if (*check_type == 'V')
	{
		pF = pC + 3;
		pF = strchr(pF,'/');
		if (pF != NULL) *pF = 0;
		if (strstr(pC , options) != NULL)
		{
			return(1);
		}
	}

	return(ret);
}

/**
 * @fn int32_t check_template_issuerorg(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_issuerorg(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	X509_NAME *x509_name;
	char str[1024] = {0};
	char * pC = NULL;
	char * pF = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	x509_name = X509_get_issuer_name(x509);
	if (x509_name == NULL)
	{
		return(0);
	}

	X509_NAME_oneline(x509_name, str, sizeof(str));
	if (strlen(str) == 0)
	{
		return(0);
	}

	pC = strstr(str,"/O=");
	if (pC == NULL)
	{
		return(0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}

	if (*check_type == 'V')
	{
		pF = pC + 3;
		pF = strchr(pF,'/');
		if (pF != NULL) *pF = 0;
		if (strstr(pC , options) != NULL)
		{
			return(1);
		}
	}

	return(ret);
}
/**
 * @fn int32_t check_template_issuerorgunit(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_issuerorgunit(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	X509_NAME *x509_name;
	char str[1024] = {0};
	char * pC = NULL;
	char * pF = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	x509_name = X509_get_issuer_name(x509);
	if (x509_name == NULL)
	{
		return(0);
	}

	X509_NAME_oneline(x509_name, str, sizeof(str));
	if (strlen(str) == 0)
	{
		return(0);
	}

	pC = strstr(str,"/OU=");
	if (pC == NULL)
	{
		return(0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}

	if (*check_type == 'V')
	{
		pF = pC + 3;
		pF = strchr(pF,'/');
		if (pF != NULL) *pF = 0;
		if (strstr(pC , options) != NULL)
		{
			return(1);
		}
	}

	return(ret);
}
/**
 * @fn int32_t check_template_issuercommonname(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_issuercommonname(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	X509_NAME *x509_name;
	char str[1024] = {0};
	char * pC = NULL;
	char * pF = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	x509_name = X509_get_issuer_name(x509);
	if (x509_name == NULL)
	{
		return(0);
	}

	X509_NAME_oneline(x509_name, str, sizeof(str));
	if (strlen(str) == 0)
	{
		return(0);
	}

	pC = strstr(str,"/CN=");
	if (pC == NULL)
	{
		return(0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}

	if (*check_type == 'V')
	{
		pF = pC + 3;
		pF = strchr(pF,'/');
		if (pF != NULL) *pF = 0;
		if (strstr(pC , options) != NULL)
		{
			return(1);
		}
	}

	return(ret);
}
/**
 * @fn int32_t check_template_subjectcountry(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_subjectcountry(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	X509_NAME *x509_name;
	char str[1024] = {0};
	char * pC = NULL;
	char * pF = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	x509_name = X509_get_subject_name(x509);
	if (x509_name == NULL)
	{
		return(0);
	}

	X509_NAME_oneline(x509_name, str, sizeof(str));
	if (strlen(str) == 0)
	{
		return(0);
	}

	pC = strstr(str,"/C=");
	if (pC == NULL)
	{
		return(0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}

	if (*check_type == 'V')
	{
		pF = pC + 3;
		pF = strchr(pF,'/');
		if (pF != NULL) *pF = 0;
		if (strstr(pC , options) != NULL)
		{
			return(1);
		}
	}

	return(ret);
}
/**
 * @fn int32_t check_template_subjectorg(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_subjectorg(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	X509_NAME *x509_name;
	char str[1024] = {0};
	char * pC = NULL;
	char * pF = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	x509_name = X509_get_subject_name(x509);
	if (x509_name == NULL)
	{
		return(0);
	}

	X509_NAME_oneline(x509_name, str, sizeof(str));
	if (strlen(str) == 0)
	{
		return(0);
	}

	pC = strstr(str,"/O=");
	if (pC == NULL)
	{
		return(0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}

	if (*check_type == 'V')
	{
		pF = pC + 3;
		pF = strchr(pF,'/');
		if (pF != NULL) *pF = 0;
		if (strstr(pC , options) != NULL)
		{
			return(1);
		}
	}

	return(ret);
}
/**
 * @fn int32_t check_template_subjectorgunit(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_subjectorgunit(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	X509_NAME *x509_name;
	char str[1024] = {0};
	char * pC = NULL;
	char * pF = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	x509_name = X509_get_subject_name(x509);
	if (x509_name == NULL)
	{
		return(0);
	}

	X509_NAME_oneline(x509_name, str, sizeof(str));
	if (strlen(str) == 0)
	{
		return(0);
	}

	pC = strstr(str,"/OU=");
	if (pC == NULL)
	{
		return(0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}

	if (*check_type == 'V')
	{
		pF = pC + 3;
		pF = strchr(pF,'/');
		if (pF != NULL) *pF = 0;
		if (strstr(pC , options) != NULL)
		{
			return(1);
		}
	}

	return(ret);
}
/**
 * @fn int32_t check_template_subjectcommonname(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_subjectcommonname(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	X509_NAME *x509_name;
	char str[1024] = {0};
	char * pC = NULL;
	char * pF = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	x509_name = X509_get_subject_name(x509);
	if (x509_name == NULL)
	{
		return(0);
	}

	X509_NAME_oneline(x509_name, str, sizeof(str));
	if (strlen(str) == 0)
	{
		return(0);
	}

	pC = strstr(str,"/CN=");
	if (pC == NULL)
	{
		return(0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}

	if (*check_type == 'V')
	{
		pF = pC + 3;
		pF = strchr(pF,'/');
		if (pF != NULL) *pF = 0;
		if (strstr(pC , options) != NULL)
		{
			return(1);
		}
	}

	return(ret);
}

/**
 * @fn int32_t check_template_pubkeylength(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_pubkeylength(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	int i1,i2,i3;
	uint32_t ui1;
	EVP_PKEY *PubKey = NULL;
	long int liValue;
	int32_t i32Val = 0;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	liValue = X509_get_signature_info(x509, &i1, &i2, &i3, &ui1);
	if (liValue == 0)
	{
		return 0;
	}
	PubKey = X509_get_pubkey(x509);
	if (PubKey == NULL)
	{
		return (0);
	}

	if (*check_type == 'P')
	{
		return(1);
	}

	liValue = EVP_PKEY_size(PubKey) << 3;

	// Convert the options to a value
	i32Val = atoi(options);

	if (*check_type == 'V')
	{
		if (liValue == i32Val)	return(1);
	}
	else if (*check_type == '>')
	{
		if (liValue >= i32Val)	return(1);
	}

	return(ret);
}

/**
 * @fn int32_t check_template_cryptoalgorythm(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_cryptoalgorythm(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 1;
	long int liValue;
	int32_t i32Val = 0;

	//TODO: complete check_template_cryptoalgorythm
	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}
	return(ret);
}

/**
 * @fn int32_t check_template_authoritykeyid(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_authoritykeyid(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	int nid = NID_undef;
	int i, nb_ext;
	ASN1_OBJECT *obj_name;
	X509_EXTENSION *ext;
	int critical;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	//Get the number of extension
	nb_ext = X509_get_ext_count(x509);
	for (i=0; i < nb_ext; i++)
	{
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			// On recupere le cote critical
			critical = X509_EXTENSION_get_critical(ext);

			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_authority_key_identifier)
				{
					if (*check_type == 'P')
					{
						return(1);
					}
					return (0);
				}
			}
		}
	}

	return(ret);
}

/**
 * @fn int32_t check_template_subjectkeyid(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_subjectkeyid(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	int nid = NID_undef;
	int i, nb_ext;
	ASN1_OBJECT *obj_name;
	X509_EXTENSION *ext;
	int critical;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	//Get the number of extension
	nb_ext = X509_get_ext_count(x509);
	for (i=0; i < nb_ext; i++)
	{
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			// On recupere le cote critical
			critical = X509_EXTENSION_get_critical(ext);

			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_subject_key_identifier)
				{
					if (*check_type == 'P')
					{
						return(1);
					}
					return (0);
				}
			}
		}
	}

	return(ret);
}

/**
 * @fn uint32_t CreateMaskKeyUsage(char*, int*)
 * @brief
 *
 * @pre
 * @post
 * @param options
 * @param critical
 * @return
 */
uint32_t CreateMaskKeyUsage(char * options, int * critical)
{
	// critical&digitalsign&keyencipherment
	uint32_t mask = 0;
	char * pDeb = options;
	char * pC = NULL;
	*critical = 0;

	if ((options == NULL) || (critical == NULL))
	{
		return (0);
	}

	while (pC< options+strlen(options))
	{
		pC = strchr(pDeb,'&');
		if (strncmp(pDeb,"critical", 8) == 0)
		{
			*critical = 1;
		}
		else if (strncmp(pDeb,"digitalsign", 11) == 0)
		{
			mask |= KU_DIGITAL_SIGNATURE;
		}
		else if (strncmp(pDeb,"keyencipherment", 15) == 0)
		{
			mask |= KU_KEY_ENCIPHERMENT;
		}
		else if (strncmp(pDeb,"dataencipherment", 15) == 0)
		{
			mask |= KU_DATA_ENCIPHERMENT;
		}
		else if (strncmp(pDeb,"keyagreement", 12) == 0)
		{
			mask |= KU_KEY_AGREEMENT;
		}
		else if (strncmp(pDeb,"keycertsign", 11) == 0)
		{
			mask |= KU_KEY_CERT_SIGN;
		}
		else if (strncmp(pDeb,"crlsign", 7) == 0)
		{
			mask |= KU_CRL_SIGN;
		}
		if (pC != NULL)
		{
			pDeb = pC+1;
		}
		else
		{
			break;
		}
	}
	return(mask);
}

/**
 * @fn int32_t check_template_keyusage(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_keyusage(X509 * x509, char * check_type, char * options)
{
	int32_t ret = 0;
	int nid = NID_undef;
	int i, nb_ext;
	ASN1_OBJECT *obj_name;
	X509_EXTENSION *ext;
	int critical, crit;
	uint32_t ui1 = 0;
	uint32_t msk = 0;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	//Get the number of extension
	nb_ext = X509_get_ext_count(x509);
	for (i=0; i < nb_ext; i++)
	{
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			// On recupere le cote critical
			critical = X509_EXTENSION_get_critical(ext);

			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_key_usage)
				{
					if (*check_type == 'P')
					{
						return(1);
					}
					else if (*check_type == 'V')
					{
						// example of keyusage :
						// keyusage=V;critical&digitalsign&keyencipherment;
						ui1 = X509_get_key_usage(x509);
						msk = CreateMaskKeyUsage(options, &crit);
						if ((crit == 1) && (critical != 1))
						{
							// The critical is not set and we want it !
							return (0);
						}
						if (msk == ui1)
						{
							return (1);
						}
						return(0);
					}
				}
			}
		}
	}

	return(ret);
}

/**
 * @fn uint32_t CreateMaskExtendedKeyUsage(char*, int*)
 * @brief
 *
 * @pre
 * @post
 * @param options
 * @param critical
 * @return
 */
uint32_t CreateMaskExtendedKeyUsage(char * options, int * critical)
{
	// critical&digitalsign&keyencipherment
	uint32_t mask = 0;
	char * pDeb = options;
	char * pC = NULL;
	*critical = 0;

	if ((options == NULL) || (critical == NULL))
	{
		return (0);
	}

	while (pC< options+strlen(options))
	{
		pC = strchr(pDeb,'&');
		if (strncmp(pDeb,"critical", 8) == 0)
		{
			*critical = 1;
		}
		else if (strncmp(pDeb,"serverauth", 10) == 0)
		{
			mask |= XKU_SSL_SERVER;
		}
		else if (strncmp(pDeb,"clientauth", 10) == 0)
		{
			mask |= XKU_SSL_CLIENT;
		}
		else if (strncmp(pDeb,"smime", 5) == 0)
		{
			mask |= XKU_SMIME;
		}
		else if (strncmp(pDeb,"codesign", 8) == 0)
		{
			mask |= XKU_CODE_SIGN;
		}
		else if (strncmp(pDeb,"sgc", 3) == 0)
		{
			mask |= XKU_SGC;
		}
		else if (strncmp(pDeb,"ocspsign", 8) == 0)
		{
			mask |= XKU_OCSP_SIGN;
		}
		else if (strncmp(pDeb,"timestamp", 9) == 0)
		{
			mask |= XKU_TIMESTAMP;
		}
		else if (strncmp(pDeb,"dvcs", 4) == 0)
		{
			mask |= XKU_DVCS;
		}
		else if (strncmp(pDeb,"anyeku", 6) == 0)
		{
			mask |= XKU_ANYEKU;
		}

		if (pC != NULL)
		{
			pDeb = pC+1;
		}
		else
		{
			break;
		}
	}
	return(mask);
}
/**
 * @fn int32_t check_template_extendedkeyusage(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_extendedkeyusage(X509 * x509, char * check_type, char * options)
{
	int nid = NID_undef;
	int i, nb_ext;
	ASN1_OBJECT *obj_name;
	X509_EXTENSION *ext;
	int critical, crit;
	uint32_t ui1 = 0;
	uint32_t msk = 0;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	//Get the number of extension
	nb_ext = X509_get_ext_count(x509);



	for (i=0; i < nb_ext; i++)
	{
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			// On recupere le cote critical
			critical = X509_EXTENSION_get_critical(ext);

			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_ext_key_usage)
				{
					if (*check_type == 'P')
					{
						return(1);
					}
					else if (*check_type == 'V')
					{
						// example of keyusage :
						// keyusage=V;critical&digitalsign&keyencipherment;
						ui1 = X509_get_extended_key_usage(x509);
						msk = CreateMaskExtendedKeyUsage(options, &crit);
						if ((crit == 1) && (critical != 1))
						{
							// The critical is not set and we want it !
							return (0);
						}
						if (msk == ui1)
						{
							return (1);
						}
						return(0);
					}
				}
			}
		}
	}

	// Check if we want to test missing parameter.
	if (*check_type == 'M')
	{
		// There isn't any extended key usage so all is OK
		return (1);
	}

	return (0);
}

/**
 * @fn int32_t check_template_certificatepolicies(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_certificatepolicies(X509 * x509, char * check_type, char * options)
{
	int nid = NID_undef;
	int i, nb_ext;
	ASN1_OBJECT *obj_name;
	X509_EXTENSION *ext;
	int critical;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	//Get the number of extension
	nb_ext = X509_get_ext_count(x509);
	for (i=0; i < nb_ext; i++)
	{
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			// On recupere le cote critical
			critical = X509_EXTENSION_get_critical(ext);

			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_certificate_policies)
				{
					if (*check_type == 'P')
					{
						return(1);
					}
					return (0);
				}
			}
		}
	}

	// Check if we want to test missing parameter.
	if (*check_type == 'M')
	{
		// There isn't any extended key usage so all is OK
		return (1);
	}
	return(0);
}

/**
 * @fn void CreateOptionsBasicConstraint(char*, char*, int*)
 * @brief This function retreive the critical parameter and the string to compare
 *
 * @param options
 * @param strcompare
 * @param critical
 */
void CreateOptionsBasicConstraint(char * options, char * strcompare, int * critical)
{
	char * pDeb = options;
	char * pC = NULL;
	*critical = 0;

	if ((options == NULL) || (critical == NULL) || (strcompare == NULL))
	{
		return;
	}

	while (pC< options+strlen(options))
	{
		pC = strchr(pDeb,'&');
		if (strncmp(pDeb,"critical", 8) == 0)
		{
			*critical = 1;
		}

		if (pC != NULL)
		{
			pDeb = pC+1;
		}
		else
		{
			if (strlen(pDeb) != 0)
			{
				strcpy(strcompare,pDeb);
			}
			break;
		}
	}
}

/**
 * @fn int32_t check_template_basicconstraint(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_basicconstraint(X509 * x509, char * check_type, char * options)
{
	int nid = NID_undef;
	int i, nb_ext;
	ASN1_OBJECT *obj_name;
	X509_EXTENSION *ext;
	int critical = 0;
	int crit = 0;
	ASN1_OCTET_STRING *string_asn = NULL;
	BIO *bio_memory = NULL;
	char str[1024] = {0};
	char compare[1024] = {0};
	int i2 = 0;;
	BUF_MEM *bptr = NULL;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	CreateOptionsBasicConstraint(options, compare, &crit);

	//Get the number of extension
	nb_ext = X509_get_ext_count(x509);
	for (i=0; i < nb_ext; i++)
	{
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			// On recupere le cote critical
			critical = X509_EXTENSION_get_critical(ext);

			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_basic_constraints)
				{
					if (*check_type == 'P')
					{
						return(1);
					}
					else if (*check_type == 'V')
					{
						if ((crit == 1) && (critical != 1))
						{
							// The critical is not set and we want it !
							return (0);
						}
						string_asn = X509_EXTENSION_get_data(ext);
						if (string_asn != NULL)
						{
							bio_memory = BIO_new(BIO_s_mem());
							if (bio_memory == NULL)
							{
								return(ERROR_BIO_CANT_CREATE);
							}
							X509V3_EXT_print(bio_memory, ext, 0, 0);
							BIO_ctrl(bio_memory,BIO_CTRL_FLUSH,0,NULL);
							BIO_ctrl(bio_memory,BIO_C_GET_BUF_MEM_PTR,0,(void *)&bptr);
							if ((sizeof(str)-1) < bptr->length)
							{
								i2 = sizeof(str)-1;
							}
							else
							{
								i2 = bptr->length;
							}
							memcpy(str, bptr->data, i2);
							str[i2] = 0;
							printf("Chaine de ExtensionGetData (BASIC constraints) %s\n",str);
							BIO_free(bio_memory);
						}
						//
						if (strstr(str,compare) != NULL)
						{
							return(1);
						}
						return(0);
					}
				}
			}
		}
	}

	// Check if we want to test missing parameter.
	if (*check_type == 'M')
	{
		// There isn't any basic constraints so all is OK
		return (1);
	}
	return(0);
}

/**
 * @fn int32_t check_template_subjectaltname(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_subjectaltname(X509 * x509, char * check_type, char * options)
{
	int nid = NID_undef;
	int i, nb_ext;
	ASN1_OBJECT *obj_name;
	X509_EXTENSION *ext;
	int critical;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	//Get the number of extension
	nb_ext = X509_get_ext_count(x509);
	for (i=0; i < nb_ext; i++)
	{
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			// On recupere le cote critical
			critical = X509_EXTENSION_get_critical(ext);

			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_subject_alt_name)
				{
					if (*check_type == 'P')
					{
						return(1);
					}
					return (0);
				}
			}
		}
	}

	// Check if we want to test missing parameter.
	if (*check_type == 'M')
	{
		// There isn't any subject alt name so all is OK
		return (1);
	}
	return(0);
}

/**
 * @fn int32_t check_template_crldistributionpoint(X509*, char*, char*)
 * @brief This function
 *
 * @param x509 x509* : pointer to a x509 certificate (not a CRL)
 * @param check_type char*: pointer on the type of check :
 * 					if check_type = P we check only if the parameter is present
 * 					if check_type = V we check the value with the reference values contain in options parameter
 * 					if check_type = > we check that the value is greater than the reference value options
 * @param options char* : pointer on the optionals parameter.
 * @return 1 if the check is good and 0 if not
 */
int32_t check_template_crldistributionpoint(X509 * x509, char * check_type, char * options)
{
	int nid = NID_undef;
	int i, nb_ext;
	ASN1_OBJECT *obj_name;
	X509_EXTENSION *ext;
	int critical;

	if ((x509 == NULL) || ( check_type == NULL) || (options == NULL))
	{
		return (0);
	}

	//Get the number of extension
	nb_ext = X509_get_ext_count(x509);
	for (i=0; i < nb_ext; i++)
	{
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			// On recupere le cote critical
			critical = X509_EXTENSION_get_critical(ext);

			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_crl_distribution_points)
				{
					if (*check_type == 'P')
					{
						return(1);
					}
					return (0);
				}
			}
		}
	}

	// Check if we want to test missing parameter.
	if (*check_type == 'M')
	{
		// There isn't any crl distribution point so all is OK
		return (1);
	}
	return(0);
}

/**
 * @fn int32_t check_template_by_file(X509*, char*)
 * @brief check a certificate template define in a file.
 *
 * @param x509 X509*: pointer of the certificate to check
 * @param template_filename char *: filename contain rules to check
 * @param isRA int32_t : 0, this is not a RA, 1 is a RA. RA are specific because
 * 			you don't check all rules in the file.
 * @return 0 if the check is good and an error if something is wrong
 */
int32_t check_template_by_file(X509* x509, char * template_filename, int32_t isRA)
{
	int32_t ret = 0;
	FILE * fp;
	char line[256] = {0};
	char * ParameterName = NULL;
	char *options = NULL;
	char *check_type = NULL;
	char *pC;
	int32_t i32;

	fp=fopen(template_filename,"r");
	if (fp)
	{
		while (fgets(line, sizeof(line)-1, fp) != NULL)
		{
			if ((line[0] != '#')
				&& (strlen(line)>2))
			{
				// We have a line like this keyusage=V;critical&digitalsign&keyencipherment;
				// First, we search ParameterName
				pC = strchr(line,'=');
				if (pC == NULL)
				{
					ret = ERROR_BAD_TEMPLATE;
					break;
				}
				ParameterName = &line[0];
				check_type = pC + 1;
				*pC = 0;
				pC++;

				// We search the end of check type
				pC = strchr(pC, ';');
				if (pC == NULL)
				{
					ret = ERROR_BAD_TEMPLATE;
					break;
				}
				options = pC + 1;
				*pC = 0;
				pC++;
				// We search the end of line
				pC = strchr(pC, ';');
				if (pC != NULL)
				{
					*pC = 0;
				}
				else
				{
					i32 = strlen(pC);
					*(pC + i32) = 0;
				}

				// We have all the informations that we need so we manage the control
				if (strcmp(ParameterName,"version") == 0)
				{
					i32 = check_template_version(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_CERT_BAD_VERSION);
						break;
					}
				}
				else if (strcmp(ParameterName,"serialnumber") == 0)
				{
					i32 = check_template_serialnumber(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_CERT_MISSING_SERIAL_NUMBER);
						break;
					}
				}
				else if (strcmp(ParameterName,"signalgorythm") == 0)
				{
					i32 = check_template_signalgorythm(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_CERT_BAD_SIGN_ALGO);
						break;
					}
				}
				else if (strcmp(ParameterName,"issuercountry") == 0)
				{
					i32 = check_template_issuercountry(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_ISSUER_UNREADABLE);
						break;
					}
				}
				else if (strcmp(ParameterName,"issuerorg") == 0)
				{
					i32 = check_template_issuerorg(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_ISSUER_UNREADABLE);
						break;
					}
				}
				else if (strcmp(ParameterName,"issuerorgunit") == 0)
				{
					i32 = check_template_issuerorgunit(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_ISSUER_UNREADABLE);
						break;
					}
				}
				else if (strcmp(ParameterName,"issuercommonname") == 0)
				{
					i32 = check_template_issuercommonname(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_ISSUER_UNREADABLE);
						break;
					}
				}
				else if (strcmp(ParameterName,"subjectcountry") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_subjectcountry(x509, check_type, options);

						if (i32 == 0)
						{
							ret = (ERROR_CERT_BAD_SUBJECT);
							printf("ERROR : bad subject country\n");
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"subjectorg") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_subjectorg(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_BAD_SUBJECT);
							printf("ERROR : bad subject organisation\n");
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"subjectorgunit") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_subjectorgunit(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_BAD_SUBJECT);
							printf("ERROR : bad subject organisation unit\n");
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"subjectcommonname") == 0)
				{
					i32 = check_template_subjectcommonname(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_CERT_BAD_SUBJECT);
						printf("ERROR : bad subject common name\n");
						break;
					}
				}
				else if (strcmp(ParameterName,"pubkeylength") == 0)
				{
					i32 = check_template_pubkeylength(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_CERT_BAD_PUBKEY);
						break;
					}
				}
				else if (strcmp(ParameterName,"cryptoalgorythm") == 0)
				{
					i32 = check_template_cryptoalgorythm(x509, check_type, options);
					if (i32 == 0)
					{
						ret = (ERROR_CERT_BAD_PUBKEY);
						break;
					}
				}
				else if (strcmp(ParameterName,"authoritykeyid") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_authoritykeyid(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_BAD_AUTH_KEY_ID);
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"subjectkeyid") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_subjectkeyid(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_BAD_SUBJ_KEY_ID);
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"keyusage") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_keyusage(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_UNEXPECTED_KEY_USAGE);
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"extendedkeyusage") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_extendedkeyusage(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_MISSING_EXT_KEY_USAGE);
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"certificatepolicies") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_certificatepolicies(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_BAD_POLICIES);
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"basicconstraint") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_basicconstraint(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_BAD_BASIC_CONSTRAINTS);
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"subjectaltname") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_subjectaltname(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_BAD_SUBJ_ALT_NAME);
							break;
						}
					}
				}
				else if (strcmp(ParameterName,"crldistributionpoint") == 0)
				{
					if (isRA == 0)
					{
						i32 = check_template_crldistributionpoint(x509, check_type, options);
						if (i32 == 0)
						{
							ret = (ERROR_CERT_BAD_CRL_DIST_POINT);
							break;
						}
					}
				}
			}
		}
		fclose(fp);
	}
	else
	{
		ret = ERROR_CANT_LOAD_TEMPLATE;
	}

	if (ret != 0)
	{
		printf("ERROR template n° %d\n",ret);
	}
	return(ret);
}
