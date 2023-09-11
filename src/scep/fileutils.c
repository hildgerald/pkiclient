
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/* Misc. cert/crl manipulation routines */

#if !defined(__APPLE__)
#include <malloc.h>
#endif
#include <dirent.h>
#include "sceputils.h"
#include "../check.h"
#include "syslog.h"


#ifdef WIN32
#include <io.h>
#define F_OK	0
#define access	_access
#else
#include <unistd.h>
#endif
X509 *cacert;
X509 *encert;
X509 *localcert;
X509 *renewal_cert;
X509 *issuer_cert;
X509_REQ *request;
EVP_PKEY *rsa;
EVP_PKEY *renewal_key;
X509_CRL *crl;

/**
 * @fn int16_t is_CertisSignedInBundle(X509*, struct stack_st_X509*)
 * @brief Cette fonction permet d'indiquer si le certificat appartient bien
 * 		au bundle et qu'il a été signé ou qu'il signe un certificat du bundle
 *
 * @param cert X509 * : certificat a vérifier
 * @param bundle STACK_OF(X509) *: Bundle de certificat.
 * @return 0 si il n'appartient pas au bundle; 1 si ce certificat a signé un certificat du bundle; 2 si le certificat a été signé par un certificat du bundle
 */
int16_t is_CertisSignedInBundle(X509 * cert2Verify, STACK_OF(X509) * bundle)
{
	int16_t ret = 0;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	int i;
	int r;

	// On verifie si ce certificat a signé un certificat du bundle
	pkey=X509_get_pubkey(cert2Verify); // On récupére la clé publique du certificat root
	i = 0;
	while (i<sk_X509_num(bundle))
	{
		cert = sk_X509_value(bundle, i); // On récupére le CA du bundle de CA
		r= X509_verify(cert, pkey);
		if (r == 1)
		{
			ret = 1;
			i = sk_X509_num(bundle);
		}
		i++;
	}

	if (ret == 0)
	{
		// Notre certificat n'a pas signé de certificat du bundle. Un certificat du bundle a peut-être signé notre certificat
		i = 0;
		while (i<sk_X509_num(bundle))
		{
			cert = sk_X509_value(bundle, i); // On récupére le CA du bundle de CA
			pkey=X509_get_pubkey(cert); // On récupére la clé publique du certificat du bundle
			r= X509_verify(cert2Verify, pkey); // On vérifie avec notre certificat
			if (r == 1)
			{
				ret = 2;
				i = sk_X509_num(bundle);
			}
			i++;
		}
	}

	return(ret);
}

/**
 * @fn struct stack_st_X509 load_certs_from_file*(const char*)
 * @brief Cette fonction va lire le bundle de CA sur le disque et le mettre dans
 * 		un STACK_OF(X509). Ce code est basé sur le code de RAUC,
 * 		fichier source signature.c
 *
 * @param certfile char *: nom du fichier de bundle à lire
 * @return STACK_OF(X509)* : pointeur sur le bundle de CA
 */
static STACK_OF(X509) *load_certs_from_file(const char* certfile)
{
	BIO *cert_bio = NULL;
	X509 *cert_X509 = NULL;
	STACK_OF(X509) *certs = NULL;
	unsigned long err;

	cert_bio = BIO_new_file(certfile, "r");
	if (cert_bio == NULL)
	{
		//add_log("load_certs_from_file : Error reading certfile", LOG_WARNING);
		warning("load_certs_from_file : Error reading certfile");
		return(NULL);
	}

	certs = sk_X509_new_null();

	for (;;)
	{
		cert_X509 = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
		if (cert_X509 == NULL)
		{
			err = ERR_peek_last_error();
			if (ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
			{
				// C'est la fin du fichier. C'est OK, on quitte
				ERR_clear_error();
				break;
			}

			// C'est une vrai erreur. On efface le bundle
//			snprintf(texte, sizeof(texte)-1, "load_certs_from_file : Error %d. Need to clear bundle.",ERR_GET_REASON(err));
//			add_log(texte, LOG_WARNING);
			warning("load_certs_from_file : Error %d. Need to clear bundle.",ERR_GET_REASON(err));
			sk_X509_pop_free(certs, X509_free);
			certs = NULL;
			break;
		}
		sk_X509_push(certs, cert_X509);
	}

	BIO_free_all(cert_bio);
	return (certs);
}

/**
 * @fn		void tohex(unsigned char * in, size_t insz, char *out, size_t outsz)
 * @brief	 Cette fonction converti un buffer de donnée en leur représentation
 * 			hexa.
 * @param 	in	unsigned char* : pointer on the input buffer in bytes
 * @param 	insz size_t : size of the input buffer in bytes
 * @param 	out unsigned char* : pointer of the output hexadecimal buffer
 * @param 	outsz size_t : size of the output hexadecimal buffer
 * @return	none
 */
void tohex(unsigned char * in, size_t insz, char *out, size_t outsz)
{
	const char map[17] = "0123456789ABCDEF";
	size_t i = 0;
	char nibble;
	char *pout = out;

	while ((i<insz) && ((i*2 + (2+1)) <= outsz))
	{
		nibble = (in[i] & 0xF0) >> 4;
		*pout = map[nibble];
		pout++;
		nibble = (in[i] & 0x0F);
		*pout = map[nibble];
		pout++;
		i++;
	}
	*pout = 0;
}

/**
 * @fn		int32_t	is_ROOTinChain(X509* x509)
 * @brief	Cette fonction permet de déterminer si un certificat ROOT est présent
 * 			dans la chaine de validation.
 * @param 	chain STACK_OF(X509) *: pointeur vers une chaine de certificat CA
 * @return	int32_t : retourne 1 si un ROOT est présent et 0 autrement
 */
int32_t is_ROOTinChain( STACK_OF(X509) *chain)
{
	int32_t Ret = 0; // Il n'y a pas de certificat Root dans la chaine
	int32_t i;
	for (i = 0; i < sk_X509_num(chain); i++)
	{
		if (is_ROOT(sk_X509_value(chain, i)) == 1)
		{
			Ret = 1;
			break;
		}
	}

	return(Ret);
}
/**
 * @fn		int32_t	is_CA(X509* x509)
 * @brief	Cette fonction permet de déterminer si un certificat est ROOT ou pas.
 * @param 	x509 *: pointeur vers un certificat CA
 * @return	int32_t : retourne 1 si c'est un ROOT et 0 autrement
 */
int32_t is_ROOT(X509* x509)
{
	int32_t Ret = 0; // ce n'est pas un certificat ROOT par défaut
	X509_NAME *issuer_name;
	X509_NAME *subject_name;
	char issuer_str[250];
	char subject_str[250];

	issuer_name = X509_get_issuer_name(x509);
	if (issuer_name == NULL)
	{
		return(0);
	}

	X509_NAME_oneline(issuer_name, issuer_str, sizeof(issuer_str));
	if (strlen(issuer_str) == 0)
	{
		return(0);
	}

	// On récupére le subject
	subject_name = X509_get_subject_name(x509);
	if (subject_name == NULL)
	{
		return(0);
	}
	X509_NAME_oneline(subject_name, subject_str, sizeof(subject_str));
	if (strlen(issuer_str) == 0)
	{
		return(0);
	}

	// On compare l'issuer et le subject pour savoir si c'est un CA root
	if (strcmp(subject_str,issuer_str) == 0)
	{
		Ret = 1;
	}

	return(Ret);
}

/**
 * @fn		int32_t	is_RA(X509* x509)
 * @brief	Cette fonction permet de déterminer si un certificat est RA ou non
 * 			suivant les critéres Enedis. On ne vérifie que si on est CA ou pas.
 * @param 	x509 *: pointeur vers un certificat CA
 * @return	int32_t : retourne 0 si c'est un CA et 1 si c'est un RA
 */
int32_t	is_RA(X509* x509)
{
	int32_t Ret = 1;
	int nid = NID_undef;
	int i = 0;
	int i2 = 0;
	int nb_ext = 0;
	ASN1_OBJECT *obj_name= NULL;
	X509_EXTENSION *ext= NULL;
	BIO *bio_memory = NULL;
	BUF_MEM *bptr = NULL;
	char str[1024];

	// Get the number of extension
	nb_ext = X509_get_ext_count(x509);

	for (i=0; i < nb_ext; i++) {
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_basic_constraints)
				{
					// Il faut que ce soit critique
					// et que nous soyons en CA si c'est le root CA
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
					BIO_free(bio_memory);

					//
					if (strstr(str,"CA:TRUE") != NULL)
					{
						return (0);
					}
					if (strstr(str,"CA:FALSE") != NULL)
					{
						return (1);
					}
				}
			}
		}
	}

	return (Ret);
}

/**
 * @fn		int32_t	is_CA(X509* x509)
 * @brief	Cette fonction permet de déterminer si un certificat est RA ou non
 * 			suivant les critéres Enedis. On ne vérifie que si on est CA ou pas.
 * @param 	x509 *: pointeur vers un certificat CA
 * @return	int32_t : retourne 1 si c'est un CA et 0 autrement
 */
int32_t	is_CA(X509* x509)
{
	int32_t Ret = 0;
	int nid = NID_undef;
	int i = 0;
	int i2 = 0;
	int nb_ext = 0;
	ASN1_OBJECT *obj_name= NULL;
	X509_EXTENSION *ext= NULL;
	//ASN1_OCTET_STRING *string_asn = NULL;
	BIO *bio_memory = NULL;
	BUF_MEM *bptr = NULL;
	char str[1024];

	// Get the number of extension
	nb_ext = X509_get_ext_count(x509);

	for (i=0; i < nb_ext; i++) {
		//Get the extension
		ext = X509_get_ext(x509, i);
		if (ext != NULL)
		{
			//Get the extension type
			obj_name = X509_EXTENSION_get_object(ext);
			if (obj_name != NULL)
			{
				nid = OBJ_obj2nid(obj_name);
				if (nid == NID_basic_constraints)
				{
					// Il faut que ce soit critique
					// et que nous soyons en CA si c'est le root CA
					//if (string_asn != NULL)
					//{
						bio_memory = BIO_new(BIO_s_mem());
						if (bio_memory == NULL)
						{
							return(SCEP_PKISTATUS_ERROR);
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
						BIO_free(bio_memory);
					//}
					//
					if (strstr(str,"CA:TRUE") != NULL)
					{
						return (1);
					}
					if (strstr(str,"CA:FALSE") != NULL)
					{
						return (0);
					}
				}
			}
		}
	}

	return (Ret);
}

/**
 * @fn int32_t write_cert_in_file(X509*)
 * @brief Cette fonction permet d'ecrire un certificat dans un fichier
 *
 * @param cert : certificat à écrire
 * @param filename : nom du fichier où écrire le certificat au format pem
 * @param mode : 0 = write; sinon append
 * @return
 */
int32_t write_cert_in_file(X509 * cert, char * filename, int mode)
{
	int32_t ret = ERROR_OK;
	FILE *fd = NULL;

	if ((cert == NULL) || (filename == NULL)) return (ERROR_FILE_NOT_X509);
	if (mode == 0)
	{
#ifdef WIN32
		fopen_s(&fd, filename, "w");
#else
		fd = fopen(filename, "w");
#endif
	}
	else
	{
#ifdef WIN32
		fopen_s(&fd, filename, "a+");
#else
		fd = fopen(filename, "a+");
#endif
	}
	if (fd == NULL)
	{
		//fprintf(stderr, "%s: cannot open CA file for writing\n", pname);
		//add_log("write_cert_in_file : cannot open file for writing", LOG_WARNING);
		warning("write_cert_in_file : cannot open file for writing");
		exit (SCEP_PKISTATUS_ERROR);
	}

	if (PEM_write_X509(fd, cert) != 1)
	{
//		add_log("write_cert_in_file : error while writing file", LOG_WARNING);
//		ERR_print_errors_fp(stderr);
		warning("write_cert_in_file : error while writing file : %s", ERR_error_string(ERR_get_error(),NULL));
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (v_flag)
		printf("%s: CA certificate written as %s\n", pname, filename);

	(void)fclose(fd);
	return (ret);
}

/**
 * @fn void write_crl(struct scep*)
 * @brief Write the CRL received on the disk...
 *
 * @param s struct scep * : structure of the responds
 */
void write_crl(struct scep *s)
{
	PKCS7			*p7;
	STACK_OF(X509_CRL)	*crls;
	X509_CRL		*crl;	
	FILE			*fp;
	int32_t ret = 0;

	/* Get CRL */
	p7 = s->reply_p7;
	crls = p7->d.sign->crl;
	
	/* We expect only one CRL: */
	crl = sk_X509_CRL_value(crls, 0);
	if (crl == NULL) {
//		fprintf(stderr, "%s: cannot find CRL in reply\n", pname);
//		add_log("cannot find CRL in reply", LOG_WARNING);
		warning("cannot find CRL in reply");
		exit (SCEP_PKISTATUS_FILE);
	}

	/* Check CRL format */
	ret = check_verify_CRL(crl);
	if (ret != 0)
	{
		//fprintf(stderr, "%s: the crl file %s is not valid\n", pname, w_char);
//		snprintf(buf, sizeof(buf)-1, "the crl file %s is not valid", w_char_GetCert_certificate);
//		add_log(buf, LOG_WARNING);
		warning("the crl file %s is not valid", w_char_GetCert_certificate);
		exit (SCEP_PKISTATUS_FILE);
	}

	if (v_flag)
	{
		printf("%s: the CRL %s is valid\n", pname, w_char_GetCert_certificate);
	}

	/* Write PEM-formatted file: */
#ifdef WIN32
	if ((fopen_s(&fp, w_char_GetCert_certificate, "w")))
#else
	if (!(fp = fopen(w_char_GetCert_certificate, "w")))
#endif
	{
		//fprintf(stderr, "%s: cannot open CRL file for writing\n", pname);
		//add_log("cannot open CRL file for writing", LOG_WARNING);
		warning("cannot open CRL file for writing");
		exit (SCEP_PKISTATUS_FILE);
	}
	if (v_flag)
		printf("%s: writing CRL\n", pname);
	if (v_flag > 1)
		PEM_write_X509_CRL(stdout, crl);
	if (PEM_write_X509_CRL(fp, crl) != 1) {
//		fprintf(stderr, "%s: error while writing CRL file\n", pname);
//		ERR_print_errors_fp(stderr);
		warning(" error while writing CRL file : %s", ERR_error_string(ERR_get_error(),NULL));
		exit (SCEP_PKISTATUS_FILE);
	}
	printf("%s: CRL written as %s\n", pname, w_char_GetCert_certificate);
	(void)fclose(fp);
}

/**
 * @brief	Compare the subject of the certificate and the subject of the request
 * @param 	cert X509 *
 * @return	0 if the 2 subject are equal
 */
static int compare_subject(X509 * cert)
{
	int iReq = 0;
	int LenReq = 0;
	int LenCert = 0;
	char buffer[1024];
	char *pStart = NULL;
	char *pDeb = NULL;
	char *pFin = NULL;
	int rc = X509_NAME_cmp(X509_get_subject_name(cert), X509_REQ_get_subject_name(request));


	if(v_flag) {
		fprintf(stdout, "Subject of the returned certificate: %s\n", X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0));
		fprintf(stdout, "Subject of the request: %s\n",
				X509_NAME_oneline(X509_REQ_get_subject_name(request), buffer, sizeof(buffer))
			);
	}
	if (rc)
	{
		/* X509_NAME_cmp should return 0 when X509_get_subject_name()
         * and X509_REQ_get_subject_name() match. There is a bug
		 * report on that issue (1422).
         *
		 * Assume we cannot trust X509_NAME_cmp() and perform a strcmp()
		 * when X509_NAME_cmp returns true (which is in fact false ;-))
		 */
		char cert_buf[1024] = {0};
		char req_buf[1024] = {0};
		X509_NAME_oneline(X509_get_subject_name(cert), cert_buf, sizeof(cert_buf)-1);
		X509_NAME_oneline(X509_REQ_get_subject_name(request), req_buf, sizeof(req_buf)-1);
		if (v_flag)
			printf (" X509_NAME_cmp() workaround: strcmp request subject (%s) to cert subject (%s)\n", req_buf, cert_buf);
		//rc = strcmp (cert_buf, req_buf);
		//  /CN=ENS2240003.web-api.base.emis.enedis.fr/O=ENEDIS/OU=0002 44460844213631/C=FR
		LenReq = strlen(req_buf);
		LenCert = strlen(cert_buf);
		if (( LenCert == 0) || ( LenReq == 0))
		{
			rc = 1;
		}
		else
		{
			pStart = &req_buf[1];
			pDeb = pStart;
			pFin = pStart;
			rc = 0;
			for (iReq=1; iReq < LenReq; iReq++)
			{
				if (*pFin == '/')
				{
					*pFin = 0;
					if (v_flag)
					{
						printf (" X509_NAME_cmp() workaround: Compare :%s\n", pDeb);
					}
					if (strstr(cert_buf, pDeb) == NULL)
					{
						// We don't find the substring
						rc = 1;
						break;
					}
					else
					{
						pFin++;
						pDeb = pFin;
					}
				}
				else
				{
					pFin++;
				}
			}
			if (pDeb != pFin)
			{
				if (v_flag)
				{
					printf (" X509_NAME_cmp() workaround: Compare :%s\n", pDeb);
				}
				if (strstr(cert_buf, pDeb) == NULL)
				{
					// We don't find the substring
					rc = 1;
				}
				else
				{
					rc = 0;
				}
			}
		}
	}

	return rc;
} /* is_same_cn */

/**
 * @fn		int32_t ExtractFilePath(char * FileName)
 * @brief	Cette fonction permet de supprimer le nom de fichier pour ne concerver que le chemin du fichier.
 * 			Attention cette focntion met un 0 à l'endroit du nom de fichier
 * @param 	Filename char* : nom du fichier avec son chemin.
 * @return  Retourne 0 si le chemin n'existe pas. 1 si le chemin existe
 */
int32_t ExtractFilePath(char * FileName)
{
	int32_t erreur = 0;
	int32_t SLen = strlen(FileName);
	SLen = SLen-1; // on pointe sur le dernier caractère de la chaine
	while ((SLen > 0) && (FileName[SLen]))
	{
		if ((FileName[SLen] == '/')
			|| (FileName[SLen] == '\\'))
		{
				FileName[SLen] = 0;
				erreur = 1;
				break;
		}
		SLen --;
	}

	return (erreur);
}

/**
 * @fn int16_t AddRootCAInBundle(char*, struct stack_st_X509*)
 * @brief Cette fonction permet d'ajouter dans un bundle de CA le certificat racine
 *        s'il n'est pas présent dans le bundle et ceci en recherchant le certificat racine
 *        dans le dossier contenant tous les certificats
 *
 * @param CADir char * : Chemin du dossier contenant les certificats CA
 * @param bundle STACK_OF(X509) * : bundle de ca à compléter
 * @return 0 si tout est OK
 */
int16_t AddRootCAInBundle(char * CADir, STACK_OF(X509) * bundle)
{
	int16_t ret = -1;
	BIO *InCertBIO = NULL;
	char CAFileName[512] = {0};
	X509 *cert_CA = NULL;
	X509 *cert = NULL;
	int i;
	int r;
	EVP_PKEY *pkey = NULL;
	struct dirent *dir = NULL;
	DIR *d = NULL;

	// vérification des données d'entrées
	if ((bundle != NULL)
		&& (CADir != NULL))
	{
		d = opendir(CADir);
		if (d != NULL)
		{
			// On créé un objet BIO pour pouvoir lire un fichier de certificat dans libopenssl
			InCertBIO = BIO_new(BIO_s_file());
			while ( (dir = readdir(d)) != NULL)
			{
				if (strstr(dir->d_name, "ca.crt-") != NULL)
				{
					// On a un fichier de certificat unique
					snprintf(CAFileName, sizeof (CAFileName)-1,"%s/%s",CADir,dir->d_name);
					BIO_read_filename(InCertBIO, CAFileName);
					cert_CA = PEM_read_bio_X509(InCertBIO, NULL, NULL, NULL);
					if (cert_CA != NULL)
					{
						// On vérifie si le certificat est un certificat root
						if (is_ROOT(cert_CA) != 0)
						{
							// On verifie si ce certificat a signé un certificat de la chaine
							pkey=X509_get_pubkey(cert_CA); // On récupére la clé publique du certificat root
							i = 0;
							while (i<sk_X509_num(bundle))
							{
								cert = sk_X509_value(bundle, i); // On récupére le CA du bundle de CA
								r= X509_verify(cert, pkey);
								if (r == 1)
								{
									ret = 1;
									i = sk_X509_num(bundle);
								}
								i++;
							}
						}
					}
				}

				if (ret > 0)
				{
					// On a trouvé notre root CA
					if (sk_X509_push(bundle, cert_CA) <1)
					{
						//add_log("impossible to add the Root CA file into the received trust chain !", LOG_WARNING);
						warning("impossible to add the Root CA file into the received trust chain !");
					}
					else
					{
						ret = 0;
					}
					break;
				}
			} // fin du while ( (dir = readdir(d)) != NULL)

			if (d != NULL) closedir(d);
			// On ferme le fichier
			if (InCertBIO) BIO_free(InCertBIO);
			ret = 0;
		}
		else
		{
			//add_log("The CA directory doesn't exists or doesn't have the right to read !", LOG_WARNING);
			warning("The CA directory doesn't exists or doesn't have the right to read !");
		}
	}
	return (ret);
}
/**
 * @fn void create_pki_bundle_ca(char*, struct stack_st_X509*, uint32_t)
 * @brief Cette fonction lit le bundle de ca sur le disque et vient ajouter les
 * 			certificats CA qui ne sont pas dans le bundle bundle_certs afin
 * 			d'obtenir un bundle de la pki compléte.
 *
 * @param ca_bundlestr char *: pointeur sur le nom du fichier du bundle de CA à ajouter
 * @param bundle_certs STACK_OF(X509) * : pointeur sur le bundle de CA ou ajouter les certificats manquant
 * @param dir uint32_t : ordre de rangement des certificats = 1
 * 			on est dans le sens de la présentation des certificats issuers vers root
 * @return uint32_t : nombre de certificat ajouté dans bundle_certs.
 */
int32_t create_pki_bundle_ca(char * ca_bundlestr, STACK_OF(X509) *bundle_certs, uint32_t dir)
{
	int i;
	int j;
	int comparaison = 0;
	STACK_OF(X509) *bundle_CA = NULL;
	X509			*certCA = NULL;
	X509			*cert = NULL;
	char name_strCA[512] = {0};
	char name_strCAStack[512] = {0};
	int32_t i32Ret = 0;

	// On quitte si un des parametres est inexistant,
	if ((ca_bundlestr == NULL) || (bundle_certs == NULL)) return (i32Ret);

	// On n'a pas de certificats à comparer
	if (sk_X509_num(bundle_certs) <= 0) return (i32Ret);

	// Lecture de notre bundle de CA
	bundle_CA = load_certs_from_file(ca_bundlestr);
	if (bundle_CA == NULL)
	{
		// On n'a pas de bundle de CA disponible
		//add_log("Error creating X509_STORE object", LOG_WARNING);
		warning("Error creating X509_STORE object");
		return (i32Ret);
	}

	// Traitement
	for (i = 0; i < sk_X509_num(bundle_CA); i++)
	{
		certCA = sk_X509_value(bundle_CA, i); // On récupére le CA du bundle de CA
		comparaison = 0;
		for (j = 0; j < sk_X509_num(bundle_certs); j++)
		{
			cert = sk_X509_value(bundle_certs, j); // On récupére le CA du bundle passé en paramètre
			X509_NAME_oneline(X509_get_issuer_name(certCA), name_strCA, sizeof(name_strCA));
			X509_NAME_oneline(X509_get_issuer_name(cert), name_strCAStack, sizeof(name_strCAStack));

			if (strncmp(name_strCA, name_strCAStack, sizeof(name_strCA)) == 0)
			{
				// Les deux issuers sont identiques, on vérifie les deux subjects
				X509_NAME_oneline(X509_get_subject_name(certCA), name_strCA, sizeof(name_strCA));
				X509_NAME_oneline(X509_get_subject_name(cert), name_strCAStack, sizeof(name_strCAStack));
				if (strncmp(name_strCA, name_strCAStack, sizeof(name_strCA)) == 0)
				{
					comparaison = 1;
					break;
				}
			}
		}

		if (comparaison == 0)
		{
			i32Ret++;
			// Le certificat certCA n'est pas connu, on l'ajoute dans notre bundle
			if (dir == 0)
			{
				// sens root vers issuers
				// On ajoute le certificat à la fin, juste avant le certificat final
				sk_X509_push(bundle_certs, certCA);
				j = sk_X509_num(bundle_certs);
				sk_X509_insert(bundle_certs, certCA, j-1);
			}
			else
			{
				// sens issuers vers root
				// insertion des certificats à l'emplacement 1 car le 0 represente le certificat final
				sk_X509_insert(bundle_certs, certCA, 1);
			}
		}
	}
	return  (i32Ret);
}

/**
 * @fn void create_pki_bundle_ca_from_dir(char*, struct stack_st_X509*, uint32_t)
 * @brief Cette fonction lit le bundle de ca sur le disque et vient ajouter les
 * 			certificats CA qui ne sont pas dans le bundle bundle_certs afin
 * 			d'obtenir un bundle de la pki compléte sans vérification d'authenticité.
 *
 * @param CADir char *: pointeur sur le nom du dossier du bundle de CA à ajouter
 * @param bundle_certs STACK_OF(X509) * : pointeur sur le bundle de CA ou ajouter les certificats manquant
 * @param dir uint32_t : ordre de rangement des certificats = 1
 * 			on est dans le sens de la présentation des certificats issuers vers root
 * @return uint32_t : nombre de certificat ajouté dans bundle_certs.
 */
int32_t Add_ca_from_dir(char * CADir, STACK_OF(X509) *bundle_certs, uint32_t dir)
{
	int j;
	int comparaison = 0;
	X509			*certCA = NULL;
	X509			*cert = NULL;
	char name_strCA[512] = {0};
	char name_strCAStack[512] = {0};
	int32_t i32Ret = 0;
	struct dirent *directory = NULL;
	DIR *d = NULL;
	char CAFileName[512] = {0};
	BIO *InCertBIO = NULL;


	// On quitte si un des parametres est inexistant,
	if ((CADir == NULL) || (bundle_certs == NULL)) return (i32Ret);

	// On n'a pas de certificats à comparer
	if (sk_X509_num(bundle_certs) <= 0) return (i32Ret);

	d = opendir(CADir);
	if (d != NULL)
	{
		// On créé un objet BIO pour pouvoir lire un fichier de certificat dans libopenssl
		InCertBIO = BIO_new(BIO_s_file());
		while ( (directory = readdir(d)) != NULL)
		{
			if (strstr(directory->d_name, "ca.crt-") != NULL)
			{
				// On a un fichier de certificat unique
				snprintf(CAFileName, sizeof (CAFileName)-1,"%s/%s",CADir,directory->d_name);
				BIO_read_filename(InCertBIO, CAFileName);
				certCA = PEM_read_bio_X509(InCertBIO, NULL, NULL, NULL);
				if (certCA != NULL)
				{
					comparaison = 0;
					for (j = 0; j < sk_X509_num(bundle_certs); j++)
					{
						cert = sk_X509_value(bundle_certs, j); // On récupére le CA du bundle passé en paramètre
						X509_NAME_oneline(X509_get_issuer_name(certCA), name_strCA, sizeof(name_strCA));
						X509_NAME_oneline(X509_get_issuer_name(cert), name_strCAStack, sizeof(name_strCAStack));

						if (strncmp(name_strCA, name_strCAStack, sizeof(name_strCA)) == 0)
						{
							// Les deux issuers sont identiques, on vérifie les deux subjects
							X509_NAME_oneline(X509_get_subject_name(certCA), name_strCA, sizeof(name_strCA));
							X509_NAME_oneline(X509_get_subject_name(cert), name_strCAStack, sizeof(name_strCAStack));
							if (strncmp(name_strCA, name_strCAStack, sizeof(name_strCA)) == 0)
							{
								// On est tombé sur notre certificat donc pas d'ajout
								// La comparaison est à 1
								comparaison = 1;
								break;
							}
						}
					}

					if (comparaison == 0)
					{
						// On ne connais pas ce certificat
						// On vérifie qu'il appartient bien à notre chaine de confiance
//						if (is_CertisSignedInBundle(certCA, bundle_certs) != 0)
//						{
							i32Ret++;
							// Le certificat certCA n'est pas connu, on l'ajoute dans notre bundle
							if (dir == 0)
							{
								// sens root vers issuers
								// On ajoute le certificat à la fin, juste avant le certificat final
								sk_X509_push(bundle_certs, certCA);
								j = sk_X509_num(bundle_certs);
								sk_X509_insert(bundle_certs, certCA, j-1);
							}
							else
							{
								// sens issuers vers root
								// insertion des certificats à l'emplacement 1 car le 0 represente le certificat final
								sk_X509_insert(bundle_certs, certCA, 1);
							}
//						}
					}
				}
			}
		}
		if (d != NULL) closedir(d);
		// On ferme le fichier
		if (InCertBIO) BIO_free(InCertBIO);
	}

	return  (i32Ret);
}
/**
 * @fn void create_pki_bundle_ca_from_dir(char*, struct stack_st_X509*, uint32_t)
 * @brief Cette fonction lit le bundle de ca sur le disque et vient ajouter les
 * 			certificats CA qui ne sont pas dans le bundle bundle_certs afin
 * 			d'obtenir un bundle de la pki compléte.
 *
 * @param ca_bundlestr char *: pointeur sur le nom du fichier du bundle de CA à ajouter
 * @param bundle_certs STACK_OF(X509) * : pointeur sur le bundle de CA ou ajouter les certificats manquant
 * @param dir uint32_t : ordre de rangement des certificats = 1
 * 			on est dans le sens de la présentation des certificats issuers vers root
 * @return uint32_t : nombre de certificat ajouté dans bundle_certs.
 */
int32_t create_pki_bundle_ca_from_dir(char * CADir, STACK_OF(X509) *bundle_certs, uint32_t dir)
{
	int j;
	int comparaison = 0;
	X509			*certCA = NULL;
	X509			*cert = NULL;
	char name_strCA[512] = {0};
	char name_strCAStack[512] = {0};
	int32_t i32Ret = 0;
	struct dirent *directory = NULL;
	DIR *d = NULL;
	char CAFileName[512] = {0};
	BIO *InCertBIO = NULL;


	// On quitte si un des parametres est inexistant,
	if ((CADir == NULL) || (bundle_certs == NULL)) return (i32Ret);

	// On n'a pas de certificats à comparer
	if (sk_X509_num(bundle_certs) <= 0) return (i32Ret);

	d = opendir(CADir);
	if (d != NULL)
	{
		// On créé un objet BIO pour pouvoir lire un fichier de certificat dans libopenssl
		InCertBIO = BIO_new(BIO_s_file());
		while ( (directory = readdir(d)) != NULL)
		{
			if (strstr(directory->d_name, "ca.crt-") != NULL)
			{
				// On a un fichier de certificat unique
				snprintf(CAFileName, sizeof (CAFileName)-1,"%s/%s",CADir,directory->d_name);
				BIO_read_filename(InCertBIO, CAFileName);
				certCA = PEM_read_bio_X509(InCertBIO, NULL, NULL, NULL);
				if (certCA != NULL)
				{
					comparaison = 0;
					for (j = 0; j < sk_X509_num(bundle_certs); j++)
					{
						cert = sk_X509_value(bundle_certs, j); // On récupére le CA du bundle passé en paramètre
						X509_NAME_oneline(X509_get_issuer_name(certCA), name_strCA, sizeof(name_strCA));
						X509_NAME_oneline(X509_get_issuer_name(cert), name_strCAStack, sizeof(name_strCAStack));

						if (strncmp(name_strCA, name_strCAStack, sizeof(name_strCA)) == 0)
						{
							// Les deux issuers sont identiques, on vérifie les deux subjects
							X509_NAME_oneline(X509_get_subject_name(certCA), name_strCA, sizeof(name_strCA));
							X509_NAME_oneline(X509_get_subject_name(cert), name_strCAStack, sizeof(name_strCAStack));
							if (strncmp(name_strCA, name_strCAStack, sizeof(name_strCA)) == 0)
							{
								// On est tombé sur notre certificat donc pas d'ajout
								// La comparaison est à 1
								comparaison = 1;
								break;
							}
						}
					}

					if (comparaison == 0)
					{
						// On ne connais pas ce certificat
						// On vérifie qu'il appartient bien à notre chaine de confiance
						if (is_CertisSignedInBundle(certCA, bundle_certs) != 0)
						{
							i32Ret++;
							// Le certificat certCA n'est pas connu, on l'ajoute dans notre bundle
							if (dir == 0)
							{
								// sens root vers issuers
								// On ajoute le certificat à la fin, juste avant le certificat final
								sk_X509_push(bundle_certs, certCA);
								j = sk_X509_num(bundle_certs);
								sk_X509_insert(bundle_certs, certCA, j-1);
							}
							else
							{
								// sens issuers vers root
								// insertion des certificats à l'emplacement 1 car le 0 represente le certificat final
								sk_X509_insert(bundle_certs, certCA, 1);
							}
						}
					}
				}
			}
		}
		if (d != NULL) closedir(d);
		// On ferme le fichier
		if (InCertBIO) BIO_free(InCertBIO);
	}

	return  (i32Ret);
}
/**
 * @fn		write_local_ca_from_enroll
 * @brief	cette fonction permet de sauvegarder la chaine de confiance lié au
 * 			certificat lors de l'enrolement
 * @param 	s struct scep *: the scep
 * @return 	sens des CA dans le bundle de certificats. 0 = root -> issuer; 1 = issuers -> root
 */
int32_t write_local_ca_from_enroll(struct scep *s) {
	PKCS7				*p7;
	STACK_OF(X509)		*certs;
	X509				*cert = NULL;
	FILE				*fp;
	int32_t				i;

	localcert = NULL;
	char fileCAName[1024]={0};
	char filePath[512]={0};
	char fileCAPath[512]={0};
	char buffer[1024] = {0};
	char name[1024] = {0};

	char ligne[4096] = {0};
	int32_t isFirstRA = 0; // Par défaut on considére que le premier certificat recu n'est pas un RA
	int32_t SensIssuer_Root = 1; // par défaut on part du principe qu'on est dans le sens de la présentation des certificats issuers vers root
	int32_t IndexCert = 1;
	int32_t RootInChain = 0; // =0, le certificat root n'est pas dans la chaine
	//BIO	*InCertBIO = NULL;
	int32_t IndexCACert = 0;
	int16_t r;

	/* Get certs */
	p7 = s->reply_p7;
	certs = p7->d.sign->cert;
	if (v_flag) printf("Write all trust chain to the disk\n");

	if (v_flag) printf("%s: Find %d certificate in the response\n", pname, sk_X509_num(certs));

	// Define the path of the files
	strncpy(filePath, l_char_local_certificate,sizeof(filePath) - 1);
	i = ExtractFilePath(filePath);
	if (i != 1)
	{
		//printf("Error, impossible to find the path of the file to write the trust chain !\n");
		//add_log("Impossible to find the path of the file to write the trust chain !", LOG_WARNING);
		warning("Impossible to find the path of the file to write the trust chain !");
		return SensIssuer_Root;
	}


	if (snprintf(fileCAName, sizeof(fileCAName)-1, "%s/ca.crt",filePath) <= 0)
	{
		//printf("ERROR, the filename for the CA chain to write is too long\n");
		//add_log("The filename for the CA chain to write is too long !", LOG_WARNING);
		warning("The filename for the CA chain to write is too long !");
		return (SensIssuer_Root);
	}

	// On efface l'ancien fichier
	if (access(fileCAName, F_OK) == 0)
	{
		// Le fichier existe, on le supprime
		remove(fileCAName);
	}

	strncpy(fileCAPath, c_char_CA_certificate,sizeof(fileCAPath) - 1);
	i = ExtractFilePath(fileCAPath);
	if (i != 1)
	{
		//printf("Error, impossible to find the path of the CA file to write the trust chain !\n");
		//add_log("impossible to find the root CA path in c_char. Impossible to write the trust chain !", LOG_WARNING);
		warning("impossible to find the root CA path in c_char. Impossible to write the trust chain !");
		return (SensIssuer_Root);
	}

	/* Find cert */
	if (sk_X509_num(certs) > 1)
	{
		// On vérifie si le premier certificat est un certificat RA
		cert = sk_X509_value(certs, 1);
		if (is_CA(cert) == 0)
		{
			isFirstRA = 1; // Le premier certificat après le certificat enrolé est le certificat RA
		}

		// On analyse le sens des certificats CAs
		if ((sk_X509_num(certs)>(isFirstRA+1)))
		{
			if (is_ROOT(sk_X509_value(certs, (isFirstRA + 1))) == 1)
			{
				SensIssuer_Root = 0; // Le certificat Root est en premier dans la chaine
				IndexCert = sk_X509_num(certs) - 1;
				RootInChain = 1; // Le certificat root est bien présent
			}
			else
			{
				RootInChain = is_ROOTinChain(certs);
				if (RootInChain == 0)
				{
					// Le certificat Root n'est pas présent dans la chaine
					// On va essayer de le lire coté "RA" ou il y est
					// surement par le GetCA
					if (v_flag) printf("%s: No ROOT CA certificate in the response. Need to read it from \"RA\" chain\n", pname);

					// Ajout éventuel du CA dans le bundle de CA si trouvé
					snprintf(ligne, sizeof(ligne), "%s", fileCAPath);
					r = AddRootCAInBundle(ligne, certs);
					if (r < 0)
					{
						//add_log("There is no ROOT CA in the directory !", LOG_WARNING);
						warning("There is no ROOT CA in the directory !");
					}
				}
			}
		}

		// On vient voir si les certificats du coté CA existe dans les certificats recus
		// si non, ils seront ajouté à la PKI
		//snprintf(ligne, sizeof(ligne), "%s/ca.crt", fileCAPath);
		//i = create_pki_bundle_ca(ligne, certs, SensIssuer_Root);
		i = create_pki_bundle_ca_from_dir(fileCAPath, certs, SensIssuer_Root);
		if (i>0)
		{
			// On a ajouté des certificats. On doit modifier des variables
			if (SensIssuer_Root == 0)
			{
				IndexCert = sk_X509_num(certs) - 1;
			}
		}

		// Boucle Analyse et d'écriture de la chaine de confiance
		for (i = 1; i < sk_X509_num(certs); i++) {
			cert = sk_X509_value(certs, IndexCert);
			if (SensIssuer_Root == 0)
			{
				if (IndexCert>0) IndexCert--;
			}
			else
			{
				IndexCert++;
			}

			//cert = sk_X509_value(certs, i);
			if (v_flag) {
				printf("%s: found certificate with\n  subject: '%s'\n",
						pname,
					    X509_NAME_oneline(X509_get_subject_name(cert),
						buffer,
						sizeof(buffer)));
				printf("  issuer: %s\n",
						X509_NAME_oneline(X509_get_issuer_name(cert),
						buffer,
						sizeof(buffer)));
				printf("  request_subject: '%s'\n",
						X509_NAME_oneline(X509_REQ_get_subject_name(request),
						buffer,
						sizeof(buffer)));
			}

			if (is_CA(cert) > 0)
			{
				/* Write PEM-formatted file: */
#ifdef WIN32
				if ((fopen_s(&fp, fileCAName, "a")))
#else
				if (!(fp = fopen(fileCAName, "a")))
#endif
				{
					//fprintf(stderr, "%s: cannot open CA cert file for writing\n", fileCAName);
					//add_log("cannot open CA cert file for writing", LOG_WARNING);
					warning("%s: cannot open CA cert file for writing",fileCAName);
					exit (SCEP_PKISTATUS_FILE);
				}
				if (v_flag)	printf("%s: certificate written as %s\n", pname, fileCAName);
				if (v_flag > 1)	PEM_write_X509(stdout, cert);

				if (PEM_write_X509(fp, cert) != 1) {
					//fprintf(stderr, "%s: error while writing certificate file\n", pname);
					//add_log("error while writing certificate file", LOG_WARNING);
					warning("error while writing certificate file");
					//ERR_print_errors_fp(stderr);
//					snprintf(buffer, sizeof(buffer)-1, "%s: %s", pname, ERR_error_string(ERR_get_error(),NULL));
//				    add_log(buffer, LOG_WARNING);
					warning("%s: %s", pname, ERR_error_string(ERR_get_error(),NULL));
					exit (SCEP_PKISTATUS_FILE);
				}
				(void)fclose(fp);

				// Ecriture des certificats détaillé...
				// Definition du nom du fichier
				if (snprintf(name, sizeof(name)-1, "%s/ca.crt-%d",filePath, IndexCACert) <= 0)
				{
					//printf("ERROR, the filename for the CA chain to write is too long\n");
					//add_log("The filename for the CA intermediate certificate to write is too long !", LOG_WARNING);
					warning("The filename for the CA intermediate certificate to write is too long !");
					return (SensIssuer_Root);
				}
				IndexCACert ++;
#ifdef WIN32
				if ((fopen_s(&fp, name, "w")))
#else
				if (!(fp = fopen(name, "w")))
#endif
				{
					//fprintf(stderr, "%s: cannot open CA cert file for writing\n", fileCAName);
					//add_log("cannot open CA cert file for writing", LOG_WARNING);
					warning("%s: cannot open CA cert file for writing\n", fileCAName);
					exit (SCEP_PKISTATUS_FILE);
				}
				if (v_flag)	printf("%s: certificate written as %s\n", pname, name);
				if (v_flag > 1)	PEM_write_X509(stdout, cert);

				if (PEM_write_X509(fp, cert) != 1) {
					//fprintf(stderr, "%s: error while writing certificate file\n", pname);
//					add_log("error while writing certificate file", LOG_WARNING);
//					snprintf(buffer, sizeof(buffer)-1, "%s: %s", pname, ERR_error_string(ERR_get_error(),NULL));
//					add_log(buffer, LOG_WARNING);
					//ERR_print_errors_fp(stderr);
					warning("error while writing certificate file :%s",ERR_error_string(ERR_get_error(),NULL));
					exit (SCEP_PKISTATUS_FILE);
				}
				(void)fclose(fp);

			}
			else
			{
				if (v_flag)	printf("%s: certificate [%d] is not written because it is not a CA\n", pname, IndexCert);
			}
		}
	} else
	{
		// On est dans le cas ou on n'a pas la chaine de confiance entière, on la copie de l'endroit où se trouve le RA
		// On copie tous les certificats de c_char vers filePath
		// Define the path of the files
		strncpy(fileCAPath, c_char_CA_certificate,sizeof(fileCAPath) - 1);
		i = ExtractFilePath(fileCAPath);
		if (i != 1)
		{
			//printf("Error, impossible to find the path of the CA file to write the trust chain !\n");
			//add_log("impossible to find the path of the CA file to write the trust chain !", LOG_WARNING);
			warning("impossible to find the path of the CA file to write the trust chain !");
			return (SensIssuer_Root);
		}
		int rc;
		snprintf(ligne, sizeof(ligne), "cp %s/ca.crt* %s", fileCAPath, filePath);
		rc = system(ligne);
		rc = WEXITSTATUS(rc);
		if (rc != 0)
		{
			//printf("Error, impossible to write the trust chain from RA path to cert path!\n");
			//add_log("impossible to write the trust chain from RA path to cert path!", LOG_WARNING);
			warning("impossible to write the trust chain from RA path to cert path!");
		}
	}
	return (SensIssuer_Root);
}
/**
 * @fn void write_local_cert(struct scep*)
 * @brief Open the inner, decrypted PKCS7 and try to write cert.
 *
 * @param s struct scep *:
 */
void write_local_cert(struct scep *s)
{
	PKCS7			*p7;
	STACK_OF(X509)		*certs;
	X509			*cert = NULL;
	FILE			*fp;
	int			i;
	int32_t ret;
	int32_t i32SensCA = 0;
	int32_t i32Index = 0;

	localcert = NULL;

	write_local_ca_from_enroll(s);

	/* Get certs */
	p7 = s->reply_p7;
	certs = p7->d.sign->cert;
       
        if (v_flag) {
		printf ("write_local_cert(): found %d cert(s)\n", sk_X509_num(certs));
        }

	/* Find cert */
	for (i = 0; i < sk_X509_num(certs); i++) {
		char buffer[1024];
		cert = sk_X509_value(certs, i);
		if (v_flag) {
			printf("%s: found certificate with\n"
				"  subject: '%s'\n", pname,
				X509_NAME_oneline(X509_get_subject_name(cert),
					buffer, sizeof(buffer)));
			printf("  issuer: %s\n", 
				X509_NAME_oneline(X509_get_issuer_name(cert),
					buffer, sizeof(buffer)));
			printf("  request_subject: '%s'\n", 
				X509_NAME_oneline(X509_REQ_get_subject_name(request),
                                        buffer, sizeof(buffer)));
		}
		/* The subject has to match that of our request */
		if (!compare_subject(cert)) {
			if (v_flag)
				printf ("CN's of request and certificate matched!\n");
		} else {
			//fprintf(stderr, "%s: Subject of our request does not match that of the returned Certificate!\n", pname);
			//exit (SCEP_PKISTATUS_FILE);
			warning("Subject of our request does not match that of the returned Certificate!");
		}
		
		/* The subject cannot be the issuer (selfsigned) */
		if (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)))
		{
				localcert = cert;
				break;
		}
	}
	if (localcert == NULL) {
		//fprintf(stderr, "%s: cannot find requested certificate\n", pname);
		error("cannot find requested certificate");
		exit (SCEP_PKISTATUS_FILE);

	}

	if (v_flag)
		printf("%s: certificate %s must to be verify\n", pname, l_char_local_certificate);

	ret = check_verify_cert(cert, certs);

	if (ret != 0)
	{
		//fprintf(stderr, "%s: the cert file %s is not valid\n", pname, l_char);
//		snprintf(buf, sizeof(buf)-1, "the cert file %s is not valid", l_char_local_certificate);
//		add_log(buf, LOG_WARNING);
		warning("the cert file %s is not valid",l_char_local_certificate);
		exit (SCEP_PKISTATUS_FILE);
	}

	if (v_flag)
	{
		printf("%s: the certificate %s is valid\n", pname, l_char_local_certificate);
	}

	/* Write PEM-formatted file: */
#ifdef WIN32
	if ((fopen_s(&fp, l_char_local_certificate, "w")))
#else
	if (!(fp = fopen(l_char_local_certificate, "w")))
#endif
	{
		//fprintf(stderr, "%s: cannot open cert file for writing\n",	pname);
		//add_log("cannot open cert file for writing", LOG_WARNING);
		warning("cannot open cert file for writing");
		exit (SCEP_PKISTATUS_FILE);
	}
	if (v_flag)
		printf("%s: certificate written as %s\n", pname, l_char_local_certificate);
	if (v_flag >1)
		PEM_write_X509(stdout, localcert);
	if (PEM_write_X509(fp, localcert) != 1) {
		//fprintf(stderr, "%s: error while writing certificate file\n", pname);
		//add_log("error while writing certificate file", LOG_WARNING);
		//ERR_print_errors_fp(stderr);
//		snprintf(buf, sizeof(buf)-1, "%s: %s", pname, ERR_error_string(ERR_get_error(),NULL));
//		add_log(buf, LOG_WARNING);
		warning("error while writing certificate file: %s", ERR_error_string(ERR_get_error(),NULL));
		exit (SCEP_PKISTATUS_FILE);
	}
	if (j_flag != 0)
	{
		// On doit écrire la chaine de confiance dans le fichier
		if (i32SensCA == 0)
		{
			i32Index = sk_X509_num(certs) - 1;
		}
		else
		{
			i32Index = 0;
		}
		for (i = 0; i < sk_X509_num(certs); i++)
		{
			cert = sk_X509_value(certs, i32Index);
			if (is_CA(cert) != 0)
			{
				// C'est bien un CA à ajouter
				if (PEM_write_X509(fp, cert) != 1) {
					//add_log("error while writing certificate CA in the service certificate file", LOG_WARNING);
					//ERR_print_errors_fp(stderr);
					//snprintf(buf, sizeof(buf)-1, "%s: %s", pname, ERR_error_string(ERR_get_error(),NULL));
					//add_log(buf, LOG_WARNING);
					warning("error while writing certificate CA in the service certificate file : %s", ERR_error_string(ERR_get_error(),NULL));
					exit (SCEP_PKISTATUS_FILE);
				}
			}
			if (i32SensCA == 0)
			{
				if (i32Index>0) i32Index--;
			}
			else
			{
				i32Index ++;
			}
		}
	}
	(void)fclose(fp);
}

/* Open the inner, decrypted PKCS7 and try to write cert.  */ 
void write_other_cert(struct scep *s) {
	PKCS7			*p7;
	STACK_OF(X509)		*certs;
	X509			*cert = NULL;
	FILE			*fp;
	int			i;
	X509 *othercert = NULL;

	/* Get certs */
	p7 = s->reply_p7;
	certs = p7->d.sign->cert;
	
	/* Find cert */
	for (i = 0; i < sk_X509_num(certs); i++) {
		char buffer[1024];

		cert = sk_X509_value(certs, i);
		if (v_flag) {
			printf("%s: found certificate with\n"
				"  subject: %s\n", pname,
				X509_NAME_oneline(X509_get_subject_name(cert),
					buffer, sizeof(buffer)));
			printf("  issuer: %s\n", 
				X509_NAME_oneline(X509_get_issuer_name(cert),
					buffer, sizeof(buffer)));
		}
		/* The serial has to match to requested one */
		if (!ASN1_INTEGER_cmp(X509_get_serialNumber(cert),
				s->ias_getcert->serial)) {
				othercert = cert;	
				break;
		}	
	}
	if (othercert == NULL) {
		//fprintf(stderr, "%s: cannot find certificate\n", pname);
		error("cannot find certificate");
		exit (SCEP_PKISTATUS_FILE);

	}
	/* Write PEM-formatted file: */
#ifdef WIN32
	if ((fopen_s(&fp, w_char_GetCert_certificate, "w")))
#else
	if (!(fp = fopen(w_char_GetCert_certificate, "w")))
#endif
	{
		//fprintf(stderr, "%s: cannot open cert file for writing\n", pname);
		error("cannot open cert file for writing");
		exit (SCEP_PKISTATUS_FILE);
	}
	if (v_flag)
		printf("%s: certificate written as %s\n", pname, w_char_GetCert_certificate);
	if (v_flag > 1)
		PEM_write_X509(stdout, othercert);
	if (PEM_write_X509(fp, othercert) != 1) {
//		fprintf(stderr, "%s: error while writing certificate file\n", pname);
//		ERR_print_errors_fp(stderr);
		error("error while writing certificate file : %s", ERR_error_string(ERR_get_error(),NULL));
		exit (SCEP_PKISTATUS_FILE);
	}
	(void)fclose(fp);
}


/**
 * @fn int write_ca_ra(struct http_reply*)
 * @brief Open the inner, decrypted PKCS7 and try to write CA/RA certificates
 *
 * @param s struct http_reply *: reply from the SCEP server
 * @return int : this function doesn't return any value because it exit the software ...
 */
int write_ca_ra(struct http_reply *s)
{
	BIO				*bio;
	PKCS7			*p7;
	STACK_OF(X509)	*certs = NULL;
	X509			*cert = NULL;
	FILE			*fp = NULL;
	int				c;
	int				i;
	int				index;
    unsigned int	n;
    unsigned char	md[EVP_MAX_MD_SIZE];
	X509_EXTENSION	*ext;
	int32_t	ret;
	int32_t isRoot = 0; // Variable permettant de récupérer si le certificat est Root lors de la vérification
	int32_t isRA = 0; // Variable permettant de récupérer si le certificat est un certificat RA lors de la vérification
	int32_t isFirstRA = 0; // Par défaut on considére que le premier certificat recu n'est pas un RA
	int32_t SensIssuer_Root = 1; // par défaut on part du principe qu'on est dans le sens de la présentation des certificats issuers vers root
	int32_t IndexCert = 0;
	char name[1024] = {0};
	char nameroot[1024] = {0};
	//int WriteFirstCA = 0; // Variable permettant de savoir si on a déja écrit le premier CA dans un fichier -0 (ex: ca.crt-0). = 0 => non

	int WriteRA = 0;
	int CAFileIndex = 0;

	/* Create read-only memory bio */
	bio = BIO_new_mem_buf(s->payload, s->bytes);
	p7 = d2i_PKCS7_bio(bio, NULL);
	if (p7 == NULL) {
//		fprintf(stderr, "%s: error reading PKCS#7 data\n", pname);
//		ERR_print_errors_fp(stderr);
		error("error reading PKCS#7 data : %s", ERR_error_string(ERR_get_error(),NULL));
		exit (SCEP_PKISTATUS_FILE);
	}
	/* Get certs */
	i = OBJ_obj2nid(p7->type);
	switch (i) {
		case NID_pkcs7_signed:
			certs = p7->d.sign->cert;
			break;
		default:
			printf("%s: wrong PKCS#7 type\n", pname);
			error(" wrong PKCS#7 type");
			exit (SCEP_PKISTATUS_FILE);
	}
	/* Check if there is cert */
	if (certs == NULL) {
		//fprintf(stderr, "%s: cannot find certificates\n", pname);
		error("cannot find certificates");
		exit (SCEP_PKISTATUS_FILE);
	} 

	/* Check if the CA certificate exists. If yes, remove it */
	if (access(c_char_CA_certificate, F_OK) == 0)
	{
		// Le fichier existe, on le supprime
		remove(c_char_CA_certificate);
	}

	// Check if we have a RA certificate or not
	if ((sk_X509_num(certs)>0))
	{
		// Check if the first certificate is a RA certificate
		cert = sk_X509_value(certs, 0);
		if (is_CA(cert) == 0)
		{
			// The first certificate is a RA certificate
			isFirstRA = 1;
		}
	}

	// Analyze the certificate order. It depend of the PKI server.
	// OpenXPKI put the root CA at the end of chain and Ejbca at the beginning
	if ((sk_X509_num(certs)>isFirstRA))
	{
		// if we don't have RA certificate, isFirstRA = 0
		// if we have a RA certificate , isFirstRA = 1
		// The first CA certificate of the trust chain is :
		// Index 0 if the isn't RA
		// Index 1 if there is a RA
		if (is_ROOT(sk_X509_value(certs, isFirstRA)) == 1)
		{
			// The Root CA certificate is the first in the trust chain
			SensIssuer_Root = 0; 	// Order =0 => We have root CA in first, subCA
									//.... and issuer at the end
			IndexCert = sk_X509_num(certs) - 1; // We change the start index to
												// analyze the certificates and write them
												// in the order Issuer, SubCA, root
		}
	}

	/* Find cert */
	for (i = 0; i < sk_X509_num(certs); i++) {
		char buffer[1024];
		//char name[1024];

		memset(buffer, 0, 1024);
		//memset(name, 0, 1024);
		if (i == 0)
		{
			if (isFirstRA == 1)
			{
				cert = sk_X509_value(certs, 0);
				if (SensIssuer_Root != 0)
				{
					IndexCert = 1;
				}
			} else
			{
				cert = sk_X509_value(certs, IndexCert);
				if (SensIssuer_Root == 0)
				{
					if (IndexCert>0) IndexCert--;
				}
				else
				{
					IndexCert++;
				}
			}
			strncpy(name,c_char_CA_certificate,sizeof(name)-1);
			ExtractFilePath(name);
			strncat(name,"/ra.crt",sizeof(name)-1);
			WriteRA = 1;
		}
		else
		{
			cert = sk_X509_value(certs, IndexCert);
			strncpy(name,c_char_CA_certificate,sizeof(name)-1);
			WriteRA = 0;
			if (SensIssuer_Root == 0)
			{
				if (IndexCert>0) IndexCert--;
			}
			else
			{
				IndexCert++;
			}
		}

		/* Read and print certificate information */
		if (v_flag)
		{
			printf("\n%s: found certificate with\n  subject: %s\n", pname,
					X509_NAME_oneline(X509_get_subject_name(cert),
					buffer, sizeof(buffer)));

			printf("  issuer: %s\n",
					X509_NAME_oneline(X509_get_issuer_name(cert),
					buffer, sizeof(buffer)));
		}

		// Calculate the fingerprint of the certificate
		if (!X509_digest(cert, fp_alg, md, &n)) {
			//ERR_print_errors_fp(stderr);
			error("error digest : %s", ERR_error_string(ERR_get_error(),NULL));
			exit (SCEP_PKISTATUS_FILE);
		}

		/* Print basic constraints: */
		index = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);
		if (index < 0) {
			if (v_flag)
				printf("  basic constraints: (not included)\n");
		} else {
			ext = X509_get_ext(cert, index);
			if (v_flag){
				printf("  basic constraints: ");
				X509V3_EXT_print_fp(stdout, ext, 0, 0);
				printf("\n");
			}
		}

		/* Print key usage: */
		index = X509_get_ext_by_NID(cert, NID_key_usage, -1);
		if (index < 0) {
			if (v_flag)
				printf("  usage: (not included)\n");
		} else {
			ext = X509_get_ext(cert, index);
			if (v_flag){
				printf("  usage: ");
				X509V3_EXT_print_fp(stdout, ext, 0, 0);
				printf("\n");
			}
		}
		if (v_flag){
			printf("  %s fingerprint: ", OBJ_nid2sn(EVP_MD_type(fp_alg)));
			for (c = 0; c < (int)n; c++) {
				printf("%02X%c",md[c], (c + 1 == (int)n) ?'\n':':');
			}
		}

		/* Before to write the file, we need to check the certificate himself */
		if (v_flag)
			printf("%s: certificate %d must to be verify\n", pname, i);

		ret = check_verify_CA(cert, certs , &isRoot, &isRA);
		if (ret != 0)
		{
//			snprintf(name, sizeof(name)-1, "the CA cert file n° %d is not valid", i);
//			add_log(name, LOG_WARNING);
			warning("the CA cert file n° %d is not valid", i);
			exit (SCEP_PKISTATUS_FILE);
		}

		if (v_flag)
		{
			printf("%s: the certificate is valid\n", pname);
		}

		/* Write root CA */
		if (is_ROOT(cert) == 1)
		{
			// This is a Root certificate so we copy it with the filename rootca.crt en plus
			// We use this file when we enroll the certifiacte and the received trust chain is not complete
			char nameroot[1024] = {0};
			strncpy(nameroot,c_char_CA_certificate,sizeof(nameroot)-1);
			ExtractFilePath(nameroot);
			strncat(nameroot,"/rootca.crt",sizeof(nameroot)-1);
			fp = fopen(nameroot, "w");
			if (fp != NULL)
			{
				if (v_flag) printf("%s: certificate Root CA written in %s\n", pname, nameroot);
				if (PEM_write_X509(fp, cert) != 1) {
					//fprintf(stderr, "%s: error while writing certificate file\n", pname);
//					add_log("error while writing root CA certificate file", LOG_WARNING);
//					snprintf(name, sizeof(name)-1, "%s: %s", pname, ERR_error_string(ERR_get_error(),NULL));
//					add_log(name, LOG_WARNING);
					//ERR_print_errors_fp(stderr);
					warning("error while writing root CA certificate file : %s", ERR_error_string(ERR_get_error(),NULL));
					fclose(fp);
					exit (SCEP_PKISTATUS_FILE);
				}

				fclose(fp);
			}
		}

		/* Write PEM-formatted file: */
		if (WriteRA == 0)
		{
			// We write ca certificate file by file
			snprintf(nameroot,sizeof(nameroot)-1, "%s-%d",c_char_CA_certificate, (CAFileIndex));
			CAFileIndex++;
			fp = fopen(nameroot, "w");
			if (fp != NULL)
			{
				if (v_flag) printf("%s: certificate CA in individual file in %s\n", pname, nameroot);
				if (PEM_write_X509(fp, cert) != 1) {
					//fprintf(stderr, "%s: error while writing certificate file\n", pname);
//					add_log("error while writing individual certificate CA ", LOG_WARNING);
//					snprintf(name, sizeof(name)-1, "%s: %s", pname, ERR_error_string(ERR_get_error(),NULL));
//					add_log(name, LOG_WARNING);
					warning("error while writing individual certificate CA : %s", ERR_error_string(ERR_get_error(),NULL));
					fclose(fp);
					exit (SCEP_PKISTATUS_FILE);
				}

				fclose(fp);
			}

			// Pour l'écriture des CA, on fait un append pour ajouter les différents certificats dans un bundle
			fp = fopen(name, "a");
		}
		else
		{
			// Pour le certificat RA, on écrit uniquement le certificat ra
			fp = fopen(name, "w");
		}

		if (fp == NULL)
		{
			//fprintf(stderr, "%s: cannot open cert file for writing\n", pname);
			//add_log("cannot open cert file for writing", LOG_WARNING);
			warning("cannot open cert file for writing");
			exit (SCEP_PKISTATUS_FILE);
		}

		if (v_flag)
			printf("%s: certificate written in %s\n", pname, name);
		if (v_flag>1)
			PEM_write_X509(stdout, cert);

		// écriture du certificat dans le fichier pointé par fp
		if (PEM_write_X509(fp, cert) != 1) {
			//fprintf(stderr, "%s: error while writing certificate file\n", pname);
//			add_log("error while writing certificate file", LOG_WARNING);
//			ERR_print_errors_fp(stderr);
			warning("error while writing certificate file : %s", ERR_error_string(ERR_get_error(),NULL));
			fclose(fp);
			exit (SCEP_PKISTATUS_FILE);
		}

		fclose(fp);

		//
		if (WriteRA == 1)
		{
			// On a écrit le ra.crt.
			// On vérifie qu'il n'est pas nécessaire de copier ce certificat en ca.crt
			if (is_CA(cert) != 0)
			{
				// C'est un CA également
				// On doit l'ajouter dans la chaine de confiance ca.crt
				strncpy(name,c_char_CA_certificate,sizeof(name)-1);
				fp = fopen(name, "w");
				if (fp == NULL)
				{
					//fprintf(stderr, "%s: cannot open cert file for writing\n", pname);
					//add_log("cannot open cert file for writing", LOG_WARNING);
					warning("cannot open cert file for writing");
					exit (SCEP_PKISTATUS_FILE);
				}

				if (v_flag)
					printf("%s: certificate written in %s\n", pname, name);
				if (v_flag>1)
					PEM_write_X509(stdout, cert);
				if (PEM_write_X509(fp, cert) != 1) {
					//fprintf(stderr, "%s: error while writing certificate file\n", pname);
//					add_log("error while writing certificate file", LOG_WARNING);
//					snprintf(name, sizeof(name)-1, "%s: %s", pname, ERR_error_string(ERR_get_error(),NULL));
//					add_log(name, LOG_WARNING);
					warning("error while writing certificate file : %s", ERR_error_string(ERR_get_error(),NULL));
					fclose(fp);
					exit (SCEP_PKISTATUS_FILE);
				}

				fclose(fp);
			}
		}
	}

	PKCS7_free(p7);
	BIO_free(bio);
	exit (SCEP_PKISTATUS_SUCCESS);
}

/* Read local certificate (GetCert and GetCrl) */

X509 *
read_cert(const char *filename)
{
	FILE *file;
	X509 *res;

	if (
#ifdef WIN32
		(fopen_s(&file, filename, "r"))
#else
		!(file = fopen(filename, "r"))
#endif
		)
	{
		return NULL;
	}

	if (!(res = PEM_read_X509(file, NULL, NULL, NULL)))
	{
		//ERR_print_errors_fp(stderr);
		error("error read_cert : %s", ERR_error_string(ERR_get_error(),NULL));
	}
	fclose(file);

	return res;
}

/* Read CA cert and optionally, encyption CA cert */

void
guess_ca_certs(const char* filename, X509_NAME *issuer_name,
			   X509 **sigc, X509 **encc, X509 **issuer_cert)
{
	int ccnt, i, j;
	X509 *cert[20];

	ccnt = 0;
	/* read all certificates */
	while (ccnt < 20) {
		char name[1024];

		snprintf(name, sizeof(name)-1, "%s-%d", filename, ccnt);
		if (!(cert[ccnt] = read_cert(name)))
			break;

		ccnt++;
	}

	/* this is either NULL or the first certificate */
	*sigc = *encc = cert[0];

	for (i = 0; i < ccnt; i++) {
		X509_NAME *myname = X509_get_subject_name(cert[i]);
		int is_issuer = 0;

		/* the right CA is the final-one, either leaf or not */
		for (j = 0; j < ccnt; j++) {
			X509_NAME *issuer = X509_get_issuer_name(cert[j]);
			if (!X509_NAME_cmp(myname, issuer)) {
				is_issuer = 1;
				break;
			}
		}

		if (issuer_name != NULL && !X509_NAME_cmp(issuer_name, myname))
			*issuer_cert = cert[i];

		if (!is_issuer) {
			/* X509_get_key_usage(cert[i]) is not in older openssl */
			ASN1_BIT_STRING *usage = X509_get_ext_d2i(cert[i], NID_key_usage, NULL, NULL);
			if (usage && (usage->length > 0)) {
				if (usage->data[0] & KU_DIGITAL_SIGNATURE)
					*sigc = cert[i];
				if (usage->data[0] & KU_KEY_ENCIPHERMENT)
					*encc = cert[i];
			} else {
				/* no usability constraints */
				*sigc = *encc = cert[i];
			}
		}
	}

	/* release those we don't use */
	for (i = 0; i < ccnt; i++) {
		if (cert[i] != *sigc && cert[i] != *encc && cert[i] != *issuer_cert)
			X509_free(cert[i]);
	}

	if (v_flag) {
		char buffer[1024];

		if (*sigc)
			printf("%s: using RA certificate: %s\n", pname,
				X509_NAME_oneline(X509_get_subject_name(*sigc),
						buffer, sizeof(buffer)));
		if (*encc)
			printf("%s: using RA encryption certificate: %s\n", pname,
				X509_NAME_oneline(X509_get_subject_name(*encc),
						buffer, sizeof(buffer)));
		if (*issuer_cert)
			printf("%s: using issuer certificate: %s\n", pname,
				X509_NAME_oneline(X509_get_subject_name(*issuer_cert),
						buffer, sizeof(buffer)));
	}

}

/*
void read_cert_Engine(X509** cert, char* id, ENGINE *e, char* filename)
{
	BIO *bio, *b64;
	PCCERT_CONTEXT ctx = NULL;
	int ret;
	HCERTSTORE store;
	DWORD cbSize;
	LPTSTR pszName;
	LPSTR str;
	FILE *certfile;
	
	store = CertOpenSystemStore(0, L"MY");
	
	ctx = CertFindCertificateInStore(store, MY_ENCODING_TYPE, 0, CERT_FIND_SUBJECT_STR, (LPCSTR) id, NULL);
	if(!ctx) {
		while(ctx = CertEnumCertificatesInStore(store, ctx))
		{
			cbSize = CertGetNameString(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
			pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR));
			CertGetNameString(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszName, cbSize);
			cbSize = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK | WC_DEFAULTCHAR, (LPCWSTR) pszName, -1, NULL, 0, NULL, NULL);
			str = (LPSTR)malloc(cbSize * sizeof(LPSTR));
			WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK | WC_DEFAULTCHAR, (LPCWSTR) pszName, -1, str, cbSize, NULL, NULL);
			if(strstr(str, id)) {
				ret = 0;
				break;
			} else {
				ret = 127;
			}
		}
	}
	if(!ctx || ret != 0)
	{
		fprintf(stderr, "%s: cannot find Certificate with subject %s in store\n", pname, id);
		exit(SCEP_PKISTATUS_FILE);
	}

	certfile = fopen(filename, "w");
	fputs("-----BEGIN CERTIFICATE-----\n", certfile);
	fclose(certfile);

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_file(filename, "a");
	bio = BIO_push(b64, bio);
	ret = BIO_write(bio, ctx->pbCertEncoded, ctx->cbCertEncoded);
	ret = BIO_flush(bio);
	BIO_free_all(bio);

	certfile = fopen(filename, "a");
	fputs("-----END CERTIFICATE-----", certfile);
	fclose(certfile);

	read_cert(cert, filename);
}*/


/* Read private key */

EVP_PKEY *
read_key(char* filename)
{
	FILE *file;
	EVP_PKEY *res;
	/* Read private key file */
#ifdef WIN32
	if ((fopen_s(&file, filename, "r")))
#else
	if (!(file = fopen(filename, "r")))
#endif
	{
	    //fprintf(stderr, "%s: cannot open private key file %s\n", pname, filename);
		warning("cannot open private key file %s", filename);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (!(res = PEM_read_PrivateKey(file, NULL, NULL, NULL))) {
//	    fprintf(stderr, "%s: error while reading private key %s\n", pname, filename);
//		ERR_print_errors_fp(stderr);
		error("error while reading private key %s : %s",filename, ERR_error_string(ERR_get_error(),NULL));
		exit (SCEP_PKISTATUS_FILE);
	}
	fclose(file);
	return res;
}

/* Read PKCS#10 request */

void
read_request(void) {
	FILE *reqfile;

	/* Read certificate request file */
	if (!r_flag || 
#ifdef WIN32
		(fopen_s(&reqfile, r_char_Certificate_request_file, "r")))
#else
		!(reqfile = fopen(r_char_Certificate_request_file, "r")))
#endif
	{
		//fprintf(stderr, "%s: cannot open certificate request\n", pname);
		error("cannot open certificate request");
		exit (SCEP_PKISTATUS_FILE);
	}
	if (!PEM_read_X509_REQ(reqfile, &request, NULL, NULL)) {
//		fprintf(stderr, "%s: error while reading request file\n", pname);
//		ERR_print_errors_fp(stderr);
		error("error while reading request file %s : %s",r_char_Certificate_request_file, ERR_error_string(ERR_get_error(),NULL));
		exit (SCEP_PKISTATUS_FILE);
	}
	fclose(reqfile);
}

