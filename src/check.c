/*
 * check.c
 *
 * Ce fichier contient toutes les fonction de vérification des certificats
 *
 *  Created on: Dec 2, 2022
 *      Author: gege
 */

#include <stdint.h>
#include <time.h>
#include <syslog.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include "check.h"
#include "cert_template.h"
//#include "enedis_error.h"
#include "cmd.h"
#include "pkiclient.h"

//static X509* x509 = NULL;
//static X509_CRL* x509_crl = NULL;
//static int IsCRL = 0;
extern const EVP_MD *fp_alg;


/**
 * @fn		int32_t OpenX509_CRL_Certificate(FILE* chk_f, int chk_crl)
 * @brief 	Cette fonction permet d'ouvrir un fichier certificat ou CRL avant le traitement de vérification
 * @param 	chk_f FILE* : pointeur sur un fichier certificat déja ouvert
 * @param 	chk_crl int : permet de savoir si on a affaire à une crl ou pas. si =0, c'est un certificat, si !=0 c'est une crl
 * @return 	int error code, 0 all OK. !=0 error
 */
#if 0
int32_t OpenX509_CRL_Certificate(FILE* chk_f, int chk_crl)
{
	int32_t Ret = ERROR_OK;

	if (chk_f == NULL)
	{
		Ret = ERROR_FILE_NOT_OPEN;
	}

	if(chk_crl){
		x509_crl = PEM_read_X509_CRL(chk_f, NULL, NULL, NULL);

		if(x509_crl == NULL){
			add_log("Unable to read the CRL, maybe the format of the CRL is not PEM", LOG_ERR);
			Ret = ERROR_FILE_NOT_CRL;
		}

	}
	else{
		x509 = PEM_read_X509(chk_f, NULL, NULL, NULL);

		if(x509 == NULL){
			add_log("Unable to read the certificate, maybe the format of the certificate is not PEM", LOG_ERR);
			Ret = ERROR_FILE_NOT_X509;
		}
	}

	if (Ret == ERROR_OK)
	{
		IsCRL = chk_crl;
	}
	return(Ret);
}

/**
 * @fn	void CloseX509_CRL_Certificate(void)
 * @param : none
 * @return : none
 */
void CloseX509_CRL_Certificate(void)
{
	if(x509)
		X509_free(x509);

	if(x509_crl)
		X509_CRL_free(x509_crl);
}
#endif
/**
 * @fn		void display_hexa(uint8_t *before, uint8_t *after, uint8_t *buffer, size_t buffer_len)
 * @brief   Cette fonction permet d'afficher un buffer en hexa avec une chaine de début et une chaine de fin
 * @param 	before uint8_t * : pointeur sur la chaine de début à afficher
 * @param 	after uint8_t *: pointeur sur la chaine de fin à afficher
 * @param 	buffer uint8_t *: pointeur sur le tableau de valeur à afficher en hexadecimal
 * @param 	buffer_len size_t: longueur des données à afficher
 */
void display_hexa(uint8_t *before, uint8_t *after, uint8_t *buffer, size_t buffer_len){

	uint32_t i = 0;

	printf("%s", before);
	for(i = 0; i < buffer_len; i++){
		printf("%02X", buffer[i]);
	}
	printf("%s", after);
}

//static void display_hexa_table(uint8_t *buf, uint32_t buf_len, bool add_0x, bool add_comma){
//
//	uint32_t i = 0;
//
//	printf("\t");
//	for(i = 0; i < buf_len; i++){
//		if(add_0x)
//			printf("0x");
//		printf("%02x", buf[i]);
//		if(add_comma)
//			printf(",");
//		printf(" ");
//
//		if((i + 1) % 16 == 0){
//			printf("\n");
//			if((i + 1) < buf_len)
//				printf("\t");
//		}
//	}
//	if(i % 16 != 0)
//		printf("\n");
//
//}



/**
 * @fn		bool isNumber(char *str)
 * @brief	Cette fonction permet de vérifier si une chaine de caractères est un nombre ou pas
 * @param 	str char *: chaine de caractère
 * @return	valeur booleenne indiquant si la chaine de caractère est un nombre
 */
bool isNumber(char *str){
	//Check if str is a number

	int i = 0;
	int len = strlen(str);
	for(i = 0;i < len;i++){
		if(!isdigit(str[i])){
			return false;
		}
	}

	return true;
}

/**
 * @fn		int32_t check_validity(FILE* chk_f, int chk_crl)
 * @brief 	Cette fonction permet de vérifier la date entre le début et la fin de validité est bon
 * @param 	chk_f FILE* : pointeur sur un fichier certificat déja ouvert
 * @param 	chk_crl int : permet de savoir si on a affaire à une crl ou pas. si =0, c'est un certificat, si !=0 c'est une crl
 * @return 	int error code, 0 all OK. !=0 error
 */
int32_t check_validity(X509_CRL *x509_crl, X509 *x509)
{
	if ((x509_crl == NULL) && (x509 == NULL))
	{
		return(ERROR_UNABLE_READ_EXPIRATION_DATE);
	}
	if ((x509_crl != NULL) && (x509 != NULL))
	{
		return(ERROR_UNABLE_READ_EXPIRATION_DATE);
	}
	//Check delay between start and stop date

	//Get the expiration date
	//const ASN1_TIME *expiration_date = X509_get0_notAfter(x509);
	const ASN1_TIME *expiration_date = NULL;


	if(x509_crl != NULL){
		expiration_date = X509_CRL_get0_nextUpdate(x509_crl);
	}
	else{
		expiration_date = X509_get_notAfter(x509);
	}
	if(expiration_date == NULL){
		if(x509_crl != NULL){
			//add_log("Unable to get the next update date from the CRL", LOG_ERR);
			error("Unable to get the next update date from the CRL");

		}
		else{
			//add_log("Unable to get the expiration date from the certificate", LOG_ERR);
			error("Unable to get the expiration date from the certificate");
		}

		return(ERROR_UNABLE_READ_EXPIRATION_DATE);
	}

	//Get the issue date
	//const ASN1_TIME *issue_date = X509_get0_notBefore(x509);
	const ASN1_TIME *issue_date = NULL;
	if(x509_crl != NULL){
		issue_date = X509_CRL_get0_lastUpdate(x509_crl);
	}
	else{
		issue_date = X509_get_notBefore(x509);
	}
	if(issue_date == NULL){
		if(x509_crl != NULL){
			//add_log("Unable to get the last update date from the CRL", LOG_ERR);
			error("Unable to get the last update date from the CRL");
		}
		else{
			//add_log("Unable to get the issue date from the certificate", LOG_ERR);
			error("Unable to get the issue date from the certificate");
		}

		return(ERROR_UNABLE_TO_GET_ISSUE_DATE);
	}

	//Check the difference between start and stop date
	int day_expiration, sec_expiration = 0;
	if(!ASN1_TIME_diff(&day_expiration, &sec_expiration, issue_date, expiration_date)){
		//add_log("Unable to get the difference between start and stop date", LOG_ERR);
		error("Unable to get the difference between start and stop date");

		return(ERROR_UNABLE_CALCULATE_DIFF);
	}

//	snprintf(buf, sizeof(buf)-1, "Delay between start and stop date: %d day(s) %d second(s)", day_expiration, sec_expiration);
//	add_log(buf, LOG_NOTICE);
	notice("Delay between start and stop date: %d day(s) %d second(s)", day_expiration, sec_expiration);

	return (ERROR_OK);
}

#if 0

/**
 * @fn		int32_t check_extension(FILE* chk_f, int chk_crl, uint8_t *chk_extension)
 * @brief 	Cette fonction permet de vérifier si une extension est présente. Par défaut, elle imprime toutes les extensions
 * @param 	chk_f FILE* : pointeur sur un fichier certificat déja ouvert
 * @param 	chk_crl int : permet de savoir si on a affaire à une crl ou pas. si =0, c'est un certificat, si !=0 c'est une crl
 * @param	chk_extension uint8_t* : chaine de caractère de l'extension recherchée
 * @return 	int error code, 0 all OK. !=0 error
 */
int32_t check_extension(char *chk_extension)
{
	int nid = NID_undef;
	if(chk_extension[0] != 0){
		nid = OBJ_sn2nid(chk_extension);
	}

	int i, nb_ext;

	//Get the number of extension
	if(IsCRL){
		nb_ext = X509_CRL_get_ext_count(x509_crl);
	}
	else{
		nb_ext = X509_get_ext_count(x509);
	}
	if(nb_ext <= 0){
		add_log("No extension found", LOG_ERR);

		return(ERROR_NO_EXTENSION_FOUND);
	}

	for (i=0; i < nb_ext; i++) {
		ASN1_OBJECT *obj_name;
		//ASN1_OCTET_STRING *obj_data;
		X509_EXTENSION *ext;

		//Get the extension
		if(IsCRL){
			ext = X509_CRL_get_ext(x509_crl, i);
		}
		else{
			ext = X509_get_ext(x509, i);
		}

		//Get the extension type
		obj_name = X509_EXTENSION_get_object(ext);

		if(nid == 0 || OBJ_obj2nid(obj_name) == nid){

			//Get the space needed for the buffer of the extension name
			int len = i2t_ASN1_OBJECT(NULL, 0, obj_name);
			if(len <= 0){
				printf("Getting space for the buffer of the extension name for object=%d failed\n", i);
				continue;
			}

			//Allocate buffer
			char *buf_name;
			buf_name = malloc(len + 1);
			if(buf_name == NULL){
				printf("Allocating buffer of the extension name for object=%d failed\n", i);
				continue;
			}

			//Copy extension name in to the buffer
			i2t_ASN1_OBJECT(buf_name, len + 1, obj_name);

			//Get if extension is critical
			int critical = X509_EXTENSION_get_critical(ext);

			printf("Extension %d(%s): %s %s\n", i, OBJ_nid2sn(OBJ_obj2nid(obj_name)), buf_name, (critical == 1) ? "-> critical" : "");

			free(buf_name);
		}
	}

	return (ERROR_OK);
}

/**
 * @fn		int32_t check_basic_constraint(void)
 * @brief 	Cette fonction permet de vérifier
 * @param 	none
 * @return 	int error code, 0 all OK. !=0 error
 */
int32_t check_basic_constraint(void)
{
	if(IsCRL){
		add_log("Checking the Basic Constraints extension of a CRL makes no sense", LOG_ERR);
		return(ERROR_NOT_CHECKINGBASIC_CRL);
	}

	//Get basic constraints structure
	BASIC_CONSTRAINTS *bs;
	if((bs = X509_get_ext_d2i(x509, NID_basic_constraints, NULL, NULL))){

		printf("CA=%s\n", (bs->ca == 0) ? "FALSE" : "TRUE");
		if(bs->pathlen){
			printf("PathLen=%ld\n", ASN1_INTEGER_get(bs->pathlen));
		}
	}
	else{
		add_log("Basic Constraints not found in the certificate", LOG_ERR);

		return(ERROR_MISSING_BASIC_CONSTRAIN);
	}

	return (ERROR_OK);
}

/**
 * @fn		int32_t check_crl_distribution_point(void)
 * @brief 	Cette fonction permet de vérifier
 * @param 	none
 * @return 	int error code, 0 all OK. !=0 error
 */
int32_t check_crl_distribution_point(void)
{
	if(IsCRL){
		printf("Checking the CRL Distribution Point extension of a CRL makes no sense\n");
		add_log("Checking the CRL Distribution Point extension of a CRL makes no sense", LOG_ERR);
		return(ERROR_NOT_CHECKING_DISTRIBUTION_CRL);
	}

	//Get CRL Distribution Point
	STACK_OF(DIST_POINT) *crldp;
	if((crldp = X509_get_ext_d2i(x509, NID_crl_distribution_points, NULL, NULL))){

		int i = 0;
		int cnt = 0;
		for(i = 0; i < sk_DIST_POINT_num(crldp); i++) {
			DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
			if(!dp->distpoint || dp->distpoint->type != 0){
				printf("CRL Distribution Point not found in the certificate\n");
				add_log("CRL Distribution Point not found in the certificate", LOG_ERR);
				sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);

				return(ERROR_MISSING_CRL_DISTRIBUTION_POINT);
			}

			GENERAL_NAMES *gens;
			gens = dp->distpoint->name.fullname;

			int y = 0;
			for(y = 0; y < sk_GENERAL_NAME_num(gens); y++) {
				GENERAL_NAME *gen;
				gen = sk_GENERAL_NAME_value(gens, y);

				ASN1_STRING *uri;
				int gtype = 0;
				uri = GENERAL_NAME_get0_value(gen, &gtype);
				if(gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
					const char *uptr = (const char *)ASN1_STRING_get0_data(uri);
					if(strncmp(uptr, "http://", 7) == 0 || strncmp(uptr, "https://", 8) == 0){
						printf("URL-%d=%s\n", cnt, uptr);
						cnt++;
					}
				}
			}
		}
	}
	else{
		printf("CRL Distribution Point not found in the certificate\n");
		add_log("CRL Distribution Point not found in the certificate", LOG_ERR);
		sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);

		return(ERROR_MISSING_CRL_DISTRIBUTION_POINT);
	}

	sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);

	return (ERROR_OK);
}
#endif
/**
 * @fn		int32_t check_fingerprint(const X509 *x509, char *Fpt_filename)
 * @brief	Cette fonction permet de vérifier si le fingerprint d'un fichier est bien celui du certificat
 * @param 	x509 const X509 *: pointeur sur le certificat dont on doit examiner le fingerprint
 * @param 	Fpt_filename char *: Nom du fichier contenant le fingerprint
 * @return  int32_t : Valeur de retour ERROR_BAD_FINGERPRINT si le fingerprint est différent ou le fichier n'existe pas
 * 			et ERROR_OK si c'est le même
 */
int32_t check_fingerprint(const X509 *x509, char *Fpt_filename)
{
	FILE * fpt = NULL;
	char strfingerprint_ref[1024] = {0}; // fingerprint de référence en chaine de caractère
	unsigned char		FPRef[EVP_MAX_MD_SIZE]; // fingerprint de référence du certificat en binaire
	unsigned int		n;
	unsigned char		md[EVP_MAX_MD_SIZE]; // fingerprint récupéré du certificat en binaire
	char *pC = NULL;
	int16_t i,j,k;
	int16_t lg;
	char octet;
	char car;

	fpt = fopen(Fpt_filename,"r");
	if (fpt != NULL)
	{
		// Le fichier existe, on va lire le fingerprint contenu dedans
		pC = fgets(strfingerprint_ref, sizeof(strfingerprint_ref)-1, fpt);
		fclose(fpt);
		if (pC == NULL) {
			//add_log("The fingerprint file is empty", LOG_WARNING);
			warning("The fingerprint file is empty");
			return (ERROR_BAD_FINGERPRINT);
		}

		// On convertit la chaine de fingerprint en donnée binaire
		lg = strlen(strfingerprint_ref);
		octet = 0;
		j = 0;
		k = 0;
		for (i=0; i<lg; i++)
		{
			car = strfingerprint_ref[i];
			if (car == 0) break;
			if (((car >= 'a')
				&& (car <= 'f'))
				|| ((car >= 'A')
				&& (car <= 'F'))
				|| ((car >= '0')
				&& (car <='9')))
			{
				// On a bien un caractère de traitement
				if ((car >= 'a') && (car <= 'f'))
				{
					octet = (car - 'a')  + 10;
				}
				else if ((car >= 'A') && (car <= 'F'))
				{
					octet = (car - 'A')  + 10;
				}
				else
				{
					octet = car -'0';
				}
				if (k == 0)
				{
					// On est sur la parti haute de l'octet à convertir
					FPRef[j] = (octet << 4);
					k++;
				} else
				{
					// on est sur la partie basse de l'octet
					FPRef[j] |= octet;
					j++;
					if (j>= EVP_MAX_MD_SIZE)
					{
						break;
					}
					k = 0;
				}
			}
		}

		// On calcule le fingerprint du certificat
		if (!X509_digest(x509, fp_alg, md, &n)) {
			//add_log("Impossible to digest the fingerprint", LOG_WARNING);
			warning("Impossible to digest the fingerprint");
			return (ERROR_BAD_FINGERPRINT);
		}
		// On compare les fingerprints
		for (i=0; i<n; i++)
		{
			if (md[i] != FPRef[i])
			{
				//add_log("Bad fingerprint", LOG_WARNING);
				warning("Bad fingerprint");
				return (ERROR_BAD_FINGERPRINT);
			}
		}
	}
	//add_log("fingerprint is valid", LOG_WARNING);
	notice("fingerprint is valid");
	return (ERROR_OK);
}

/**
 * @fn
 * @brief	Cette fonction permet de vérifier si un certificat CA est authentique ou pas
 * @param 	none
 * @return
 */
int32_t check_verify_CA(const X509 *x509 , STACK_OF(X509) *chain, int32_t *isroot, int32_t *isRA) //FILE* chk_conf_file,
{
	int32_t ret=ERROR_CERTIFICATE_INVALID;
	//int32_t root=0; // ce n'est pas un certificat root au démarrage
	time_t in_time;

	ASN1_TIME *expiration_date = NULL;
	X509_NAME *issuer_name;
	X509_NAME *subject_name;
    char issuer_str[250];
    char subject_str[250];
	int cmp_time = 0;
	int32_t roottmp = 0;	// Par défaut on considére que ce n'est pas un certificat root
	int32_t RAtmp = 1;	    // Par défaut, on considére que le certificat est un certificat RA (CA:FALSE)

	// #Check certificate validity by the date
	// On lit la date courante
	time(&in_time);

	// On lit la date d'expiration
	expiration_date = X509_get_notAfter(x509);

	// On vérifie que la lecture s'est bien passée
	if(expiration_date == NULL){
		//add_log("Unable to get the expiration date from the certificate", LOG_ERR);
		error("Unable to get the expiration date from the certificate");
		if (isroot != NULL)	{
			*isroot = roottmp;
		}
		if (isRA != NULL)	{
			*isRA = RAtmp;
		}
		return(ERROR_UNABLE_READ_EXPIRATION_DATE);
	}

	//Check the expiration date
	cmp_time = X509_cmp_time(expiration_date, &in_time);
	if(cmp_time == 0){
		//add_log("Unable to check date", LOG_ERR);
		warning("Unable to check date");
		if (isroot != NULL)	{
			*isroot = roottmp;
		}
		if (isRA != NULL)	{
			*isRA = RAtmp;
		}
		return(ERROR_UNABLE_CHECK_DATE);
	}
	else if(cmp_time > 0){
		//Not expired
		//add_log("Certificate is not expired", LOG_NOTICE);
		notice("Certificate is not expired");

	}
	else{
		//Expired
		//add_log("Certificate has expired", LOG_WARNING);
		warning("Certificate has expired");
		if (isroot != NULL)	{
			*isroot = roottmp;
		}
		if (isRA != NULL)	{
			*isRA = RAtmp;
		}
		return(ERROR_CRL_CERTIFICATE_EXPIRED);
	}

	// #Check certificate chain
	// On vérifie si le certificat est un certificat root ou non
	// On récupére l'issuer
	issuer_name = X509_get_issuer_name(x509);
	if (issuer_name == NULL)
	{
		if (isroot != NULL)	{
			*isroot = roottmp;
		}
		if (isRA != NULL)	{
			*isRA = RAtmp;
		}
		return(ERROR_ISSUER_UNREADABLE);
	}

	X509_NAME_oneline(issuer_name, issuer_str, sizeof(issuer_str));
    if (strlen(issuer_str) == 0)
    {
		if (isroot != NULL)	{
			*isroot = roottmp;
		}
		if (isRA != NULL)	{
			*isRA = RAtmp;
		}
    	return(ERROR_ISSUER_UNREADABLE);
    }

	// On récupére le subject
	subject_name = X509_get_subject_name(x509);
	if (subject_name == NULL)
	{
		if (isroot != NULL)	{
			*isroot = roottmp;
		}
		if (isRA != NULL)	{
			*isRA = RAtmp;
		}
		return(ERROR_SUBJECT_UNREADABLE);
	}
	X509_NAME_oneline(subject_name, subject_str, sizeof(subject_str));
	if (strlen(issuer_str) == 0)
	{
		if (isroot != NULL)	{
			*isroot = roottmp;
		}
		if (isRA != NULL)	{
			*isRA = RAtmp;
		}
		return(ERROR_ISSUER_UNREADABLE);
	}

	// On compare l'issuer et le subject pour savoir si c'est un CA root
	if (strcmp(subject_str,issuer_str) == 0)
	{
		roottmp = 1;
	}

	RAtmp = is_RA(x509);

	// On attaque la vérification
	if ((roottmp) == 1)
	{
		// This is a root certificate
		// #Check certificate template
		//ret = check_template_ca(x509, &RAtmp);
		if (x_char_certificate_template_filename != NULL)
		{
			ret = check_template_by_file(x509, x_char_certificate_template_filename, RAtmp);
		}
		else
		{
			ret = 0;
		}

		if (P_flag_fingerprint_filename)
		{
			// Check with a finger print
			ret = check_fingerprint(x509, P_char_fingerprint_filename);
		}
		else if (a_flag_PATH_Trust_Anchor)
		{
			// Check is this root certificate is in the trust anchor ...
			ret = check_CA_inTA(x509, a_char_PATH_Trust_Anchor);
		}
		else
		{
			ret = 0;
		}
	}
	else
	{
		// This is an intermediate CA certificate
		// #Check certificate template
		//ret = check_template_ca(x509, &RAtmp);
		if (x_char_certificate_template_filename != NULL)
		{
			ret = check_template_by_file(x509, x_char_certificate_template_filename, RAtmp);
		}
		else
		{
			ret = 0;
		}

		// #Check signature of the intermediate
		if ((ret == 0) && (chain != NULL))
		{
			ret = check_authenticated_chain(x509, chain);
		}
	}

	if (isroot != NULL)	{
		*isroot = roottmp;
	}
	if (isRA != NULL)	{
		*isRA = RAtmp;
	}
	return (ret);
}


/**
 * @fn		int32_t check_verify_cert(void)
 * @brief	Cette fonction permet de vérifier si un certificat est authentique ou pas
 * 			Pour le template, il est necessaire de préciser le type de certificat
 * @param	x509 X509*: pointeur sur le certificat à controler
 * @param 	certs STACK_OF(X509) * : bundle de certificats CA de confiance necessaire pour l'authentification du certificat
 * @return  int32_t : ERROR_OK si c'est OK sinon, un numero d'erreur
 */
int32_t check_verify_cert(const X509 *x509, STACK_OF(X509) *certs) //FILE* chk_conf_file,
{
	int32_t ret=ERROR_OK;
	EVP_PKEY *pkey;
	time_t in_time;
	ASN1_TIME *expiration_date = NULL;
	X509_NAME *issuer_name;
	X509_NAME *subject_name;
	char issuer_str[250];
	char subject_str[250];
	int cmp_time = 0;
	char fileCAPath[512] = {0};
	int i = 0;

	// #Check certificate validity by the date
	// On lit la date courante
	time(&in_time);

	// On lit la date d'expiration
	expiration_date = X509_get_notAfter(x509);


	// On vérifie que la lecture s'est bien passée
	if(expiration_date == NULL){
		//add_log("Unable to get the expiration date from the certificate", LOG_ERR);
		error("Unable to get the expiration date from the certificate");
		return(ERROR_UNABLE_READ_EXPIRATION_DATE);
	}

	//Check the expiration date
	cmp_time = X509_cmp_time(expiration_date, &in_time);
	if(cmp_time == 0){
		//add_log("Unable to check date", LOG_ERR);
		error("Unable to check date");
		return(ERROR_UNABLE_CHECK_DATE);
	}
	else if(cmp_time > 0){
		//Not expired
		//add_log("Certificate is not expired", LOG_NOTICE);
		notice("Certificate is not expired");
	}
	else{
		//Expired
		//add_log("Certificate has expired", LOG_NOTICE);
		warning("Certificate has expired");
		return(ERROR_CRL_CERTIFICATE_EXPIRED);
	}

	// #Check certificate chain
	// On vérifie si le certificat est un certificat root ou non
	// On récupére l'issuer
	issuer_name = X509_get_issuer_name(x509);
	if (issuer_name == NULL)
	{
		return(ERROR_ISSUER_UNREADABLE);
	}

	X509_NAME_oneline(issuer_name, issuer_str, sizeof(issuer_str));
	if (strlen(issuer_str) == 0)
	{
		return(ERROR_ISSUER_UNREADABLE);
	}

	// On récupére le subject
	subject_name = X509_get_subject_name(x509);
	if (subject_name == NULL)
	{
		return(ERROR_SUBJECT_UNREADABLE);
	}
	X509_NAME_oneline(subject_name, subject_str, sizeof(subject_str));
	 if (strlen(issuer_str) == 0)
	{
		return(ERROR_ISSUER_UNREADABLE);
	}
	// #Check certificate template
	if (x_char_certificate_template_filename != NULL)
	{
		ret = check_template_by_file(x509, x_char_certificate_template_filename, 0); // This is not a RA certificate so alls rules must verify...
	}

	if (ret != ERROR_OK)
	{
		return(ret);
	}

	// #Check certificate validity
	ret = check_validity(NULL, x509);
	if (ret != ERROR_OK)
	{
		return(ret);
	}

	// #Check certificate chain
	if (sk_X509_num(certs) <= 1)
	{
		// There is only the final certificate so we need to read the trust chain if possible
		if (c_char_CA_certificate != NULL)
		{
			// read the trust chain
			// Get the CA path
			strncpy(fileCAPath, c_char_CA_certificate,sizeof(fileCAPath) - 1);
			i = ExtractFilePath(fileCAPath);
			if (i != 1)
			{
				//printf("Error, impossible to find the path of the CA file to write the trust chain !\n");
				//add_log("impossible to find the root CA path in c_char. Impossible to write the trust chain !", LOG_WARNING);
				warning("impossible to find the root CA path in c_char. Impossible to write the trust chain !");
				return (ERROR_LOADING_CA_CHAIN);
			}
			Add_ca_from_dir(fileCAPath, certs, 1);
		}
		else
		{
			//add_log("No authentification of the certificate with chain of trust because there isn't any trust chain\n", LOG_NOTICE);
			notice("No authentification of the certificate with chain of trust because there isn't any trust chain");
		}
	}
	if (sk_X509_num(certs) > 1)
	{
		ret = check_authenticated_chain(x509, certs);
	}
	else
	{
		//add_log("Can't authenticate one certificate\n", LOG_NOTICE);
		notice("Can't authenticate one certificate");
	}
	if (ret != ERROR_OK)
	{
		return(ret);
	}

	// #Check public key if readable
	pkey = X509_get_pubkey(x509);
	if (pkey == NULL)
	{
		ret = ERROR_CERT_BAD_PUBKEY;
	}
	//
	//

	return (ret);
}


/**
 * @fn		int32_t check_verify_CRL(void)
 * @brief	Cette fonction permet de vérifier si une CRL est valide ou pas
 * @param 	none
 * @return
 */
int32_t check_verify_CRL(X509_CRL *x509_crl)
{
	int32_t ret = ERROR_OK;
	time_t in_time;
	ASN1_TIME *expiration_date = NULL;
	int cmp_time = 0;

	// verification de la signature
	//ret = verifyCRL(x509_crl, CA_filename);
	// #Check certificate validity by the date
	// On valide par la même la présence des champs this update et nextupdate
	// On lit la date courante
	time(&in_time);

	// On lit la date d'expiration
	expiration_date = X509_CRL_get0_nextUpdate(x509_crl);
	if(expiration_date == NULL){
		//add_log("Unable to get the next update date from the CRL", LOG_ERR);
		error("Unable to get the next update date from the CRL");
		return(ERROR_UNABLE_READ_EXPIRATION_DATE);
	}

	//Check the expiration date
	cmp_time = X509_cmp_time(expiration_date, &in_time);
	if(cmp_time == 0){
		//add_log("Unable to check date", LOG_ERR);
		error("Unable to check date");
		return(ERROR_UNABLE_CHECK_DATE);
	}
	else if(cmp_time > 0){
		//Not expired
		//add_log("CRL is not expired", LOG_NOTICE);
		notice("CRL is not expired");
	}
	else{
		//Expired
		//add_log("CRL has expired", LOG_NOTICE);
		warning("CRL has expired");
		return(ERROR_CRL_CERTIFICATE_EXPIRED);
	}

	// verification du format
	ret = check_template_crl(x509_crl);
	if (ret != ERROR_OK)
	{
		return(ret);
	}
	// verification de la signature
	//ret = verifyCRL(x509_crl, CA_filename);
	//TODO: Faire la vérification de la CRL avec sa chaine de confiance

	return(ret);
}


/**
 * @fn		int32_t check_authenticated_CAfile(X509 *x509, const char * ca_bundlestr)
 * @brief	Cette fonction valide l'authentification du certificat avec la chaine de confiance
 * @param   x509 X509* : pointeur sur le certificat à valider
 * @param 	ca_bundlestr char * : nom du fichier avec son chemin du CA de vérification ou du bundle
 * @return  int32_t : etat d'erreur : 0 tout est OK, sinon, l'erreur vient de la liste de check.h
 */
int32_t check_authenticated_CAfile(X509 *x509, const char * ca_bundlestr)
{
	int32_t Ret = 0;
	int ret;


	/* ------------------------------------------------------------ *
	 * file:        certverify.c                                    *
	 * purpose:     Example code for OpenSSL certificate validation *
	 * author:      06/12/2012 Frank4DD                             *
	 * code recupere sur :											*
	 * 	https://fm4dd.com/openssl/certverify.shtm					*
	 *                                                              *
	 * gcc -o certverify certverify.c -lssl -lcrypto                *
	 * ------------------------------------------------------------ */

//	X509          *error_cert = NULL;
//
//	X509_NAME    *certsubject = NULL;
	X509_STORE         *store = NULL;
	X509_STORE_CTX  *vrfy_ctx = NULL;


	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* ---------------------------------------------------------- *
	* Initialize the global certificate validation store object. *
	* ---------------------------------------------------------- */
	if (!(store=X509_STORE_new()))
	{
		//add_log("Error creating X509_STORE_CTX object", LOG_NOTICE);
		warning("Error creating X509_STORE_CTX object");
		return(ERROR_UNABLE_CREATE_CTX);
	}
	/* ---------------------------------------------------------- *
	* Create the context structure for the validation operation. *
	* ---------------------------------------------------------- */
	vrfy_ctx = X509_STORE_CTX_new();

	/* ---------------------------------------------------------- *
	* Load the certificate and cacert chain from file (PEM).     *
	* ---------------------------------------------------------- */
//	ret = BIO_read_filename(certbio, cert_filestr);
//	if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
//	BIO_printf(outbio, "Error loading cert into memory\n");
//	exit(-1);
//	}

	ret = X509_STORE_load_locations(store, ca_bundlestr, NULL);
	if (ret != 1)
	{
		//add_log("Error loading CA cert or chain file", LOG_NOTICE);
		warning("Error loading CA cert or chain file");
		if (store != NULL) X509_STORE_free(store);
		if (vrfy_ctx != NULL) X509_STORE_CTX_free(vrfy_ctx);

		return(ERROR_LOADING_CA_CHAIN);
	}
	/* ---------------------------------------------------------- *
	* Initialize the ctx structure for a verification operation: *
	* Set the trusted cert store, the unvalidated cert, and any  *
	* potential certs that could be needed (here we set it NULL) *
	* ---------------------------------------------------------- */
	X509_STORE_CTX_init(vrfy_ctx, store, x509, NULL);

	/* ---------------------------------------------------------- *
	* Check the complete cert chain can be build and validated.  *
	* Returns 1 on success, 0 on verification failures, and -1   *
	* for trouble with the ctx object (i.e. missing certificate) *
	* ---------------------------------------------------------- */
	ret = X509_verify_cert(vrfy_ctx);
//	snprintf(buf,sizeof(buf)-1,"Authentification : Verification return code: %d", ret);
//	add_log(buf, LOG_NOTICE);
	notice("Authentification : Verification return code: %d", ret);

//	snprintf(buf,sizeof(buf)-1,"Authentification : Verification error code: %d", X509_STORE_CTX_get_error(vrfy_ctx));
//	add_log(buf, LOG_NOTICE);
	notice("Authentification : Verification error code: %d", X509_STORE_CTX_get_error(vrfy_ctx));

	if(ret == 0 || ret == 1)
	{
//		snprintf(buf,sizeof(buf)-1,"Authentification : Verification result text: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(vrfy_ctx)));
//		add_log(buf, LOG_NOTICE);
		notice("Authentification : Verification result text: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(vrfy_ctx)));
	}

	if (ret == 1)
	{
		Ret = 0;
	}
	else
	{
		Ret = ERROR_CERT_NOT_VALID_CA_CHAIN;
	}

	/* ---------------------------------------------------------- *
	* The error handling below shows how to get failure details  *
	* from the offending certificate.                            *
	* ---------------------------------------------------------- */
//	if(ret == 0) {
//		/*  get the offending certificate causing the failure */
//		error_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
//		certsubject = X509_NAME_new();
//		certsubject = X509_get_subject_name(error_cert);
//		printf(outbio, "Verification failed cert:\n");
//		X509_NAME_print(outbio, certsubject, 0, XN_FLAG_MULTILINE);
//		BIO_printf(outbio, "\n");
//	}

	/* ---------------------------------------------------------- *
	* Free up all structures                                     *
	* ---------------------------------------------------------- */
	if (store != NULL) X509_STORE_free(store);
	if (vrfy_ctx != NULL) X509_STORE_CTX_free(vrfy_ctx);

	return (Ret);
}

/**
 * @fn		int32_t check_authenticated_chain(X509 *x509, STACK_OF(X509) *chain)
 * @brief	Cette fonction valide l'authentification du certificat avec la chaine de confiance
 * @param   x509 X509* : pointeur sur le certificat à valider
 * @param 	chain STACK_OF(X509) * : nom du fichier avec son chemin du CA de vérification ou du bundle
 * @return  int32_t : etat d'erreur : 0 tout est OK, sinon, l'erreur vient de la liste de check.h
 */
int32_t check_authenticated_chain(X509 *x509, STACK_OF(X509) *chain)
{
	int32_t Ret = 0;
	int ret;
	int ErrorCode = X509_V_OK;
	int i;
	X509_NAME *issuer_name;
	X509_NAME *subject_name;
	char issuer_str[250];
	char subject_str[250];
	X509 * cert;

	if (v_flag)
	{
		printf("check_authenticated_chain : %d certificate in the chain of trust\n", sk_X509_num(chain));
	}

	if (sk_X509_num(chain) <= 1)
	{
		// We can't validate the certificate because there is no chain
		//add_log("No authentification of the certificate with chain of trust because there isn't any trust chain\n", LOG_NOTICE);
		notice("No authentification of the certificate with chain of trust because there isn't any trust chain");
		return(0);
	}
	if (v_flag > 1)
	{
		for (i=0; i<sk_X509_num(chain);i++)
		{
			cert = sk_X509_value(chain, i);
			issuer_name = X509_get_issuer_name(cert);
			subject_name = X509_get_subject_name(cert);
			X509_NAME_oneline(issuer_name, issuer_str, sizeof(issuer_str));
			X509_NAME_oneline(subject_name, subject_str, sizeof(subject_str));
			//printf("Certificate n°%d has issuer : %s; subject : %s\n",i, issuer_str, subject_str);
			debug("Certificate n°%d has issuer : %s; subject : %s\n",i, issuer_str, subject_str);
		}
	}
	/* ------------------------------------------------------------ *
	 * file:        certverify.c                                    *
	 * purpose:     Example code for OpenSSL certificate validation *
	 * author:      06/12/2012 Frank4DD                             *
	 * code recupere sur :											*
	 * 	https://fm4dd.com/openssl/certverify.shtm					*
	 *                                                              *
	 * gcc -o certverify certverify.c -lssl -lcrypto                *
	 * ------------------------------------------------------------ */

	X509_STORE_CTX  *vrfy_ctx = NULL;


	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* ---------------------------------------------------------- *
	* Create the context structure for the validation operation. *
	* ---------------------------------------------------------- */
	vrfy_ctx = X509_STORE_CTX_new();

	/* ---------------------------------------------------------- *
	* Initialize the ctx structure for a verification operation: *
	* Set the trusted cert store, the unvalidated cert, and any  *
	* potential certs that could be needed (here we set it NULL) *
	* ---------------------------------------------------------- */
	X509_STORE_CTX_init(vrfy_ctx, NULL, x509, chain);

	/* ---------------------------------------------------------- *
	* Check the complete cert chain can be build and validated.  *
	* Returns 1 on success, 0 on verification failures, and -1   *
	* for trouble with the ctx object (i.e. missing certificate) *
	* ---------------------------------------------------------- */
	ret = X509_verify_cert(vrfy_ctx);
//	snprintf(buf,sizeof(buf)-1,"Authentification : Verification return code: %d", ret);
//	add_log(buf, LOG_NOTICE);
	notice("Authentification : Verification return code: %d", ret);

	ErrorCode = X509_STORE_CTX_get_error(vrfy_ctx);
//	snprintf(buf,sizeof(buf)-1,"Authentification : Verification error code: %d", ErrorCode );
//	add_log(buf, LOG_NOTICE);
	notice("Authentification : Verification error code: %d", ErrorCode);

	// Remove some error code
	if (ErrorCode != X509_V_OK)
	{
		if ((ErrorCode == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
			|| (ErrorCode == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) )
		{
			ErrorCode = X509_V_OK;
			ret = 1;
		}
	}

	if(ret == 0 || ret == 1)
	{
//		snprintf(buf,sizeof(buf)-1,"Authentification : Verification result text: %s", X509_verify_cert_error_string(ErrorCode));
//		add_log(buf, LOG_NOTICE);
		notice("Authentification : Verification result text: %s", X509_verify_cert_error_string(ErrorCode));
	}

	if (ret == 1)
	{
		Ret = 0;
	}
	else
	{
		Ret = ERROR_CERT_NOT_VALID_CA_CHAIN;
	}

	/* ---------------------------------------------------------- *
	* The error handling below shows how to get failure details  *
	* from the offending certificate.                            *
	* ---------------------------------------------------------- */
//	if(ret == 0) {
//		/*  get the offending certificate causing the failure */
//		error_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
//		certsubject = X509_NAME_new();
//		certsubject = X509_get_subject_name(error_cert);
//		printf(outbio, "Verification failed cert:\n");
//		X509_NAME_print(outbio, certsubject, 0, XN_FLAG_MULTILINE);
//		BIO_printf(outbio, "\n");
//	}

	/* ---------------------------------------------------------- *
	* Free up all structures                                     *
	* ---------------------------------------------------------- */
	if (vrfy_ctx != NULL) X509_STORE_CTX_free(vrfy_ctx);

	return (Ret);
}

/**
 * @fn int32_t check_CA_inTA(X509*, char*)
 * @brief Cette fonction permet de vérifier que le fichier rootCA est présent
 *    dans le dossier TA CADir
 *
 * @param cert X509 *: certificat à vérifier
 * @param CADir char *: Dossier ou se trouve les certificats
 * @return ERROR_OK si oui et ERROR_CERT_NOT_VALID_CA_CHAIN si non
 */
int32_t check_CA_inTA(const X509 *cert, const char * CADir)
{
	int32_t 		ret = ERROR_CERT_NOT_VALID_CA_CHAIN;
	BIO 			*InCertBIO = NULL;
	char 			CAFileName[512] = {0};
	X509 			*cert_CA = NULL;
	int 			i;
	struct dirent 	*dir = NULL;
	DIR 			*d = NULL;
	unsigned char	FPRef[EVP_MAX_MD_SIZE] = {0}; // fingerprint de référence du certificat en binaire
	unsigned int    nRef = 0;
	unsigned int	n = 0;
	unsigned char	md[EVP_MAX_MD_SIZE] = {0}; // fingerprint récupéré du certificat en binaire

	if ((cert != NULL)
		&& (CADir != NULL))
	{
		d = opendir(CADir);
		if (d != NULL)
		{
			// On créé un objet BIO pour pouvoir lire un fichier de certificat dans libopenssl
			InCertBIO = BIO_new(BIO_s_file());

			// Avant la comparaison, on calcule le fingerprint de notre certificat
			if (!X509_digest(cert, fp_alg, FPRef, &nRef)) {
				//add_log("Impossible to digest the first fingerprint for checking", LOG_WARNING);
				warning("Impossible to digest the first fingerprint for checking");
				if (d != NULL) closedir(d);
				if (InCertBIO) BIO_free(InCertBIO);
				return (ERROR_BAD_FINGERPRINT);
			}

			// On va chercher dans le TA le si le CA est présent
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
						if (!X509_digest(cert_CA, fp_alg, md, &n)) {
							//add_log("Impossible to digest the reference fingerprint for checking", LOG_WARNING);
							warning("Impossible to digest the reference fingerprint for checking");
							if (d != NULL) closedir(d);
							if (InCertBIO) BIO_free(InCertBIO);
							return (ERROR_BAD_FINGERPRINT);
						}
						// On compare les fingerprints
						ret = ERROR_OK;
						for (i=0; i<n; i++)
						{
							if (md[i] != FPRef[i])
							{
								ret = (ERROR_CERT_NOT_VALID_CA_CHAIN);
								break;
							}
						}
						if (ret == ERROR_OK)
						{
							break;
						}
					}
				}
			}
			if (d != NULL) closedir(d);
			if (InCertBIO) BIO_free(InCertBIO);
		}
	}

	return (ret);
}

/**
 * @fn 		int32_t verifyCRL( X509_CRL* crl, X509* ca )
 * @param crl X509_CRL*: pointeur sur la CRL à vérifier
 * @param ca X509*: pointeur sur le certificat qui a signé la CRL
 * @return
 */
int32_t verifyCRL( X509_CRL* crl, const char * ca_bundlestr )
{
	int 				rv = 0;
	int32_t 			ret = ERROR_OK;
	EVP_PKEY* 			pkey = NULL;
	FILE* 				ca_f = NULL;
	X509_STORE_CTX  	*xsc = NULL;
	X509_STORE         	*xst = NULL;
	X509_OBJECT        	*xobj = NULL;



	ca_f = fopen(ca_bundlestr,"r");
	if (ca_f == NULL)
	{
		return(ERROR_CRL_UNABLE_CA);
	}

	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* ---------------------------------------------------------- *
	* Create the context structure for the validation operation. *
	* ---------------------------------------------------------- */
	xsc = X509_STORE_CTX_new();

	/* ---------------------------------------------------------- *
	* Initialize the global certificate validation store object. *
	* ---------------------------------------------------------- */
	if (!(xst=X509_STORE_new()))
	{
		//add_log("Error creating X509_STORE object", LOG_NOTICE);
		warning("Error creating X509_STORE object");
		if (xsc != NULL) X509_STORE_CTX_free(xsc);
		if (ca_f != NULL) fclose(ca_f);
		return(ERROR_UNABLE_CREATE_CTX);
	}

	/*
	 * Initialise the object
	 */
	if (!(xobj=X509_OBJECT_new()))
	{
		//add_log("Error creating X509_OBJECT", LOG_NOTICE);
		warning("Error creating X509_OBJECT");
		if (xst != NULL) X509_STORE_free(xst);
		if (xsc != NULL) X509_STORE_CTX_free(xsc);
		if (ca_f != NULL) fclose(ca_f);
		return(ERROR_UNABLE_CREATE_CTX);
	}

	// On récupére le bundle de certificats
	rv = X509_STORE_load_locations(xst, ca_bundlestr, NULL);
	if (rv != 1)
	{
		//add_log("Error loading CA cert or chain file", LOG_NOTICE);
		warning("Error loading CA cert or chain file");
		if (xst != NULL) X509_STORE_free(xst);
		if (xsc != NULL) X509_STORE_CTX_free(xsc);
		if (xobj != NULL) X509_OBJECT_free(xobj);
		if (ca_f != NULL) fclose(ca_f);
		return(ERROR_LOADING_CA_CHAIN);
	}

	/* ---------------------------------------------------------- *
	* Initialize the ctx structure for a verification operation: *
	* Set the trusted cert store, the unvalidated cert, and any  *
	* potential certs that could be needed (here we set it NULL) *
	* ---------------------------------------------------------- */
	X509_STORE_CTX_init(xsc, xst, NULL, NULL);

	// On récupére le l'objet contenant le certificat qui a signé la CRL
	rv = X509_STORE_CTX_get_by_subject(xsc, X509_LU_X509, X509_CRL_get_issuer(crl), xobj);
	if (rv <= 0)
	{
		//add_log("Error don't find the CA cert that sign the CRL", LOG_NOTICE);
		warning("Error don't find the CA cert that sign the CRL");
		if (xst != NULL) X509_STORE_free(xst);
		if (xsc != NULL) X509_STORE_CTX_free(xsc);
		if (xobj != NULL) X509_OBJECT_free(xobj);
		if (ca_f != NULL) fclose(ca_f);
		return(ERROR_LOADING_CA_CHAIN);
	}

	// ON recupere la clé publique du certificat
	pkey = X509_get_pubkey(X509_OBJECT_get0_X509(xobj));
	if (pkey == NULL)
	{
		ret = ERROR_CRL_NO_PKEY_CA;
	} else
	{
		rv = X509_CRL_verify( crl, pkey );
		if ( rv <= 0)
		{
			ret = ERROR_CRL_BAD_SIGNATURE;
		}
	}

	if (pkey != NULL) EVP_PKEY_free(pkey);
	if (xst != NULL) X509_STORE_free(xst);
	if (xsc != NULL) X509_STORE_CTX_free(xsc);
	if (xobj != NULL) X509_OBJECT_free(xobj);
	if (ca_f != NULL) fclose(ca_f);
	return (ret);
}


