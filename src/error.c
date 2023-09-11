/*
 * error.c
 *
 *  Ce fichier contient la fonction permettant d'afficher les erreurs et de les envoyer à syslog
 *  Created on: 6 déc. 2022
 *      Author: gege
 */
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <syslog.h>
#include "check.h"
#include "error.h"

/**
 * @fn		void debug(char *fmt, ...)
 * @brief	Envoi un message debug a syslog
 * @param	char *fmt, ... : parametre du debug a envoyer
 * @return	none
 */
void debug(char *fmt, ...){
	va_list myargs;
    va_start(myargs, fmt);
    printf("DEBUG :");
    vprintf(fmt, myargs);
	vsyslog(LOG_DEBUG, fmt, myargs);
    va_end(myargs);
}

/**
 * @fn		void informational(char *fmt, ...)
 * @brief	Envoi un message informational a syslog
 * @param	char *fmt, ... : parametre du debug a envoyer
 * @return	none
 */
void informational(char *fmt, ...){
	va_list myargs;
    va_start(myargs, fmt);
    printf("INFO :");
    vprintf(fmt, myargs);
	vsyslog(LOG_INFO, fmt, myargs);
    va_end(myargs);
}

/**
 * @fn		void error(char *fmt, ...)
 * @brief	Envoi un message error a syslog
 * @param	char *fmt, ... : parametre du debug a envoyer
 * @return	none
 */
void error(char *fmt, ...){
	va_list myargs;
    va_start(myargs, fmt);
    printf("ERROR :");
    vprintf(fmt, myargs);
	vsyslog(LOG_ERR, fmt, myargs);
    va_end(myargs);
}

/**
 * @fn		void warning(char *fmt, ...)
 * @brief	Envoi un message warning a syslog
 * @param	char *fmt, ... : parametre du debug a envoyer
 * @return	none
 */
void warning(char *fmt, ...){
	va_list myargs;
    va_start(myargs, fmt);
    printf("WARNING :");
    vprintf(fmt, myargs);
	vsyslog(LOG_WARNING, fmt, myargs);
    va_end(myargs);
}

/**
 * @fn		void notice(char *fmt, ...)
 * @brief	Envoi un message notice a syslog
 * @param	char *fmt, ... : parametre du debug a envoyer
 * @return	none
 */
void notice(char *fmt, ...){
	va_list myargs;
    va_start(myargs, fmt);
    printf("NOTICE :");
    vprintf(fmt, myargs);
    vsyslog(LOG_NOTICE, fmt, myargs);
    va_end(myargs);
}

/**
 * @fn		void add_log(char *str, int log_level)
 * @brief	Cette fonction permet d'envoyer un message de log à syslog-ng
 * @param 	str char *: CHaine de caractère contenant le message
 * @param 	log_level int: niveau de log qui peut être notice, warning, error
 * @return  none
 */
void add_log(char *str, int log_level){

	printf("%s\n",str);
	openlog("cert_checker", LOG_NDELAY | LOG_PID, LOG_USER);
	syslog(log_level, "%s", str);
	closelog();
}

/**
 * @fn		void print_error(int32_t error_value)
 * @brief	Cette fonction affiche sur la console le résultat de la vérification
 * 			sur la console et envoie les erreurs ad-hoc sur le serveur syslog
 * @param 	error_value int32_t: numéro de l'erreur interne
 * @param 	*str const char: chaine de caractère à associer dans le texte d'erreur si besoin
 * @return 	none
 */
void print_error(int32_t error_value, const char *str)
{
	char buf[1024] = {0};

    switch (error_value){
    case ERROR_OK :
    	snprintf(buf,sizeof(buf)-1, "OK" );
    	break;
    case ERROR_CERTIFICATE_INVALID:
    	snprintf(buf,sizeof(buf)-1, "ERRREUR : CERTIFICAT INVALIDE" );
    	break;
	case ERROR_CRL_INVALID:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : CERTIFICAT CRL INVALIDE" );
		break;
	case ERROR_FILE_NOT_OPEN:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : FICHIER IMPOSSIBLE A OUVRIR" );
		break;
	case ERROR_FILE_NOT_FOUND:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : FICHIER NON TROUVE" );
		break;
	case ERROR_FILE_NOT_X509:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : CERTIFICAT N'EST PAS AU FORMAT X509" );
		break;
	case ERROR_FILE_NOT_CRL:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE FICHIER N'EST PAS UNE CRL" );
		break;
	case ERROR_FILE_NOT_PEM:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE FICHIER N'EST PAS AU FORMAT PEM" );
		break;
	case ERROR_UNABLE_READ_EXPIRATION_DATE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IMPOSSIBLE DE LIRE LA DATE D'EXPIRATION" );
		break;
	case ERROR_UNABLE_CHECK_DATE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IMPOSSIBLE DE VERIFIER LA DATE" );
		break;
	case ERROR_ISSUER_UNREADABLE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : L'ISSUER EST ILLISIBLE" );
		break;
	case ERROR_SUBJECT_UNREADABLE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE SUJET EST ILLISIBLE" );
		break;
	case ERROR_CRL_CERTIFICATE_EXPIRED:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE CERTIFICAT EST EXPIRE" );
		break;
	case ERROR_CERT_BAD_VERSION:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LA VERSION DU CERTIFICAT EST MAUVAISE" );
		break;
	case ERROR_CERT_BAD_SIGN_ALGO:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : L'ALGORYTHME DE SIGNATURE EST MAUVAIS" );
		break;
	case ERROR_CERT_BAD_ISSUER:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : L'ISSUER EST MAUVAIS" );
		break;
	case ERROR_CERT_BAD_VALIDITY_PERIOD:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LA PERIDODE DE VALIDITE EST MAUVAISE" );
		break;
	case ERROR_CERT_BAD_SUBJECT:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE SUJET EST MAUVAIS" );
		break;
	case ERROR_CERT_BAD_PUBKEY:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LA CLE EST MAUVAISE" );
		break;
	case ERROR_CERT_BAD_EXT:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LES EXTENSIONS SONT MAUVAISES" );
		break;
	case ERROR_CERT_BAD_AUTH_KEY_ID:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : L'IDENTIFIANT DE LA CLE AUTHENTIFICATION EST MAUVAIS" );
		break;
	case ERROR_CERT_BAD_SUBJ_KEY_ID:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : L'IDENTIFIANT DE LA CLE DU SUJET EST MAUVAIS" );
		break;
	case ERROR_CERT_BAD_POLICIES:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LES \"POLICIES\" SONT MAUVAISES" );
		break;
	case ERROR_CERT_BAD_BASIC_CONSTRAINTS:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LES CONTRAINTES BASIQUES SONT MAUVAISES" );
		break;
	case ERROR_CERT_BAD_SUBJ_ALT_NAME:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE NOM ALTERNATIF DES SUJET EST MAUVAIS" );
		break;
	case ERROR_CERT_BAD_CRL_DIST_POINT:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LES POINTS DE DISTRIBUTIONS DE CRL SONT MAUVAIS" );
		break;
	case ERROR_CERT_BAD_AUTH_INFO_ACCESS:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LES INFORMATIONS ATHENTIFICATIONS SONT MAUVAISES" );
		break;
	case ERROR_CERT_NOT_ENOUGH_EXTENSION:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IL N'Y A PAS TOUTES LES EXTENSIONS NECESSAIRES" );
		break;
	case ERROR_CERT_MISSING_SERIAL_NUMBER:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IL MANQUE LE NUMERO DE SERIE" );
		break;
	case ERROR_CERT_MISSING_START_DATE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IL MANQUE LA DATE DE DEBUT DE VALIDITE" );
		break;
	case ERROR_CERT_MISSING_STOP_DATE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IL MANQUE LA DATE D'EXPIRATION" );
		break;
	case ERROR_CERT_MISSING_KEY_USAGE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IL MANQUE L'USAGE DE LA CLE" );
		break;
	case ERROR_CERT_MISSING_EXT_KEY_USAGE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IL MANQUE L'USAGE ETENDU DE LA CLE" );
		break;
	case ERROR_CERT_NOT_CRITICAL_KEY_USAGE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IL MANQUE LA CRITICITE DE LA CLE" );
		break;
	case ERROR_CERT_UNEXPECTED_KEY_USAGE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LA CLE A UN USAGE INATENDU" );
		break;
	case ERROR_UNABLE_CREATE_CTX:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IMPOSSIBLE DE CREER L'OBJECT CTX LORS DE LA VERIFICATION" );
		break;
	case ERROR_LOADING_CA_CHAIN:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IMPOSSIBLE D'OUVRIR LE FICHIER DE LA CHAINE DE CONFIANCE" );
		break;
	case ERROR_CERT_NOT_VALID_CA_CHAIN:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE CERTIFICAT N'A PAS ETE AUTHENTIFIE PAR SA CHAINE DE CONFIANCE" );
		break;
	case ERROR_DATE_FORMAT:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE FORMAT DE LA DATE N'EST PAS BON" );
		break;
	case ERROR_CONVERSION_DATE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : ERREUR DE CONVERSION DE DATE" );
		break;
	case ERROR_CERT_CERTIFICATE_EXPIRED:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE CERTIFICAT EST EXPIRE" );
		break;
	case ERROR_UNABLE_TO_GET_ISSUE_DATE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IMPOSSIBLE DE TROUVER LE CHAMP DE LA DATE DE L'\"ISSUER\"" );
		break;
	case ERROR_UNABLE_TO_CHECK_MID_LIFE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IMPOSSIBLE DE VERIFIER LA DEMI-VIE" );
		break;
	case ERROR_CERT_NOT_YET_VALID:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE CERTIFICAT N'EST PAS ENCORE VALIDE" );
		break;
	case ERROR_CRL_NOT_YET_VALID:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LA CRL N'EST PAS ENCORE VALIDE" );
		break;
	case ERROR_CERT_REACHED_MID_LIFE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LE CERTIFICAT A DEPASSEE SA DEMI VIE DE VALIDITE" );
		break;
	case ERROR_CRL_REACHED_MID_LIFE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : LA CRL A DEPASSEE SA DEMI VIE DE VALIDITE" );
		break;
	case ERROR_UNABLE_CALCULATE_DIFF:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IMPOSSIBLE DE CALCULER LA DIFFERENCE DE DATE" );
		break;
	case ERROR_NO_EXTENSION_FOUND:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : PAS DE CHAMP EXTENSION TROUVE" );
		break;
	case ERROR_NOT_CHECKINGBASIC_CRL:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : PAS DE VERIFICATION DE L'OPTION \"BASIC CONSTRAINT\" DANS UNE CRL" );
		break;
	case ERROR_NOT_CHECKING_DISTRIBUTION_CRL:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : PAS DE VERIFICATION DES POINTS DE DISTRIBUTION DE CRL DANS UNE CRL" );
		break;
	case ERROR_MISSING_BASIC_CONSTRAIN:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IL MANQUE DES INFORMATIONS DANS L'OPTION \"BASIC CONSTRAINT\"" );
		break;
	case ERROR_MISSING_CRL_DISTRIBUTION_POINT:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : IL MANQUE LE POINT DE DISTRIBUTION DES CRLS" );
		break;
	case ERROR_CERT_TYPE_UNKNOW:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : CERTIFICAT DE TYPE INCONNU" );
		break;
	case ERROR_CRL_BAD_VERSION :
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL) MAUVAISE VERSION DU FICHIER" );
		break;
	case ERROR_CRL_BAD_SIGN_ALGO:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL) MAUVAIS ALGORYTME DE SIGNATURE" );
		break;
	case ERROR_CRL_BAD_ISSUER:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL) MAUVAIS \"ISSUER\"" );
		break;
	case ERROR_CRL_NOT_ENOUGH_EXTENSION:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL) PAS ASSEZ D'EXTENSION PRESENTE" );
		break;
	case ERROR_CRL_NO_EXTENSION:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL) PAS D'EXTENSION PRESENTE" );
		break;
	case ERROR_CRL_NO_REVOKED_EXTENSION:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL) PAS D'EXTENSION DE REVOCATION" );
		break;
	case ERROR_CRL_NO_REVOKED_DATE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL) PAS DE DATE DE REVOCATION D'UN CERTIFICAT" );
		break;
	case ERROR_CRL_NO_REVOKED_SN:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL)PAS DE NUMERO DE SERIE D'UN CERTIFICAT" );
		break;
	case ERROR_CRL_UNABLE_CA:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL) IMPOSSIBLE DE LIRE LE FICHIER CA" );
		break;
	case ERROR_CRL_NO_PKEY_CA:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL) PAS DE CLE PUBLIQUE DANS LE CERTIFICAT CA" );
		break;
	case ERROR_CRL_BAD_SIGNATURE:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : (CRL)MAUVAISE SIGNATURE DE LA CRL" );
		break;
	case ERROR_NO_CA:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : PAS DE FICHIER CA DEFINI DANS LA LIGNE DE COMMANDE" );
		break;
	case ERROR_UNKNOW_COMMAND:
		snprintf(buf,sizeof(buf)-1, "ERRREUR : COMMANDE INCONNUE" );
		break;
	default :
		snprintf(buf,sizeof(buf)-1, "ERRREUR : Erreur %d inconnue",error_value );
    }
    add_log(buf, LOG_ERR);
}
