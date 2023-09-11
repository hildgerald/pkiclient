/*
 * estutils.h
 *
 *  Created on: 3 août 2023
 *      Author: gege
 */

#ifndef EST_ESTUTILS_H_
#define EST_ESTUTILS_H_

#include "conf.h"
#include "cmd.h"

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <setjmp.h>
#include "getopt.h"
#include "fileutils_capi.h"
#include "configuration.h"
#include "engine.h"


#ifdef WIN32

#define NOCRYPT
#include <winsock2.h>
#include <io.h>

#ifdef _DEBUG
#include <crtdbg.h>
#endif

#define snprintf _snprintf
#define close _close
#define sleep(t_num) Sleep((t_num)*1000)
#pragma comment(lib, "crypt32.lib")

#else

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#endif

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

/* EST operations */
#define	EST_OPERATION_CACERTS			101
#define	EST_OPERATION_SIMPLEENROLL		103
#define	EST_OPERATION_SIMPLEREENROLL	105
#define	EST_OPERATION_FULLCMC			107
#define EST_OPERATION_SERVERKEYGEN 		115
#define EST_OPERATION_CSRATTRS		  	131

/* EST MIME headers */
//TODO: analyser les retours des requetes
#define MIME_PKCS7				"application/pkcs7-mime"
#define MIME_PKCS10				"application/pkcs10"
#define MIME_CSRATTRS			"application/csrattrs"

/* Entrust VPN connector uses different MIME types */
#define MIME_PKI				"application/x-pki-message"
#define MIME_GETCA_RA_ENTRUST	"application/x-x509-ra-ca-certs"

/* EST reply types based on MIME headers */
//TODO: analyser le retour MIME protocole EST
#define	EST_MIME_CACERTS		1
#define	EST_MIME_SIMPLEENROLL	3
#define	EST_MIME_SIMPLEREENROLL	4
//#define	EST_MIME_PKI			5
//#define	EST_MIME_GETNEXTCA		7
//#define	EST_MIME_GETCAPS		15

//TODO: corriger tout ce qui est dessous...
/* EST request types */
//#define	EST_REQUEST_NONE			0
//#define	EST_REQUEST_PKCSREQ			19
//#define	EST_REQUEST_PKCSREQ_STR		"19"
//#define	EST_REQUEST_GETCERTINIT		20
//#define	EST_REQUEST_GETCERTINIT_STR	"20"
//#define	EST_REQUEST_GETCERT			21
//#define	EST_REQUEST_GETCERT_STR		"21"
//#define	EST_REQUEST_GETCRL			22
//#define	EST_REQUEST_GETCRL_STR		"22"

/* EST reply types */
#define	EST_REPLY_NONE			0
#define	EST_REPLY_CERTREP		3
#define	EST_REPLY_CERTREP_STR	"3"

/* EST pkiStatus values (also used as SSCEP return values) */
#define EST_PKISTATUS_SUCCESS		0
#define EST_PKISTATUS_FAILURE		2
#define EST_PKISTATUS_PENDING		3

/* SEST return values (not in EST draft) */
#define EST_PKISTATUS_ERROR		1 /* General error */
#define EST_PKISTATUS_BADALG		70 /* BADALG failInfo */
#define EST_PKISTATUS_BADMSGCHK	71 /* BADMSGCHK failInfo */
#define EST_PKISTATUS_BADREQ		72 /* BADREQ failInfo */
#define EST_PKISTATUS_BADTIME		73 /* BADTIME failInfo */
#define EST_PKISTATUS_BADCERTID	74 /* BADCERTID failInfo */
#define EST_PKISTATUS_TIMEOUT		89 /* Network timeout */
#define EST_PKISTATUS_SS			91 /* Error generating selfsigned */
#define EST_PKISTATUS_FILE			93 /* Error in file handling */
#define EST_PKISTATUS_NET			95 /* Network sending message */
#define EST_PKISTATUS_P7			97 /* Error in pkcs7 routines */
#define EST_PKISTATUS_UNSET		99 /* Unset pkiStatus */

/* SCEP failInfo values */
#define EST_FAILINFO_BADALG		0
#define EST_FAILINFO_BADALG_STR	\
	"Unrecognized or unsupported algorithm ident"
#define EST_FAILINFO_BADMSGCHK		1
#define EST_FAILINFO_BADMSGCHK_STR	\
	"Integrity check failed"
#define EST_FAILINFO_BADREQ		2
#define EST_FAILINFO_BADREQ_STR	\
	"Transaction not permitted or supported"
#define EST_FAILINFO_BADTIME		3
#define EST_FAILINFO_BADTIME_STR	\
	"Message time field was not sufficiently close to the system time"
#define EST_FAILINFO_BADCERTID		4
#define EST_FAILINFO_BADCERTID_STR 	\
	"No certificate could be identified matching"

//define encoding for capi engine support
//#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

/* SCEP capabilities */
//#define EST_CAP_AES      0x001
//#define EST_CAP_3DES     0x002
//#define EST_CAP_NEXT_CA  0x004
//#define EST_CAP_POST_PKI 0x008
//#define EST_CAP_RENEWAL  0x010
//#define EST_CAP_SHA_1    0x020
//#define EST_CAP_SHA_224  0x040
//#define EST_CAP_SHA_256  0x080
//#define EST_CAP_SHA_384  0x100
//#define EST_CAP_SHA_512  0x200
//#define EST_CAP_STA      0x400
//
//#define EST_CAPS 11

/* End of Global defines */


/* Global variables */

/* Program name */
extern char *pname;

/* Network timeout */
extern int timeout;

/* Certificates, requests, keys.. */
extern X509 *cacert;
extern X509 *encert;
extern X509 *localcert;
extern X509 *renewal_cert;
extern X509 *issuer_cert;
extern X509_REQ *request;
extern EVP_PKEY *rsa;
extern EVP_PKEY *renewal_key;
extern X509_CRL *crl;

/* Fingerprint, signing and encryption algorithms */
extern const EVP_MD *fp_alg;
extern const EVP_MD *sig_alg;
extern const EVP_CIPHER *enc_alg;

/* OpenSSL OID handles, defined in sceputils.c */
extern int nid_messageType;
extern int nid_pkiStatus;
extern int nid_failInfo;
extern int nid_senderNonce;
extern int nid_recipientNonce;
extern int nid_transId;
extern int nid_extensionReq;

/* End of Global variables */

#endif /* EST_ESTUTILS_H_ */
