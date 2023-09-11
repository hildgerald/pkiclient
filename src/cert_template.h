/*
 * cert_template.h
 *
 *  Created on: 5 déc. 2022
 *      Author: gege
 */

#ifndef CERT_TEMPLATE_H_
#define CERT_TEMPLATE_H_

#include <stdint.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


#if 0
int32_t	check_template_ca(X509* x509, int32_t *isRA);
int32_t check_template_http_api(X509* x509);
int32_t check_template_syslog(X509* x509);
int32_t check_template_iec104(X509* x509);
#endif
int32_t	check_template_crl(X509_CRL* x509crl);
int32_t check_template_by_file(X509* x509, char * template_filename, int32_t isRA);

#endif /* CERT_TEMPLATE_H_ */
