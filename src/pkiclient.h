/*
 * pkiclient
 * client for getting certificate with scep and est protocol
 * 
 * This work is based on the folowing project :
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 * 
 * 
 */
#ifndef SSCEP_H
#define SSCEP_H
#include "error.h"
#include "scep/sceputils.h"
#include "est/estutils.h"

/* Functions */

/* Print usage information */
void usage(void); // dans pkiclient.c
/* Catch SIGALRM */
void catchalarm (int); // dans pkiclient.c

void tohex(unsigned char * in, size_t insz, char *out, size_t outsz); // dans fileutils.c
int32_t ExtractFilePath(char * FileName); // dans fileutils.c
int32_t is_ROOTinChain( STACK_OF(X509) *chain);
int32_t is_ROOT(X509* x509);
int32_t	is_CA(X509* x509);
int32_t	is_RA(X509* x509);
int32_t Add_ca_from_dir(char * CADir, STACK_OF(X509) *bundle_certs, uint32_t dir);
int32_t create_pki_bundle_ca_from_dir(char * CADir, STACK_OF(X509) *bundle_certs, uint32_t dir);
int32_t write_cert_in_file(X509 * cert, char * filename, int mode);

/* End of Functions */
#endif
