/*
 * scep_actions.c
 *
 *  Created on: 11 déc. 2022
 *      Author: gege
 */
#include <stdint.h>
#include "../pkiclient.h"
#include "scep_actions.h"
#include "syslog.h"
#include "check.h"


static SCEP_CAP scep_caps[SCEP_CAPS] = {
	{ .cap = SCEP_CAP_AES,      .str = "AES" }, /* AES128-CBC */
	{ .cap = SCEP_CAP_3DES,     .str = "DES3" }, /* DES-CBC */
	{ .cap = SCEP_CAP_NEXT_CA,  .str = "GetNextCACert" },
	{ .cap = SCEP_CAP_POST_PKI, .str = "POSTPKIOperation" },
	{ .cap = SCEP_CAP_RENEWAL,  .str = "Renewal" },
	{ .cap = SCEP_CAP_SHA_1,    .str = "SHA-1" },
	{ .cap = SCEP_CAP_SHA_224,  .str = "SHA-224" },
	{ .cap = SCEP_CAP_SHA_256,  .str = "SHA-256" },
	{ .cap = SCEP_CAP_SHA_384,  .str = "SHA-384" },
	{ .cap = SCEP_CAP_SHA_512,  .str = "SHA-512" },
	{ .cap = SCEP_CAP_STA,      .str = "SCEPStandard" },
};



/**
 * @fn		scep_operation_get_ca
 * @brief	This function get the CA certificate. By example, your scep server
 * 		has the URL : http://localhost/cgi-bin/pkiclient.exe,
 * 		host_name is localhost
 * 		host_port is 80
 * 		dir_name is cgi-bin/pkiclient.exe
 * @param 	verbose int: if !=0 then print on the screen somme details message.
 * @param 	http struct http_reply *:
 * @param 	operation int:
 * @param 	M_char char*: Monitor string
 * @param 	payload char*: Data to send
 * @param 	payload_len size_t: size of the data to send
 * @param 	p_flag int: is 1 if we use a proxy
 * @param 	host_name char* : hostname of the server
 * @param 	host_port int: port of the scep service. by default is 80
 * @param 	dir_name char*: directory of the scep service
 * @param 	scep_t struct scep	*: response structure scep
 * @return	int: error of the operation
 */
int scep_operation_get_ca(
		int verbose,
		struct http_reply *http,
		char *M_char,
		char *payload,
		size_t payload_len,
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t)
{
	int pkistatus = 0;
	int c;
	//FILE	*fp = NULL;
	BIO		*bp;
	unsigned int		n;
	unsigned char		md[EVP_MAX_MD_SIZE];
	int32_t ret = 0;
	char buf[1024] = {0};

	if (verbose)
		fprintf(stdout, "%s: SCEP_OPERATION_GETCA\n", pname);

	/* Set CA identifier */
//	if (!i_flag)
//		i_char = CA_IDENTIFIER;

	/*
	 * Send http message.
	 * Response is written to http_response struct "reply".
	 */
	http->payload = NULL;
	if ((c = send_msg(
			http,
			0,
			"GetCACert",
			SCEP_OPERATION_GETCA,
			M_char,
			i_char_CA_identifier,
			strlen(i_char_CA_identifier),
			p_flag,
			host_name,
			host_port,
			dir_name)
			) == 1)
	{
		//fprintf(stderr, "%s: error while sending message\n", pname);
		error("error while sending message");
		return (SCEP_PKISTATUS_NET);
	}
	if (http->payload == NULL) {
		//fprintf(stderr, "%s: no data, perhaps you should define CA identifier (-i)\n", pname);
		error("no data, perhaps you should define CA identifier (-i)");
		return (SCEP_PKISTATUS_SUCCESS);
	}
	if (verbose){
		printf("%s: valid response from server\n", pname);
	}
	if (http->type == SCEP_MIME_GETCA_RA) {
		// There are 2 certificates or more because we have a RA certificate and a CA certificate (s)
		write_ca_ra(http);
		// We never go here because write_ca_ra leave the software ....
	}

	// We come here because we don't have a RA, we only have 1 certificate that is root

	/* Read payload as DER X.509 object: */
	bp = BIO_new_mem_buf(http->payload, http->bytes);
	cacert = d2i_X509_bio(bp, NULL);

	/* Read and print certificate information */
	if (!X509_digest(cacert, fp_alg, md, &n)) {
		//ERR_print_errors_fp(stderr);
		error("error digest : %s", ERR_error_string(ERR_get_error(),NULL));
		return (SCEP_PKISTATUS_ERROR);
	}
	if (verbose){
		printf("%s: %s fingerprint: ", pname, OBJ_nid2sn(EVP_MD_type(fp_alg)));
		for (c = 0; c < (int)n; c++) {
			printf("%02X%c",md[c], (c + 1 == (int)n) ?'\n':':');
		}
	}

	/* Before to write the file, we need to check the certificate himself */
	if (http->type != SCEP_MIME_GETCA_RA) {
		// On doit vérifier notre certificat
		if (v_flag)
			printf("%s: CA certificate %s must to be verify\n", pname, c_char_CA_certificate);

		ret = check_verify_CA(cacert, NULL, NULL, NULL);
		if (ret != 0)
		{
			//fprintf(stderr, "%s: the CA cert file %s is not valid. Error code %d\n", pname, c_char, ret);
//			snprintf(buf, sizeof(buf)-1, "the CA cert file %s is not valid. Error code %d", c_char_CA_certificate, ret);
//			add_log(buf, LOG_WARNING);
			warning("the CA cert file %s is not valid. Error code %d", c_char_CA_certificate, ret);
			exit (SCEP_PKISTATUS_FILE);
		}

		if (v_flag)
		{
			printf("%s: the certificate %s is valid\n", pname, c_char_CA_certificate);
		}

		/* Write PEM-formatted file: */
		write_cert_in_file(cacert, c_char_CA_certificate, 0);

		// We get only one certificate but we need ca.crt-0 so ...
		strncpy(buf,c_char_CA_certificate,sizeof(buf)-1);
		snprintf(buf, sizeof(buf)-1,"%s-0",c_char_CA_certificate);
		write_cert_in_file(cacert, buf, 0);

		// We get only one certificate but we need ra.crt so ...
		strncpy(buf,c_char_CA_certificate,sizeof(buf)-1);
		ExtractFilePath(buf);
		strncat(buf,"/ra.crt",sizeof(buf)-1);
		write_cert_in_file(cacert, buf, 0);

	}
	scep_t->pki_status = pkistatus = SCEP_PKISTATUS_SUCCESS;
	return (pkistatus);
}

/**
 * @fn
 * @brief
 * @param verbose
 * @param http
 * @param M_char
 * @param payload
 * @param payload_len
 * @param p_flag
 * @param host_name
 * @param host_port
 * @param dir_name
 * @param scep_t
 * @return
 */
int scep_operation_get_next_ca(
		int verbose,
		struct http_reply *http,
		char *M_char,
		char *payload,
		size_t payload_len,
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t)
{
	int pkistatus = 0;
	int c;
	FILE	*fp = NULL;
	STACK_OF(X509)		*nextcara = NULL;
	X509			*cert=NULL;
	int i;
	int l = 0;

	/*
	 * Send http message.
	 * Response is written to http_response struct "reply".
	 */
	http->payload = NULL;
	if (i_char_CA_identifier != NULL) l = strlen(i_char_CA_identifier);
	if ((c = send_msg(http, 0, "GetNextCACert", SCEP_OPERATION_GETNEXTCA,
			M_char, i_char_CA_identifier, l, p_flag, host_name, host_port, dir_name)) == 1) {
		if(verbose){
//			fprintf(stderr, "%s: error while sending message\n", pname);
//			fprintf(stderr, "%s: getnextCA might be not available\n", pname);
			error("error while sending message");
			error("getnextCA might be not available");
		}
		return (SCEP_PKISTATUS_NET);
	}
	if (http->payload == NULL) {
		//fprintf(stderr, "%s: no data, perhaps you there is no nextCA available\n", pname);
		error("no data, perhaps you there is no nextCA available");
		return (SCEP_PKISTATUS_SUCCESS);
	}

	if(verbose > 1)
	printf("%s: valid response from server\n", pname);

	if (http->type == SCEP_MIME_GETNEXTCA) {
		/* XXXXXXXXXXXXXXXXXXXXX chain not verified */

		//write_ca_ra(&reply);

		/* Set the whole struct as 0 */
		memset(scep_t, 0, sizeof(struct scep));

		scep_t->reply_payload = http->payload;
		scep_t->reply_len = http->bytes;
		scep_t->request_type = SCEP_MIME_GETNEXTCA;

		pkcs7_verify_unwrap(scep_t , C_char_CA_certificate_chain);

		//pkcs7_unwrap(scep_t);
	}


	/* Get certs */
	nextcara = scep_t->reply_p7->d.sign->cert;

	if (verbose) {
		printf ("verify and unwrap: found %d cert(s)\n", sk_X509_num(nextcara));
	}

	for (i = 0; i < sk_X509_num(nextcara); i++) {
			char buffer[1024];
			char name[1024];
			memset(buffer, 0, 1024);
			memset(name, 0, 1024);

			cert = sk_X509_value(nextcara, i);
			if (verbose) {
				printf("%s: found certificate with\n"
					"  subject: '%s'\n", pname,
					X509_NAME_oneline(X509_get_subject_name(cert),
						buffer, sizeof(buffer)));
				printf("  issuer: %s\n",
					X509_NAME_oneline(X509_get_issuer_name(cert),
						buffer, sizeof(buffer)));
			}

			/* Create name */
			snprintf(name, 1024, "%s-%d", c_char_CA_certificate, i);


			/* Write PEM-formatted file: */
			if (!(fp = fopen(name, "w"))) {
				//fprintf(stderr, "%s: cannot open cert file for writing\n",pname);
				error("cannot open cert file for writing");
				return (SCEP_PKISTATUS_FILE);
			}
			if (verbose)
				printf("%s: writing cert\n", pname);
			if (verbose > 1)
				PEM_write_X509(stdout, cert);
			if (PEM_write_X509(fp, cert) != 1) {
//				fprintf(stderr, "%s: error while writing certificate file\n", pname);
//				ERR_print_errors_fp(stderr);
				error("error while writing certificate file : %s", ERR_error_string(ERR_get_error(),NULL));
				return (SCEP_PKISTATUS_FILE);
			}
			if(verbose)
				printf("%s: certificate written as %s\n", pname, name);
			(void)fclose(fp);
	}

	pkistatus = SCEP_PKISTATUS_SUCCESS;

	return (pkistatus);
}

/**
 * @fn		scep_operation_get_cacaps
 * @brief	Cette focntion permet de récupérer les capacités du serveur SCEP en
 * 			terme de chiffrement et de hachage.
 * @param verbose
 * @param http
 * @param host_name
 * @param host_port
 * @param dir_name
 * @return
 */
int scep_operation_get_cacaps(
		int verbose,
		struct http_reply *http,
		char *host_name,
		int host_port,
		char *dir_name)
{
	int ca_caps = 0;
	int c;
	int i;

	http->payload = NULL;
	if ((c = send_msg(http, 0, "GetCACaps", SCEP_OPERATION_GETCAPS, NULL, NULL, 0,
				p_flag, host_name, host_port, dir_name)) == 1) {
		//fprintf(stderr, "%s: error while sending message\n", pname);
		error("error while sending message");
		return (SCEP_PKISTATUS_NET);
	}

	if (verbose)
		fprintf(stdout, "%s\n", http->payload);

	if (http->status == 200 && http->payload != NULL) {
		for ( i = 0 ; i < http->bytes ; ) {
			int _ca_caps = 0;
			int j = i, k;

			while (j < http->bytes && !
					(http->payload[j] == '\r' ||
					 http->payload[j] == '\n'))
				++j;

			while (j < http->bytes &&
					(http->payload[j] == '\r' ||
					 http->payload[j] == '\n'))
			{
				http->payload[j] = '\0';
				++j;
			}

			/* parse capabilities */
			/* convert the string to binary capabilities */
			for ( k = 0 ; k < SCEP_CAPS ; ++k ) {
				if (http->payload[i] != scep_caps[k].str[0])
					continue;

				if (strcmp(&http->payload[i], scep_caps[k].str) != 0)
					continue;

				_ca_caps |= scep_caps[k].cap; // _ca_caps is a compilation of SCEP_CAP_AES ...
			}

			if (_ca_caps == 0)
				//fprintf(stderr, "%s: unknown capability %s\n",pname, &http->payload[i]);
				error("unknown capability : %s", &http->payload[i]);
			else
				ca_caps |= _ca_caps;

			i = ( j == i ? j + 1 : j );
		}

		if (verbose > 1)
			fprintf(stdout, "%s: scep caps bitmask: 0x%04x\n",pname, ca_caps);
	}

	return (ca_caps);
}

/**
 * @fn
 * @brief
 * @param verbose
 * @param scep_t
 * @param operation
 * @return
 */
int scep_operation_common_enroll_getcrl_getcert(
		int verbose,
		struct scep	*scep_t,
		int operation
		)
{
	int pkistatus = 0;
	FILE			*fp = NULL;

	/*
	 * Read in CA cert, private key and certificate
	 * request in global variables.
	 */

	if (!c_flag) {
		//fprintf(stderr, "%s: missing CA cert (-c)\n", pname);
		error("missing CA cert (-c)");
		return (SCEP_PKISTATUS_FILE);
	}

	/* try to read certificate from a file */
	if (!(cacert = read_cert(c_char_CA_certificate))) {
		/* if that fails, try to guess both CA certificates */
		X509_NAME *issuer_name = (operation == SCEP_OPERATION_GETCRL) ? X509_get_issuer_name(localcert) : NULL;
		guess_ca_certs(c_char_CA_certificate, issuer_name, &cacert, &encert, &issuer_cert);

		if (!cacert) {
			//fprintf(stderr, "%s: cannot read CA cert (-c) file %s\n",pname, c_char_CA_certificate);
			error("cannot read CA cert (-c) file %s", c_char_CA_certificate);
			return (SCEP_PKISTATUS_FILE);
		}
	/* if the CA cert was in a single file, read the enc CA cert too */
	} else if (e_flag) {
		if (!(encert = read_cert(e_char_CA_encryption_certificate))) {
			//fprintf(stderr, "%s: cannot read enc CA cert (-e) file %s\n",pname, e_char_CA_encryption_certificate);
			error("cannot read enc CA cert (-e) file %s", c_char_CA_certificate);
			return (SCEP_PKISTATUS_FILE);
		}
	} else
		encert = NULL;

	if (!k_flag) {
	  //fprintf(stderr, "%s: missing private key (-k)\n", pname);
	  error("missing private key (-k)");
	  return (SCEP_PKISTATUS_FILE);
	}

#ifdef WITH_ENGINES
	if(g_flag)
		sscep_engine_read_key_new(&rsa, k_char_private_key, scep_t->e);
	else
#endif
		rsa = read_key(k_char_private_key);


	if ((K_flag && !O_flag) || (O_flag && !K_flag && (operation == SCEP_OPERATION_ENROLL))) {
	  //fprintf(stderr, "%s: -O also requires -K (and vice-versa)\n", pname);
	  error("-O also requires -K (and vice-versa)");
	  return (SCEP_PKISTATUS_FILE);
	}

	if (K_flag) {
		//TODO auf hwcrhk prfen?
#ifdef WITH_ENGINES
		if(g_flag)
			sscep_engine_read_key_old(&renewal_key, K_char_Private_key_of_already_existing_certificate, scep_t->e);
		else
#endif
			renewal_key = read_key(K_char_Private_key_of_already_existing_certificate);
	}

	if (O_flag) {
		if (!(renewal_cert = read_cert(O_char_Already_existing_certificate))) {
			//fprintf(stderr, "%s: cannot read renewal cert (-O) %s\n", pname, O_char_Already_existing_certificate);
			error("cannot read renewal cert (-O) %s", O_char_Already_existing_certificate);
			return(SCEP_PKISTATUS_FILE);
		}
	}

	if (operation != SCEP_OPERATION_ENROLL)
		goto not_enroll;

	read_request();
	scep_t->transaction_id = key_fingerprint(request);
	if (verbose) {
		printf("%s:  Read request with transaction id: %s\n", pname, scep_t->transaction_id);
	}

	if (! O_flag) {
		if (verbose)
		{
			fprintf(stdout, "%s: generating selfsigned certificate\n", pname);
		}
		new_selfsigned(scep_t);
	}
	else {
	  /* Use existing certificate */
	  scep_t->signercert = renewal_cert;
	  scep_t->signerkey = renewal_key;
	}

	/* Write the selfsigned certificate if requested */
	if (L_flag) {
		/* Write PEM-formatted file: */
#ifdef WIN32
		if ((fopen_s(&fp, L_char_local_self_signed_certificate, "w"))) {
#else
		if (!(fp = fopen(L_char_local_self_signed_certificate, "w"))) {
#endif
			//fprintf(stderr, "%s: cannot open file for writing\n", pname);
			error("cannot open file for writing");
			return (SCEP_PKISTATUS_ERROR);
		}
		if (PEM_write_X509(fp,scep_t->signercert) != 1) {
			//fprintf(stderr, "%s: error while writing certificate file\n", pname);
			//ERR_print_errors_fp(stderr);
			error("error while writing certificate file : %s", ERR_error_string(ERR_get_error(),NULL));
			return (SCEP_PKISTATUS_ERROR);
		}
		printf("%s: selfsigned certificate written as %s\n", pname, L_char_local_self_signed_certificate);
		(void)fclose(fp);
	}
	/* Write issuer name and subject (GetCertInitial): */
	if (!(scep_t->ias_getcertinit->subject =
			X509_REQ_get_subject_name(request))) {
		//fprintf(stderr, "%s: error getting subject for GetCertInitial\n", pname);
		error("error getting subject for GetCertInitial : %s", ERR_error_string(ERR_get_error(),NULL));
		//ERR_print_errors_fp(stderr);
		return (SCEP_PKISTATUS_ERROR);
	}
not_enroll:
	/* This following lines up to the O_flag assume that the
	RA certificate IS the CA certificate which is not valid
	in most cases nowadays when using a "real" CA software
	*/
	if (!(scep_t->ias_getcertinit->issuer =
			 X509_get_subject_name(cacert))) {
//		fprintf(stderr, "%s: error getting issuer for GetCertInitial\n", pname);
//		ERR_print_errors_fp(stderr);
		error("error getting issuer for GetCertInitial : %s", ERR_error_string(ERR_get_error(),NULL));
		return (SCEP_PKISTATUS_ERROR);
	}
	/* Write issuer name and serial (GETC{ert,rl}): */
	scep_t->ias_getcert->issuer = scep_t->ias_getcertinit->issuer;
	scep_t->ias_getcrl->issuer = scep_t->ias_getcertinit->issuer;
	if (!(scep_t->ias_getcrl->serial = X509_get_serialNumber(cacert))) {
//		fprintf(stderr, "%s: error getting serial for GetCertInitial\n", pname);
//		ERR_print_errors_fp(stderr);
		error("error getting serial for GetCertInitial : %s", ERR_error_string(ERR_get_error(),NULL));
		return (SCEP_PKISTATUS_ERROR);
	}

	/*
	 * For GETCRL operations and auto-selected certificates, issuer_cert
	 * may not be NULL. In that case, use it for the serial and issuer.
	 * This may still be overridden if the user uses the '-O' option.
	 */
	if (issuer_cert != NULL) {
		scep_t->ias_getcrl->serial = X509_get_serialNumber(issuer_cert);
		scep_t->ias_getcrl->issuer = X509_get_issuer_name(issuer_cert);
	}

	/* Use an extra certificate to read the issuer/serial
	information when calling getcert/getcrl */
	if ( O_flag) {
		if (operation == SCEP_OPERATION_GETCRL) {
			scep_t->ias_getcrl->serial = X509_get_serialNumber(renewal_cert);
			scep_t->ias_getcrl->issuer = X509_get_issuer_name(renewal_cert);
		} else if (operation != SCEP_OPERATION_ENROLL) {
			if (! s_flag ) {
				//fprintf(stderr, "%s: -O also requires -s for getcert\n", pname);
				error("-O also requires -s for getcert");
				return (SCEP_PKISTATUS_FILE);
			}
			scep_t->ias_getcert->issuer = X509_get_subject_name(renewal_cert);
		}
	}

	/* User supplied serial number */
	if (s_flag) {
		BIGNUM *bn = NULL;
		ASN1_INTEGER *ai;
		int len = BN_dec2bn(&bn , s_char_Certificate_serial_number);
		if (!len || !(ai = BN_to_ASN1_INTEGER(bn, NULL))) {
//			fprintf(stderr, "%s: error converting serial\n", pname);
//			ERR_print_errors_fp(stderr);
			error("error converting serial : %s", ERR_error_string(ERR_get_error(),NULL));
			return (SCEP_PKISTATUS_SS);
		}
		scep_t->ias_getcert->serial = ai;
		scep_t->ias_getcrl->serial = ai;
	}
	if (verbose) {
		char buffer[1024];
		memset(buffer, 0, 1024);
		if (operation == SCEP_OPERATION_GETCRL) {
			BIGNUM *bnser = ASN1_INTEGER_to_BN(scep_t->ias_getcrl->serial, NULL);
			char *serialChar = BN_bn2dec(bnser);
			fprintf(stdout, "%s: requesting crl for serial number %s and issuer %s\n",
				pname, serialChar,
				X509_NAME_oneline(scep_t->ias_getcrl->issuer, buffer, sizeof(buffer)));
		} else {
			BIGNUM *bnser = ASN1_INTEGER_to_BN(scep_t->ias_getcert->serial, NULL);
			char *serialChar = BN_bn2dec(bnser);
			fprintf(stdout, "%s: requesting certificate with serial number %s and issuer %s\n",
				pname, serialChar,
				X509_NAME_oneline(scep_t->ias_getcert->issuer, buffer, sizeof(buffer)));
		}
	}
	return(pkistatus);
}

/**
 * @fn
 * @brief
 * @param verbose
 * @param http
 * @param operation
 * @param M_char
 * @param payload
 * @param payload_len
 * @param p_flag
 * @param host_name
 * @param host_port
 * @param dir_name
 * @param scep_t
 * @param ca_caps
 * @param count
 * @return
 */
int scep_operation_polling(
		int verbose,
		struct http_reply *http,
		int operation,
		char *M_char,
		char *payload,
		size_t payload_len,
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t,
		int ca_caps,
		int *count
		)
{
	int pkistatus = 0;
	FILE	*fp = NULL;
	int c;

	/* Enter polling loop */
	while (scep_t->pki_status != SCEP_PKISTATUS_SUCCESS) {

		/* create payload */
		pkcs7_wrap(scep_t, !SUP_CAP_POST_PKI(ca_caps));

		/*Test mode print SCEP request and don't send it*/
		if(m_flag){

			/* Write output file : */
#ifdef WIN32
			if ((fopen_s(&fp, m_char_test_mode, "w")))
#else
			if (!(fp = fopen(m_char_test_mode, "w")))
#endif
			{
				//fprintf(stderr, "%s: cannot open output file for writing\n", m_char_test_mode);
				error("%s: cannot open output file for writing", m_char_test_mode);
			}
			else
			{
				printf("%s: writing PEM formatted PKCS#7\n", pname);
				PEM_write_PKCS7(fp, scep_t->request_p7);
			}

			//printf("Print SCEP Request:\n %s\n",scep_t->request_payload);
			return (0);
		}

		/* send http */
		http->payload = NULL;
		if ((c = send_msg(http, SUP_CAP_POST_PKI(ca_caps), "PKIOperation", operation,
					M_char, scep_t->request_payload, scep_t->request_len,
					p_flag, host_name, host_port, dir_name)) == 1)
		{
			//fprintf(stderr, "%s: error while sending message\n", pname);
			error("error while sending message");
			return (SCEP_PKISTATUS_NET);
		}
		/* Verisign Onsite returns strange reply...
		 * XXXXXXXXXXXXXXXXXXX */
		if ((http->status == 200) && (http->payload == NULL)) {
			/*
			scep_t->pki_status = SCEP_PKISTATUS_PENDING;
			break;
			*/
			return (SCEP_PKISTATUS_ERROR);
		}
		printf("%s: valid response from server\n", pname);

		/* Check payload */
		scep_t->reply_len = http->bytes;
		scep_t->reply_payload = http->payload;
		pkcs7_unwrap(scep_t);
		pkistatus = scep_t->pki_status;

		switch(scep_t->pki_status) {
			case SCEP_PKISTATUS_SUCCESS:
				break;
			case SCEP_PKISTATUS_PENDING:
				/* Check time limits */
				if (((t_num_Polling_interval * (*count)) >= T_num_MAX_Polling_interval) ||
					((*count) > n_num_Request_count)) {
					return (pkistatus);
				}
				scep_t->request_type =
					SCEP_REQUEST_GETCERTINIT;

				/* Wait for poll interval */
				if (v_flag)
				  printf("%s: waiting for %d secs\n", pname, t_num_Polling_interval);
				sleep(t_num_Polling_interval);
				printf("%s: requesting certificate (#%d)\n", pname, (*count));

				/* Add counter */
				(*count)++;
				break;

			case SCEP_PKISTATUS_FAILURE:

				/* Handle failure */
				switch (scep_t->fail_info) {
					case SCEP_FAILINFO_BADALG:
					  return (SCEP_PKISTATUS_BADALG);
					case SCEP_FAILINFO_BADMSGCHK:
					  return (SCEP_PKISTATUS_BADMSGCHK);
					case SCEP_FAILINFO_BADREQ:
					  return (SCEP_PKISTATUS_BADREQ);
					case SCEP_FAILINFO_BADTIME:
					  return (SCEP_PKISTATUS_BADTIME);
					case SCEP_FAILINFO_BADCERTID:
					  return (SCEP_PKISTATUS_BADCERTID);
					/* Shouldn't be there... */
					default:
					  return (SCEP_PKISTATUS_ERROR);
				}
			default:
				//fprintf(stderr, "%s: unknown pkiStatus\n", pname);
				error("unknown pkiStatus");
				return (SCEP_PKISTATUS_ERROR);
		}
}

	return(pkistatus);
}

/**
 * @fn		scep_operation_enroll
 * @brief	Cette fonction permet d'executer l'enrolement d'un certificat.
 * 			On envoit une requete avec un csr et on doit recevoir un certificat
 * 			en retour
 * @param verbose
 * @param http
 * @param M_char
 * @param payload
 * @param payload_len
 * @param p_flag
 * @param host_name
 * @param host_port
 * @param dir_name
 * @param scep_t
 * @param ca_caps
 * @return
 */
int scep_operation_enroll(
		int verbose,
		struct http_reply *http,
		char *M_char,
		char *payload,
		size_t payload_len,
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t,
		int ca_caps
		)
{
	int pkistatus = 0;
	int count = 1;

	// On prépare la transaction
	pkistatus = scep_operation_common_enroll_getcrl_getcert(verbose, scep_t, SCEP_OPERATION_ENROLL);
	if (pkistatus != SCEP_PKISTATUS_SUCCESS)
	{
		return(pkistatus);
	}

	if (verbose)
	{
		fprintf(stdout,	"%s: SCEP_OPERATION_ENROLL\n", pname);
	}

	/* Resum mode: set GetCertInitial */
	if (R_flag) {
		if (n_num_Request_count == 0)
			return (SCEP_PKISTATUS_SUCCESS);
		printf("%s: requesting certificate (#1)\n",	pname);
		scep_t->request_type = SCEP_REQUEST_GETCERTINIT;
		count++;
	} else {
		printf("%s: sending certificate request\n",	pname);
		scep_t->request_type = SCEP_REQUEST_PKCSREQ;
	}

	pkistatus = scep_operation_polling(
			verbose,
			http,
			SCEP_OPERATION_ENROLL,
			M_char,
			payload,
			payload_len,
			p_flag,
			host_name,
			host_port,
			dir_name,
			scep_t,
			ca_caps,
			&count);
	if (pkistatus != SCEP_PKISTATUS_SUCCESS)
	{
		return(pkistatus);
	}

	/* We got SUCCESS, analyze the reply */
	write_local_cert(scep_t);

	return(pkistatus);
}

/**
 * @fn int scep_operation_getcrl(int, struct http_reply*, char*, char*, size_t, int, char*, int, char*, struct scep*, int)
 * @brief
 *
 * @param verbose
 * @param http
 * @param M_char
 * @param payload
 * @param payload_len
 * @param p_flag
 * @param host_name
 * @param host_port
 * @param dir_name
 * @param scep_t
 * @param ca_caps
 * @return
 */
int scep_operation_getcrl(
		int verbose,
		struct http_reply *http,
		char *M_char,
		char *payload,
		size_t payload_len,
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t,
		int ca_caps
		)
{
	int pkistatus = SCEP_PKISTATUS_SUCCESS;
	int count = 1;

	/* Read local certificate */
	if (!l_flag) {
	  //fprintf(stderr, "%s: missing local cert (-l)\n", pname);
	  error("missing local cert (-l)");
	  return (SCEP_PKISTATUS_FILE);
	}
	if (!(localcert = read_cert(l_char_local_certificate))) {
		//fprintf(stderr, "%s: cannot read local cert (-l) %s\n", pname, l_char_local_certificate);
		error("cannot read local cert (-l) %s\n", l_char_local_certificate);
		return(SCEP_PKISTATUS_FILE);
	}

	// On prépare la transaction
	pkistatus = scep_operation_common_enroll_getcrl_getcert(verbose, scep_t, SCEP_OPERATION_GETCRL);
	if (pkistatus != SCEP_PKISTATUS_SUCCESS)
	{
		return(pkistatus);
	}

	if (v_flag)
		fprintf(stdout,	"%s: SCEP_OPERATION_GETCRL\n", pname);

	scep_t->request_type = SCEP_REQUEST_GETCRL;
	printf("%s: requesting crl\n",pname);

	pkistatus = scep_operation_polling(
				verbose,
				http,
				SCEP_OPERATION_GETCRL,
				M_char,
				payload,
				payload_len,
				p_flag,
				host_name,
				host_port,
				dir_name,
				scep_t,
				ca_caps,
				&count);
	if (pkistatus != SCEP_PKISTATUS_SUCCESS)
	{
		return(pkistatus);
	}

	write_crl(scep_t);
	/* We got SUCCESS, analyze the reply */

	return(pkistatus);
}

/**
 * @fn int scep_operation_getcert(int, struct http_reply*, char*, char*, size_t, int, char*, int, char*, struct scep*, int)
 * @brief
 *
 * @param verbose
 * @param http
 * @param M_char
 * @param payload
 * @param payload_len
 * @param p_flag
 * @param host_name
 * @param host_port
 * @param dir_name
 * @param scep_t
 * @param ca_caps
 * @return
 */
int scep_operation_getcert(
		int verbose,
		struct http_reply *http,
		char *M_char,
		char *payload,
		size_t payload_len,
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t,
		int ca_caps
		)
{
	int pkistatus = SCEP_PKISTATUS_SUCCESS;
	int count = 1;

	/* Read local certificate */
	if (!l_flag) {
	  //fprintf(stderr, "%s: missing local cert (-l)\n", pname);
	  error("missing local cert (-l)");
	  return (SCEP_PKISTATUS_FILE);
	}
	if (!(localcert = read_cert(l_char_local_certificate))) {
		//fprintf(stderr, "%s: cannot read local cert (-l) %s\n", pname, l_char_local_certificate);
		error("cannot read local cert (-l) %s\n", l_char_local_certificate);
		return(SCEP_PKISTATUS_FILE);
	}

	// On prépare la transaction
	pkistatus = scep_operation_common_enroll_getcrl_getcert(verbose, scep_t, SCEP_OPERATION_GETCERT);
	if (pkistatus != SCEP_PKISTATUS_SUCCESS)
	{
		return(pkistatus);
	}

	if (v_flag)
		fprintf(stdout,	"%s: SCEP_OPERATION_GETCERT\n", pname);

	scep_t->request_type = SCEP_REQUEST_GETCERT;
	printf("%s: requesting certificate\n",pname);

	pkistatus = scep_operation_polling(
				verbose,
				http,
				SCEP_OPERATION_GETCERT,
				M_char,
				payload,
				payload_len,
				p_flag,
				host_name,
				host_port,
				dir_name,
				scep_t,
				ca_caps,
				&count);
	if (pkistatus != SCEP_PKISTATUS_SUCCESS)
	{
		return(pkistatus);
	}

	/* We got SUCCESS, analyze the reply */
	switch (scep_t->request_type) {

		/* Local certificate */
		case SCEP_REQUEST_PKCSREQ:
		case SCEP_REQUEST_GETCERTINIT:
			write_local_cert(scep_t);
			break;

		/* Other end entity certificate */
		case SCEP_REQUEST_GETCERT:
			write_other_cert(scep_t);
			break;
	}
	return(pkistatus);
}



/**
 * @fn		void cacaps2str(int cacaps, char *buf, int32_t i32size)
 * @param 	cacaps int: capacité du serveur codée en binaire.
 * @param 	*buf char: pointeur sur la chaine de caractère qui va contenir les capacités
 * @param 	i32size int32_t: taille du buffer buf recevant la chaine de caractère
 */
void cacaps2str(int cacaps, char *buf, int32_t i32size)
{
	int i;
	int count = 0;
	char tmp[50];

	*buf = 0;
	for ( i = 0 ; i < SCEP_CAPS ; ++i )
	{
		if (cacaps & scep_caps[i].cap)
		{
			snprintf(tmp, sizeof(tmp)-1,"%s%s",	(count++ > 1 ? ", " : ""), scep_caps[i].str);
			strncat(buf, tmp, i32size);
		}
	}
}

