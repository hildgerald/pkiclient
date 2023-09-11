/*
 * est_actions.c
 *
 *  Created on: 3 août 2023
 *      Author: gege
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <getopt.h>
#include <syslog.h>

#include <string.h>
#include "../pkiclient.h"
#include "est_actions.h"
#include "picohttpparser.h"
#include "../check.h"

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
#if 0
unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = os_malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}
#endif

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
int base64_decode(
		const unsigned char *src,
		size_t len,
		unsigned char *out,
	    size_t *out_len)
{
	unsigned char dtable[256] = {0x80};
	unsigned char *pos;
	unsigned char block[4];
	unsigned char tmp;
	size_t i = 0;
	size_t count = 0;
	int pad = 0;

	//os_memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return 1;

	//olen = count / 4 * 3;
	pos = out; // = os_malloc(olen);
	if (out == NULL)
		return 1;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					//os_free(out);
					return 1;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return 0;
}

/**
 * @fn int read_csr(char*, char*, uint32_t)
 * @brief This function read the PKCS#10 of the csr and copy base64 datas
 * 		in the buffer
 *
 * @param csrfilename char * : pointeur on the CSR filename
 * @param Datas char * : pointer on the datas
 * @param Datas_size uint32_t: maximum size of the buffer
 * @return number of real datas writen in the buffer
 */
uint32_t read_csr(char * csrfilename, char * Datas, uint32_t Datas_size)
{
	uint32_t ret = 0;
	FILE * fp = NULL;
	char line[255] = {0};
	fp = fopen(csrfilename, "r");

	if (fp)
	{
		// We has datas so we read them and write them in the buffer
		while (fgets(line, sizeof(line)-1, fp) != NULL)
		{
			if (strncmp(line, "--", 2) != 0)
			{
				//On ajoute toute la ligne dans le buffer de datas
				strncat(Datas, line, Datas_size);
				ret += strlen(line);
			}
		}
		fclose(fp);
	}
	return(ret);
}

/**
 * @fn void init_ssl_opts(SSL_CTX*, const char*, const char*, const char*, int)
 * @brief This function initialize the SSL options...
 *
 * @param ctx
 * @param ca_filename
 * @param cert_filename
 * @param cert_key_filename
 * @param SSL_Mode
 */
void init_ssl_opts(SSL_CTX* ctx,
		const char* ca_filename,
		const char *cert_filename,
		const char *cert_key_filename,
		int SSL_Mode) {
	if (!SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256")) {
		//logger(LOG_ERR, "Could not set cipher list [%s]", ERR_error_string(ERR_get_error(), NULL));
		printf("Error : Could not set cipher list [%s]", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) {
		//logger(LOG_ERR, "Could not disable compression [%s]",
		printf("Error :Could not disable compression [%s]",
			ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}

	// If we need to verify the peer, we get the certificate and key file
	if (SSL_Mode != SSL_VERIFY_NONE)
	{
		if (SSL_CTX_load_verify_locations(ctx, ca_filename, 0) <= 0) {
			printf("Error :Unable to set verify locations [%s]",
				ERR_error_string(ERR_get_error(), NULL));
			exit(EXIT_FAILURE);
		}
		if (cert_filename) {
			if (SSL_CTX_use_certificate_file(ctx, cert_filename, SSL_FILETYPE_PEM) <= 0) {
				printf("Error :Could not load cert file(%s) [%s]",
						cert_filename, ERR_error_string(ERR_get_error(), NULL));
				exit(EXIT_FAILURE);
			}
		}
		if (cert_key_filename) {
			if (SSL_CTX_use_PrivateKey_file(ctx, cert_key_filename, SSL_FILETYPE_PEM) <= 0) {
				printf("Error :Could not load key file(%s) [%s]",
					cert_key_filename, ERR_error_string(ERR_get_error(), NULL));
				exit(EXIT_FAILURE);
			}
			if (!SSL_CTX_check_private_key(ctx)) {
				printf("Error :Private key does not match public key in certificate [%s]",
					ERR_error_string(ERR_get_error(), NULL));
				exit(EXIT_FAILURE);
			}
		}

	}
	//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE, 0);
	SSL_CTX_set_verify(ctx, SSL_Mode, 0);
}

/**
 * @fn int https_request(struct http_reply*, const int, const char*, const char*, const char*, const char*, const char*, const char*, size_t)
 * @brief This function sends datas to a server in https protocol and get the response
 *
 * @param http struct http_reply *: reply of the server
 * @param SSL_Mode int : Mode of the SSL : 0, without control,
 * @param cert_filename const char* : filename of the certificate that authenticate the software
 * @param cert_key_filename const char* : filename of the private key
 * @param ca_filename const char* : filename of the CAs
 * @param host_name const char* : hostname or the IP of the server
 * @param port_str const char* : port of the server
 * @param http_string const char* : datas to send (HTTP header and payload)
 * @param rlen size_t : size of data to send
 * @return 0 if OK
 */
int https_request(	struct http_reply *http,
					const int SSL_Mode,
					const char* cert_filename,
					const char* cert_key_filename,
					const char* ca_filename,
					const char* host_name,
					const char *port_str,
					const char *http_string,
					size_t rlen)
{
	const SSL_METHOD 	*meth = TLS_client_method();
	SSL_CTX				*ctx;
	SSL					*ssl;
	int 				err;
	int 				sd;
	X509                *cert = NULL;
	X509_NAME       	*certname = NULL;
	BIO               	*outbio = NULL;
	STACK_OF(X509) 		*chain = NULL;
	unsigned int		n;
	unsigned char		md[EVP_MAX_MD_SIZE];

	//struct sockaddr_in sa;
	//char buf[4096];
	char 				*buf;
	struct addrinfo 	hints;
	struct addrinfo 	*res;
	struct addrinfo 	*resolve_array;
	int 				i;
	int 				used;
	int					bytes;
	int					http_chunked;
	int 				http_minor;
	const char 			*http_msg;
	size_t 				msg_size, headers_num, header_size, body_size;
	struct phr_header 	headers[100];
	struct phr_chunked_decoder http_decoder = {0};
	char 				*mime_type;


	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
	ctx = SSL_CTX_new(meth);

	init_ssl_opts(ctx, ca_filename, cert_filename, cert_key_filename, SSL_Mode);

	/* resolve name */
	memset(&hints, 0, sizeof(hints));
	//hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = (AI_ADDRCONFIG | AI_V4MAPPED);
	err = getaddrinfo(host_name, port_str, &hints, &resolve_array);
	if (err!=0) {
		//fprintf(stderr, "failed to resolve remote host address %s (err=%d)\n", host_name, err);
		error("failed to resolve remote host address %s (err=%d)\n", host_name, err);
		return (1);
	}

	/* getaddrinfo() returns a list of address structures.
		Try each address until we successfully connect.
		If socket (or connect) fails, we close the socket
		and try the next address. */
	for (res = resolve_array;
		res != NULL;
		res = resolve_array->ai_next) {
		sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sd < 0) {
			continue;
		}

		/* connect to server */
		/* The two socket options SO_RCVTIMEO and SO_SNDTIMEO do not work with connect
		connect has a default timeout of 120 */
		err = connect(sd, res->ai_addr, res->ai_addrlen);
		if (err < 0) {
			close(sd);
			continue;
		}

		/* connected, exit loop */
		break;
	}

	freeaddrinfo(resolve_array);
	if (!res ) {
		//perror("cannot connect");
		error("can not connect");
		return (1);
	}

	// SSL connection
	ssl = SSL_new(ctx);

	SSL_set_fd(ssl, sd);
	SSL_set_connect_state(ssl);

	for (;;) {
		int success = SSL_connect(ssl);

		if (success < 0) {
			err = SSL_get_error(ssl, success);

			if ((err == SSL_ERROR_WANT_READ)
				|| (err == SSL_ERROR_WANT_WRITE)
				|| (err == SSL_ERROR_WANT_X509_LOOKUP))
			{
				continue;
			}
			else if (err == SSL_ERROR_ZERO_RETURN)
			{
				//printf("SSL_connect: close notify received from peer");
				error("SSL_connect: close notify received from peer");
				exit(18);
			} else {
//				printf("Error SSL_connect: %d", err);
//				fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
				error("Error SSL_connect: %d : %s", err, ERR_error_string(ERR_get_error(), NULL));
				SSL_free(ssl);
				close(sd);
				exit(16);
			}
		} else
			break;
	}

	/* ---------------------------------------------------------- *
	* Get the remote certificate into the X509 structure         *
	* ---------------------------------------------------------- */
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL)
		//BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", host_name);
		error("Error: Could not get a certificate from: %s.", host_name);
	else
		//BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", host_name);
		notice("Retrieved the server's certificate from: %s.", host_name);

	/* ---------------------------------------------------------- *
	* extract various certificate information                    *
	* -----------------------------------------------------------*/
	certname = X509_NAME_new();
	certname = X509_get_subject_name(cert);

	chain = SSL_get_peer_cert_chain(ssl);
	if (chain != NULL)
	{
		printf("\n%s: found chain certificate with %d CA: \n", pname, sk_X509_num(chain));

		for (i = 0; i < sk_X509_num(chain); i++) {
			char buffer[1024];


			memset(buffer, 0, 1024);
			cert = sk_X509_value(chain, i);

			/* Read and print certificate information */
			if (v_flag){
				printf("\n%s: found certificate with\n  subject: %s\n", pname,
						X509_NAME_oneline(X509_get_subject_name(cert),	buffer, sizeof(buffer)));

				printf("  issuer: %s\n", X509_NAME_oneline(X509_get_issuer_name(cert),	buffer, sizeof(buffer)));
				if (!X509_digest(cert, fp_alg, md, &n)) {
					//ERR_print_errors_fp(stderr);
					error("error digest certificate file : %s", ERR_error_string(ERR_get_error(),NULL));
				}
			}
		}
	}
	else
	{

	}

	/* ---------------------------------------------------------- *
	* display the cert subject here                              *
	* -----------------------------------------------------------*/
	BIO_printf(outbio, "Displaying the certificate subject data:\n");
	X509_NAME_print_ex(outbio, certname, 0, 0);
	BIO_printf(outbio, "\n");

	/* send data */
	err = SSL_write(ssl, http_string, rlen);
	//err = send(sd, http_string, rlen, 0);

	if (err < 0) {
		err = SSL_get_error(ssl, err);
//		snprintf(txt, sizeof(txt)-1,"cannot send data : %s", ERR_reason_error_string(err));
//		perror(txt);
		error("cannot send data : %s", ERR_reason_error_string(err));
		close(sd);
		return (1);
	}

	/* Get response */
	buf = (char *)malloc(1024);
	used = 0;
	//while ((bytes = recv(sd,&buf[used],1024,0)) > 0)
//	while ((bytes = SSL_read(ssl, &buf[used], 1024)) > 0)
//	{
//		printf("SSL_read bytes = %d; SSLError %d; SSL_pending %d\n", bytes, SSL_get_error(ssl, bytes), SSL_pending(ssl));
//			used += bytes;
//			buf = (char *)realloc(buf, used + 1024);
//	}

	do
	{
		bytes = SSL_read(ssl, &buf[used], 1024);
		printf("SSL_read bytes = %d; SSLError %d; SSL_pending %d\n", bytes, SSL_get_error(ssl, bytes), SSL_pending(ssl));
		used += bytes;
		buf = (char *)realloc(buf, used + 1024);
	}
	//while (SSL_pending(ssl) > 0);
	while (bytes > 0);

	if (used <= 0) {
		perror("error receiving data ");
		close(sd);
		return (1);
	}

	headers_num = sizeof(headers) / sizeof(headers[0]);
	err = phr_parse_response(buf, used, &http_minor, &http->status,
			&http_msg, &msg_size, headers, &headers_num, 0);
	if (err < 0) {
		//fprintf(stderr,"cannot parse response\n");
		error("cannot parse response");
		close(sd);
		return (2);
	}
	header_size = err;

	mime_type = NULL;
	http_chunked = 0;
	for (i = 0; i < headers_num; i++)
	{
		char *ch;
		/* convert to lowercase as some platforms don't have strcasecmp */
		for (ch = (char *)headers[i].name; ch < headers[i].name+headers[i].name_len; ch++)
			*ch = tolower(*ch);

		if (!strncmp("content-type", headers[i].name, headers[i].name_len))
		{
			char *ptr;

			mime_type = (char *)headers[i].value;
			mime_type[headers[i].value_len] = '\0';

			if ((ptr = strchr(mime_type, ';')))
				*ptr = '\0';
		}
		else if (!strncmp("transfer-encoding", headers[i].name, headers[i].name_len) &&
			!strncmp("chunked", headers[i].value, headers[i].value_len))
		{
			http_chunked = 1;
		}
	}

	if (v_flag)
		fprintf(stdout, "%s: server response status code: %d, MIME header: %s\n",
			pname, http->status, mime_type ? mime_type : "missing");

	http->mime_type = mime_type;
	http->payload = buf+header_size;
	body_size = used-header_size;

	if (http_chunked)
	{
		err = phr_decode_chunked(&http_decoder, http->payload, &body_size);
		if (err < 0) {
			//fprintf(stderr,"%i cannot decode chunked payload\n", err);
			error("%d cannot decode chunked payload", err);
			close(sd);
			return (2);
		}
	}

	http->payload[body_size] = '\0';
	http->bytes = body_size;

	close(sd);
	//close(efd);
	return 0;
}

/**
 * @fn int send_est_msg(struct http_reply*, int, char*, int, char*, char*, size_t, int, char*, int, char*)
 * @brief This function send a HTTP message to the EST server and get the responds
 *
 * @param http : structure de communication entre le client http en send_msg
 * @param do_post : 1 This is a POST request
 * @param est_operation : EST operation like EST_OPERATION_CACERTS ...
 * @param operation : the real operation
 * @param M_char :
 * @param payload :
 * @param payload_len :
 * @param p_flag : post or get HTTP operation
 * @param host_name :
 * @param host_port :
 * @param dir_name :
 * @return
 */
int send_est_msg(
		struct http_reply *http,
		int operation,
		char *payload,
		size_t payload_len,
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		int SSL_Mode,
		char * CA_certificate,
		char * certificate,
		char * PrivateKey)
{
	char			http_string[16384];
	size_t			rlen;
	char			port_str[6]; /* Range-checked to be max. 5-digit number */
	int 			ret, fail_count, waited_sec;
	int 			do_post = 0;

	switch (operation) {
	case EST_OPERATION_CACERTS:
		rlen = snprintf(
				http_string,
				sizeof(http_string),
				"GET %s%s/cacerts",
				p_flag ? "" : "/",
				dir_name);
		break;
	case EST_OPERATION_SIMPLEENROLL:
		rlen = snprintf(
				http_string,
				sizeof(http_string),
				"POST %s%s/simpleenroll",
				p_flag ? "" : "/",
				dir_name);
		do_post = 1;
		break;
	case EST_OPERATION_SIMPLEREENROLL:
		rlen = snprintf(
			http_string,
			sizeof(http_string),
			"POST %s%s/simplereenroll",
			p_flag ? "" : "/",
			dir_name);
		do_post = 1;
		break;

	}

	exit_string_overflow(sizeof(http_string) <= rlen);

	if (host_port == 443) {
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
						" HTTP/1.1\r\n"
						"Host: %s\r\n"
						"Connection: close\r\n", host_name);
	} else {
		/* According to RFC2616, non-default port must be added. */
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
				" HTTP/1.1\r\n"
				"Host: %s:%d\r\n"
				"user-agent: curl/7.85\r\n"
				"accept: */*\r\n"
				"Connection: close\r\n", host_name, host_port);
	}
	exit_string_overflow(sizeof(http_string) <= rlen);

	if (do_post) {
		if ((operation == EST_OPERATION_SIMPLEENROLL) || (operation == EST_OPERATION_SIMPLEREENROLL))
		{
			rlen += snprintf(
					http_string+rlen,
					sizeof(http_string)-rlen,
					"Content-Type: application/pkcs10\r\n");
			exit_string_overflow(sizeof(http_string) <= rlen);
			rlen += snprintf(
					http_string+rlen,
					sizeof(http_string)-rlen,
					"Content-Transfert-Encoding: base64\r\n");
			exit_string_overflow(sizeof(http_string) <= rlen);
		}
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
				"Content-Length: %zu\r\n", payload_len);
		exit_string_overflow(sizeof(http_string) <= rlen);
	}

	rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen, "\r\n");
	exit_string_overflow(sizeof(http_string) <= rlen);

	if (do_post) {
		/* concat post data */
		memcpy(http_string+rlen, payload, payload_len);

		rlen += payload_len;
		exit_string_overflow(sizeof(http_string) <= rlen);
	}

	if (v_flag > 1){
		fprintf(stdout, "%s: est request:\n%s\n***** END REQUEST ****\n", pname, http_string);
	}

	sprintf(port_str, "%d", host_port);

	fail_count = 0;
	waited_sec = 0;
	/* will retry with linear backoff, just like wget does */
	while (1) {
		ret = https_request(
				http,
				SSL_Mode,
				certificate,
				PrivateKey,
				CA_certificate,
				host_name,
				port_str,
				http_string,
				rlen);
		if (ret == 0)
			break;
		if (ret == 2 || waited_sec >= W_flag)
			return (1);

		++fail_count;
		if ((waited_sec + fail_count) <= W_flag) {
			sleep(fail_count);
			waited_sec += fail_count;
		} else {
			sleep(W_flag - waited_sec);
			waited_sec = W_flag;
		}
	}

	http->type = 0;
	/* Set EST reply type */
	switch (operation) {
		case EST_OPERATION_CACERTS:
			if (http->mime_type && !strcmp(http->mime_type, MIME_PKCS7)) {
				http->type = EST_MIME_CACERTS;
			} else {
				goto mime_err;
			}
			break;
		case EST_OPERATION_SIMPLEENROLL:
			if (http->mime_type && !strcmp(http->mime_type, MIME_PKCS7)) {
				http->type = EST_MIME_SIMPLEENROLL;
			}
			else if (http->mime_type && !strcmp(http->mime_type, MIME_PKCS10)) {
				http->type = EST_MIME_SIMPLEENROLL;
			}
			else {
				goto mime_err;
			}
			break;
		case EST_OPERATION_SIMPLEREENROLL:
			if (http->mime_type && !strcmp(http->mime_type, MIME_PKCS7)) {
				http->type = EST_MIME_SIMPLEREENROLL;
			}
			else if (http->mime_type && !strcmp(http->mime_type, MIME_PKCS10)) {
				http->type = EST_MIME_SIMPLEREENROLL;
			}
			else {
				goto mime_err;
			}
			break;
		default:
			if (http->mime_type && !strcmp(http->mime_type, MIME_PKI)) {
				http->type = SCEP_MIME_PKI;
			} else {
				goto mime_err;
			}
			break;
	}

	return (0);

mime_err:
	if (v_flag)
		//fprintf(stderr, "%s: wrong (or missing) MIME content type : %s\n", pname, http->mime_type);
		error("wrong (or missing) MIME content type : %s", http->mime_type);

	return (1);
}

/**
 * @fn int write_ca_est(struct http_reply*)
 * @brief
 *
 * @param s
 * @return
 */
int write_ca_est(struct http_reply *s, char * CA_Filename) {
	BIO			*bio;
	PKCS7			*p7;
	STACK_OF(X509)		*certs = NULL;
	X509			*cert = NULL;
	FILE			*fp = NULL;
	int			c, i, index;
    unsigned int		n;
    unsigned char		md[EVP_MAX_MD_SIZE];
	X509_EXTENSION		*ext;

	char filePath[512]={0};
	char buffer[16000] = {0};
	size_t taille = 0;
	char buffer1[16000] = {0};
	size_t taille1 = 0;
	int32_t ret = 0;

	/* Create read-only memory bio */
	for (i=0; i< s->bytes; i++)
	{
		if (s->payload[i] >=32)
		{
			buffer[taille] = s->payload[i];
			taille++;
		}
	}
	base64_decode(buffer, taille, buffer1, &taille1);
	bio = BIO_new_mem_buf(buffer1, taille1);
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
			//printf("%s: wrong PKCS#7 type\n", pname);
			error("wrong PKCS#7 type");
			exit (SCEP_PKISTATUS_FILE);
	}
	/* Check  */
	if (certs == NULL) {
		//fprintf(stderr, "%s: cannot find certificates\n", pname);
		error("cannot find certificates");
		exit (SCEP_PKISTATUS_FILE);
	}

	// Define the path of the files
	strncpy(filePath, CA_Filename, sizeof(filePath) - 1);
	i = ExtractFilePath(filePath);
	if (i != 1)
	{
		//printf("Error, impossible to find the path of the file to write the trust chain !\n");
		error("impossible to find the path of the file to write the trust chain !");
		return 1;
	}

	/* Verify the chain
	 * XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	 */
	/* Find cert */
	for (i = 0; i < sk_X509_num(certs); i++) {
		char buffer[1024];
		char name[1024];

		memset(buffer, 0, 1024);
		memset(name, 0, 1024);
		cert = sk_X509_value(certs, i);

		/* Create name */
		snprintf(name, 1024, "%s-%d", CA_Filename, i);

		/* Read and print certificate information */
		if (v_flag){
			printf("\n%s: found certificate with\n  subject: %s\n", pname,
					X509_NAME_oneline(X509_get_subject_name(cert),
					buffer, sizeof(buffer)));
		}
		if (v_flag)
			printf("  issuer: %s\n",
					X509_NAME_oneline(X509_get_issuer_name(cert),
					buffer, sizeof(buffer)));

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
			if (v_flag)
			{
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
			if (v_flag)
			{
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

		ret = check_verify_CA(cert, certs , NULL, NULL);
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

		/* Write PEM-formatted file: */
#ifdef WIN32
		if ((fopen_s(&fp, name, "w")))
#else
		if (!(fp = fopen(name, "w")))
#endif
		{
//			fprintf(stderr, "%s: cannot open cert file for "
//				"writing\n", pname);
			error("cannot open cert file for writing");
			exit (SCEP_PKISTATUS_FILE);
		}
		if (v_flag)
			printf("%s: certificate written as %s\n", pname, name);
		if (v_flag > 1)
			PEM_write_X509(stdout, cert);
		if (PEM_write_X509(fp, cert) != 1) {
//			fprintf(stderr, "%s: error while writing certificate file\n", pname);
//			ERR_print_errors_fp(stderr);
			warning("error while writing certificate file: %s", ERR_error_string(ERR_get_error(),NULL));
			exit (SCEP_PKISTATUS_FILE);
		}

		fclose(fp);
	}
	PKCS7_free(p7);
	BIO_free(bio);
	exit (SCEP_PKISTATUS_SUCCESS);
}

/**
 * @fn int write_cert_est(struct http_reply*)
 * @brief
 *
 * @param s
 * @return
 */
int write_cert_est(struct http_reply *s, char * CA_Filename, char * Cert_filename) {
	BIO			*bio;
	PKCS7			*p7;
	STACK_OF(X509)		*certs = NULL;
	X509			*cert = NULL;
	FILE			*fp = NULL;
	int			c, i, index;
    unsigned int		n;
    unsigned char		md[EVP_MAX_MD_SIZE];
	X509_EXTENSION		*ext;
	char filePath[512]={0};
	char buffer[16000] = {0};
	size_t taille = 0;
	char buffer1[16000] = {0};
	size_t taille1 = 0;
	int32_t ret = 0;
	char name[512] = {0};
	int32_t i32Index = 0;
	int32_t i32SensCA = 1;


	/* Create read-only memory bio */
	for (i=0; i< s->bytes; i++)
	{
		if (s->payload[i] >=32)
		{
			buffer[taille] = s->payload[i];
			taille++;
		}
	}
	base64_decode(buffer, taille, buffer1, &taille1);
	bio = BIO_new_mem_buf(buffer1, taille1);
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
			//printf("%s: wrong PKCS#7 type\n", pname);
			error("wrong PKCS#7 type");
			exit (SCEP_PKISTATUS_FILE);
	}
	/* Check  */
	if (certs == NULL) {
		//fprintf(stderr, "%s: cannot find certificates\n", pname);
		error("cannot find certificates");
		exit (SCEP_PKISTATUS_FILE);
	}

	// Define the path of the files
	strncpy(filePath, CA_Filename, sizeof(filePath) - 1);
	i = ExtractFilePath(filePath);
	if (i != 1)
	{
		//printf("Error, impossible to find the path of the file to write the trust chain !\n");
		error("impossible to find the path of the file to write the trust chain !");
		return 1;
	}

	/* Find cert */
	memset(buffer, 0, sizeof(buffer));
	cert = sk_X509_value(certs, 0);

	/* Create name */
	snprintf(name, 1024, "%s", Cert_filename);

	/* Read and print certificate information */
	if (v_flag){
		printf("\n%s: found certificate with\n  subject: %s\n", pname,
				X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer)));
		printf("  issuer: %s\n",
				X509_NAME_oneline(X509_get_issuer_name(cert),buffer, sizeof(buffer)));
	}

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

	if (v_flag)
		printf("%s: certificate %s must to be verify\n", pname, l_char_local_certificate);

	ret = check_verify_cert(cert, certs);

	if (ret != 0)
	{
		//fprintf(stderr, "%s: the cert file %s is not valid\n", pname, l_char);
//		snprintf(buf, sizeof(buf)-1, "the cert file %s is not valid", l_char_local_certificate);
//		add_log(buf, LOG_WARNING);
		warning("the cert file %s is not valid", l_char_local_certificate);
		exit (SCEP_PKISTATUS_FILE);
	}

	if (v_flag)
	{
		printf("%s: the certificate %s is valid\n", pname, l_char_local_certificate);
		printf("The number of certificate in the bundle are : %d\n", sk_X509_num(certs));
	}
	/* Write PEM-formatted file: */
#ifdef WIN32
	if ((fopen_s(&fp, name, "w")))
#else
	if (!(fp = fopen(name, "w")))
#endif
	{
		//fprintf(stderr, "%s: cannot open cert file for writing\n", pname);
		error("cannot open cert file for writing");
		exit (SCEP_PKISTATUS_FILE);
	}
	if (v_flag)
		printf("%s: certificate written as %s\n", pname, name);
	if (v_flag > 1)
	{
		PEM_write_X509(stdout, cert);
	}
	if (PEM_write_X509(fp, cert) != 1)
	{
//		fprintf(stderr, "%s: error while writing certificate file\n", pname);
//		ERR_print_errors_fp(stderr);
		warning("error while writing certificate file : %s", ERR_error_string(ERR_get_error(),NULL));
		exit (SCEP_PKISTATUS_FILE);
	}

	if (j_flag != 0)
	{
		// We need to write the trust chain in the certificate.
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
//					add_log("error while writing certificate CA in the service certificate file", LOG_WARNING);
//					//ERR_print_errors_fp(stderr);
//					snprintf(buf, sizeof(buf)-1, "%s: %s", pname, ERR_error_string(ERR_get_error(),NULL));
//					add_log(buf, LOG_WARNING);
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
	fclose(fp);



	PKCS7_free(p7);
	BIO_free(bio);
	exit (SCEP_PKISTATUS_SUCCESS);
}

/**
 * @fn int est_operation_cacerts(int, struct http_reply*, char*, char*, size_t, int, char*, int, char*, struct scep*)
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
 * @return
 */
int est_operation_cacerts(
		int verbose,
		struct http_reply *http,
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t)
{
	int pkistatus = 0;
	int c;
//	FILE	*fp = NULL;
//	BIO		*bp;
//	unsigned int		n;
//	unsigned char		md[EVP_MAX_MD_SIZE];

	if (verbose)
		fprintf(stdout, "%s: EST_OPERATION_CACERTS\n", pname);

	/* Set CA identifier */
//	if (!i_flag)
//		i_char = CA_IDENTIFIER;

	/*
	 * Send http message.
	 * Response is written to http_response struct "reply".
	 */
	http->payload = NULL;
	if ((c = send_est_msg(
			http,
			EST_OPERATION_CACERTS,
			NULL,
			0,
			p_flag,
			host_name,
			host_port,
			dir_name,
			//(SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE)
			(SSL_VERIFY_NONE),
			c_char_CA_certificate,
			l_char_local_certificate,
			k_char_private_key
			)
		) == 1) {
		//fprintf(stderr, "%s: error while sending message\n", pname);
		error("error while sending message");
		return (SCEP_PKISTATUS_NET);
	}
	if (http->payload == NULL) {
		//fprintf(stderr, "%s: no data, perhaps you should define CA identifier (-i)\n", pname);
		error("no data, perhaps you should define CA identifier (-i); error code  : %d",http->status);
		return (SCEP_PKISTATUS_SUCCESS);
	}

	if ((http->type == EST_MIME_CACERTS) && (http->status == 200))
	{
		if (verbose){
			printf("%s: valid response from server\n", pname);
		}
		write_ca_est(http, c_char_CA_certificate);
	}

	// if we arive here, there is a problem
	if (http->status != 200)
	{
		// We must write the error on the screen
//		printf("%s: error response from server : error %d; ", pname, http->status);
//		if (http->payload)
//		{
//			printf("%s", http->payload);
//		}
//		printf("\n");
		error("error response from server : error %d; msg : %s", http->status, http->payload);
	}

	scep_t->pki_status = pkistatus = SCEP_PKISTATUS_ERROR;
	return (pkistatus);
}

/**
 * @fn int est_operation_simpleenroll(int, struct http_reply*, char*, char*, size_t, int, char*, int, char*, struct scep*)
 * @brief
 *
 * @pre
 * @post
 * @param verbose
 * @param http
 * @param certificate_sign_char
 * @param private_key_char
 * @param p_flag
 * @param host_name
 * @param host_port
 * @param dir_name
 * @param scep_t
 * @return
 */
int est_operation_simpleenroll(
		int verbose,
		struct http_reply *http,
		char *CSR_filename, // -r ou r_char
		char *certificate_sign_char, // -O ou O_char
		char *private_key_char, // -K ou K_char
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t,
		char *out_Certificate_filename // -l ou l_char
		)
{
	int pkistatus = 0;
	int c;
//	FILE	*fp = NULL;
//	BIO		*bp;
//	unsigned int		n;
//	unsigned char		md[EVP_MAX_MD_SIZE];
	char csr_datas[16384] = {0};
	uint32_t csr_datas_size = 0;
	int SSL_Mode = SSL_VERIFY_NONE;

	if (verbose)
		fprintf(stdout, "%s: EST_OPERATION_SIMPLEENROLL\n", pname);

	/*
	 * Define the payload
	 */
	csr_datas_size = read_csr(CSR_filename, csr_datas, sizeof(csr_datas)-1);
	if (csr_datas_size == 0)
	{
		//fprintf(stderr, "%s: error while reading CSR file\n", pname);
		error("error while reading CSR file");
		return (SCEP_PKISTATUS_NET);
	}

	/*
	 * Send http message.
	 * Response is written to http_response struct "reply".
	 */
	http->payload = NULL;
	if (c_char_CA_certificate)
	{
		// TODO : activer la fonction de vérification
		//SSL_Mode = (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
	}
	if ((c = send_est_msg(
			http,
			EST_OPERATION_SIMPLEENROLL,
			csr_datas,
			csr_datas_size,
			p_flag,
			host_name,
			host_port,
			dir_name,
			//(SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE)
			SSL_Mode,
			c_char_CA_certificate,
			O_char_Already_existing_certificate,
			K_char_Private_key_of_already_existing_certificate
			)
		) == 1) {
		error("error while sending message");
		return (SCEP_PKISTATUS_NET);
	}
	if (http->payload == NULL) {
		//fprintf(stderr, "%s: no data, perhaps you should define certificate identifier (-i)\n", pname);
		error("no data, perhaps you should define certificate identifier (-i); error code  : %d",http->status);
		return (SCEP_PKISTATUS_SUCCESS);
	}

	if ((http->type == EST_MIME_SIMPLEENROLL) && (http->status == 200)) {
		if (verbose){
			printf("%s: valid response from server\n", pname);
		}
		write_cert_est(http, c_char_CA_certificate, l_char_local_certificate);
	}
	// if we arive here, there is a problem
	if (http->status != 200)
	{
		// We must write the error on the screen
//		printf("%s: error response from server : error %d; ", pname, http->status);
//		if (http->payload)
//		{
//			printf("%s", http->payload);
//		}
//		else {
//			printf("NO DATAS OR ERROR MESSAGE FROM SERVER");
//		}
//		printf("\n");
		error("error response from server : error %d; msg : %s", http->status, http->payload);
	}

	scep_t->pki_status = pkistatus = SCEP_PKISTATUS_ERROR;
	return (pkistatus);
}

/**
 * @fn int est_operation_simplereenroll(int, struct http_reply*, char*, char*, char*, int, char*, int, char*, struct scep*, char*)
 * @brief
 *
 * @param verbose
 * @param http
 * @param CSR_filename
 * @param certificate_sign_char
 * @param private_key_char
 * @param p_flag
 * @param host_name
 * @param host_port
 * @param dir_name
 * @param scep_t
 * @param out_Certificate_filename
 * @return
 */
int est_operation_simplereenroll(
		int verbose,
		struct http_reply *http,
		char *CSR_filename, // -r ou r_char
		char *certificate_sign_char, // -O ou O_char
		char *private_key_char, // -K ou K_char
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t,
		char *out_Certificate_filename // -l ou l_char
		)
{
	int pkistatus = 0;
	int c;
//	FILE	*fp = NULL;
//	BIO		*bp;
//	unsigned int		n;
//	unsigned char		md[EVP_MAX_MD_SIZE];
	char csr_datas[16384] = {0};
	uint32_t csr_datas_size = 0;
	int SSL_Mode = SSL_VERIFY_NONE;

	if (verbose)
		fprintf(stdout, "%s: EST_OPERATION_SIMPLEREENROLL\n", pname);

	/*
	 * Define the payload
	 */
	csr_datas_size = read_csr(CSR_filename, csr_datas, sizeof(csr_datas)-1);
	if (csr_datas_size == 0)
	{
		//fprintf(stderr, "%s: error while reading CSR file\n", pname);
		error("error while reading CSR file");
		return (SCEP_PKISTATUS_NET);
	}

	/*
	 * Send http message.
	 * Response is written to http_response struct "reply".
	 */
	http->payload = NULL;
	if (c_char_CA_certificate)
	{
		// TODO : activer la fonction de vérification
		//SSL_Mode = (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
	}
	if ((c = send_est_msg(
			http,
			EST_OPERATION_SIMPLEREENROLL,
			csr_datas,
			csr_datas_size,
			p_flag,
			host_name,
			host_port,
			dir_name,
			//(SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE)
			SSL_Mode,		//TODO: faire le fonctionnement avec authentification
			c_char_CA_certificate,
			O_char_Already_existing_certificate,
			K_char_Private_key_of_already_existing_certificate
			)
		) == 1) {
		error("error while sending message");
		return (SCEP_PKISTATUS_NET);
	}
	if (http->payload == NULL) {
		//fprintf(stderr, "%s: no data, perhaps you should define certificate identifier (-i)\n", pname);
		error("no data, perhaps you should define certificate identifier (-i); error code  : %d",http->status);
		return (SCEP_PKISTATUS_SUCCESS);
	}

	if ((http->type == EST_MIME_SIMPLEREENROLL) && (http->status == 200)) {
		if (verbose){
			printf("%s: valid response from server\n", pname);
		}
		write_cert_est(http, c_char_CA_certificate, l_char_local_certificate);
	}
	// if we arive here, there is a problem
	if (http->status != 200)
	{
		// We must write the error on the screen
//		printf("%s: error response from server : error %d; ", pname, http->status);
//		if (http->payload)
//		{
//			printf("%s", http->payload);
//		}
//		printf("\n");
		error("error response from server : error %d; msg : %s", http->status, http->payload);
	}

	scep_t->pki_status = pkistatus = SCEP_PKISTATUS_ERROR;
	return (pkistatus);
}

#if 0
/**
 * @fn int est_operation_fullcmc(int, struct http_reply*, char*, char*, size_t, int, char*, int, char*, struct scep*)
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
 * @return
 */
int est_operation_fullcmc(
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
	int ret = 0;
	return (ret);
}

/**
 * @fn int est_operation_serverkeygen(int, struct http_reply*, char*, char*, size_t, int, char*, int, char*, struct scep*)
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
 * @return
 */
int est_operation_serverkeygen(
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
	int ret = 0;
	return (ret);
}

/**
 * @fn int est_operation_csrattrs(int, struct http_reply*, char*, char*, size_t, int, char*, int, char*, struct scep*)
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
 * @return
 */
int est_operation_csrattrs(
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
	BIO		*bp;
	unsigned int		n;
	unsigned char		md[EVP_MAX_MD_SIZE];

	if (verbose)
		fprintf(stdout, "%s: EST_OPERATION_CSRATTRS\n", pname);

	/* Set CA identifier */
//	if (!i_flag)
//		i_char = CA_IDENTIFIER;

	/*
	 * Send http message.
	 * Response is written to http_response struct "reply".
	 */
	http->payload = NULL;
	if ((c = send_est_msg(
			http,
			0,			// do GET operation
			"csrattrs",
			EST_OPERATION_CSRATTRS,
			M_char,
			i_char_CA_identifier,
			strlen(i_char_CA_identifier),
			p_flag,
			host_name,
			host_port,
			dir_name,
			//(SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE)
			(SSL_VERIFY_NONE)
			)
		) == 1) {
		fprintf(stderr, "%s: error while sending message\n", pname);
		return (SCEP_PKISTATUS_NET);
	}
	if (http->payload == NULL) {
		fprintf(stderr, "%s: no data, perhaps you "
		   "should define CA identifier (-i)\n", pname);
		return (SCEP_PKISTATUS_SUCCESS);
	}
	if (verbose){
		printf("%s: valid response from server\n", pname);
	}
	if (http->type == EST_MIME_CACERTS) {
		/* XXXXXXXXXXXXXXXXXXXXX chain not verified */
		write_ca_est(http);
	}
	/* Read payload as DER X.509 object: */
	bp = BIO_new_mem_buf(http->payload, http->bytes);
	cacert = d2i_X509_bio(bp, NULL);

	/* Read and print certificate information */
	if (!X509_digest(cacert, fp_alg, md, &n)) {
		ERR_print_errors_fp(stderr);
		return (SCEP_PKISTATUS_ERROR);
	}
	if (verbose){
		printf("%s: %s fingerprint: ", pname, OBJ_nid2sn(EVP_MD_type(fp_alg)));
		for (c = 0; c < (int)n; c++) {
			printf("%02X%c",md[c],
				(c + 1 == (int)n) ?'\n':':');
		}
	}

	/* Write PEM-formatted file: */
	#ifdef WIN32
	if ((fopen_s(&fp,c_char_CA_certificate , "w")))
	#else
	if (!(fp = fopen(c_char_CA_certificate, "w")))
	#endif
	{
		fprintf(stderr, "%s: cannot open CA file for writing\n", pname);
		return (SCEP_PKISTATUS_ERROR);
	}
	if (PEM_write_X509(fp, cacert) != 1) {
		fprintf(stderr, "%s: error while writing CA file\n", pname);
		ERR_print_errors_fp(stderr);
		return (SCEP_PKISTATUS_ERROR);
	}
	if (verbose)
		printf("%s: CA certificate written as %s\n", pname, c_char_CA_certificate);
	(void)fclose(fp);
	scep_t->pki_status = pkistatus = SCEP_PKISTATUS_SUCCESS;
	return (pkistatus);
}

#endif
