/*
 * est_actions.h
 *
 *  Created on: 3 août 2023
 *      Author: gege
 */

#ifndef EST_EST_ACTIONS_H_
#define EST_EST_ACTIONS_H_

#include "../pkiclient.h"

int est_operation_cacerts(
		int verbose,
		struct http_reply *http,
		int p_flag,
		char *host_name,
		int host_port,
		char *dir_name,
		struct scep	*scep_t);

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
		);

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
		);

#if 0
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
		struct scep	*scep_t);

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
		struct scep	*scep_t);

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
		struct scep	*scep_t);
#endif


#endif /* EST_EST_ACTIONS_H_ */
