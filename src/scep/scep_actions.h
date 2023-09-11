/*
 * scep_actions.h
 *
 *  Created on: 11 déc. 2022
 *      Author: gege
 */

#ifndef SCEP_SCEP_ACTIONS_H_
#define SCEP_SCEP_ACTIONS_H_

#include "../pkiclient.h"

#define SUP_CAP_AES(cap) \
	((cap & SCEP_CAP_AES) || (cap & SCEP_CAP_STA))
#define SUP_CAP_3DES(cap) \
	(cap & SCEP_CAP_3DES)
#define SUP_CAP_NEXT_CA(cap) \
	(cap & SCEP_CAP_NEXT_CA)
#define SUP_CAP_POST_PKI(cap) \
	((cap & SCEP_CAP_POST_PKI) || (cap & SCEP_CAP_STA))
#define SUP_CAP_RENEWAL(cap) \
	(cap & SCEP_CAP_RENEWAL)
#define SUP_CAP_SHA_1(cap) \
	(cap & SCEP_CAP_SHA_1)
#define SUP_CAP_SHA_224(cap) \
	(cap & SCEP_CAP_SHA_224)
#define SUP_CAP_SHA_256(cap) \
	((cap & SCEP_CAP_SHA_256) || (cap & SCEP_CAP_STA))
#define SUP_CAP_SHA_384(cap) \
	(cap & SCEP_CAP_SHA_384)
#define SUP_CAP_SHA_512(cap) \
	(cap & SCEP_CAP_SHA_512)
#define SUP_CAP_STA(cap) \
	(cap & SCEP_CAP_STA)

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
		struct scep	*scep_t);

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
		struct scep	*scep_t);

int scep_operation_get_cacaps(
		int verbose,
		struct http_reply *http,
		char *host_name,
		int host_port,
		char *dir_name);

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
		);

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
		);

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
		);

void cacaps2str(int cacaps, char *buf, int32_t i32size);
#endif /* SCEP_SCEP_ACTIONS_H_ */
