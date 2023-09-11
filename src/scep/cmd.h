
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/*
 * Command line options
 * These are defined globally for easy access from all functions.
 * For each command line option 'x', there is int x_flag and
 * char *x_char or int x_num if the option requires parameter.
 */

//struct stConfig {
//	int c_flag_CA_certificate;
//	char *c_char_CA_certificate;
//	int C_flag_CA_certificate_chain;
//	char *C_char_CA_certificate_chain;
//	//int v_flag > 1;
//	int e_flag_CA_encryption_certificate;
//	char *e_char_CA_encryption_certificate;
//	char *E_char_encryption_algorythm;
//	int E_flag_encryption_algorythm;
//	int f_flag_configuration_file;
//	char *f_char_configuration_file;
//	char *F_char_fingerprint_algorythm;
//	int F_flag_fingerprint_algorythm;
//
//	#ifdef WITH_ENGINES
//	char *g_char_enable_engine_support;
//	int g_flag_enable_engine_support;
//	#endif
//	int h_flag_enable_hwcrhk_keys;
//	int H_flag_enable_old_key_engine;
//	char *l_char_local_certificate;
//	int l_flag_local_certificate;
//	char *L_char_local_self_signed_certificate;
//	int L_flag_local_self_signed_certificate;
//	char *i_char_CA_identifier;
//	int i_flag_CA_identifier;
//	char *k_char_private_key;
//	int k_flag_private_key;
//	char *K_char_Private_key_of_already_existing_certificate;
//	int K_flag_Private_key_of_already_existing_certificate;
//	int m_flag_test_mode;
//	char *m_char_test_mode;
//	int M_flag_Monitor_Information_HTTP_get_parameter_style;
//	char *M_char_Monitor_Information_HTTP_get_parameter_style;
//	int n_flag_Request_count;
//	int n_num_Request_count;
//	char *O_char_Already_existing_certificate;
//	int O_flag_Already_existing_certificate;
//	char *p_char_proxy;
//	int p_flag_proxy;
//	char *r_char_GetCrl_CRL_file;
//	int r_flag_GetCrl_CRL_file;
//	int R_flag_resume;
//	char *s_char_Certificate_serial_number;
//	int s_flag_Certificate_serial_number;
//	char *S_char_Signature_algorithm;
//	int S_flag_Signature_algorithm;
//	int t_num_Polling_interval;
//	int t_flag_Polling_interval;
//	int T_num_MAX_Polling_interval;
//	int T_flag_MAX_Polling_interval;
//	int u_flag_URL;
//	char *url_char;
//	int v_flag_verbose;
//	int w_flag_GetCert_certificate;
//	char *w_char_GetCert_certificate;
//	int W_flag_Wait_for_connectivity;
//};

extern int a_flag_PATH_Trust_Anchor;
extern char * a_char_PATH_Trust_Anchor;

/* CA certificate */
extern int c_flag;
extern char *c_char_CA_certificate;

/* CA certificate chain*/
extern int C_flag;
extern char *C_char_CA_certificate_chain;

/* Debug? */
//extern int d_flag;

/* CA encryption certificate */
extern int e_flag;
extern char *e_char_CA_encryption_certificate;

/* Encryption algorithm */
extern char *E_char_encryption_algorythm;
extern int E_flag;

/* Configuration file */
extern int f_flag;
extern char *f_char_configuration_file;

/* Fingerprint algorithm */
extern char *F_char_fingerprint_algorythm;
extern int F_flag;

#ifdef WITH_ENGINES
/* enable EnGine support */
extern char *g_char;
extern int g_flag;
#endif

/* enable hwcrhk keys
 * To set this means that the new key (for which you have the
 * CSR and Private Key) should be taken from the engine
 * while the old key (possibly, see captial letter options)
 * is selected by the -H option
*/
//extern int h_flag; //not used

/* sets if engine should be used if the old key usage is set
 * i.e., setting this uses the old key for signing and does
 * not set anything for the lowercase options that correspond
 * to the new keys
*/
//extern int H_flag;// not used

/* Local certificate  */
extern char *l_char_local_certificate;
extern int l_flag;

/* Local selfsigned certificate  (generated automaticatally) */
extern char *L_char_local_self_signed_certificate;
extern int L_flag;

/* CA identifier */
extern char *i_char_CA_identifier;
extern int i_flag;

/* CA in the cert file */
extern int j_flag;

/* Private key */
extern char *k_char_private_key;
extern int k_flag;

/* Private key of already existing certificate */
extern char *K_char_Private_key_of_already_existing_certificate;
extern int K_flag;

/* Test mode */
extern int m_flag;
extern char *m_char_test_mode;

/* Monitor Information HTTP get parameter style */
extern int M_flag;
extern char *M_char_Monitor_Information_HTTP_get_parameter_style;

/* Request count */
extern int n_flag;
extern int n_num_Request_count;

/* Already existing certificate (to be renewed) */
extern char *O_char_Already_existing_certificate;
extern int O_flag;

/* Proxy */
extern char *p_char_proxy;
extern int p_flag;

/* fingerprint filename to compare the root CA fingerprint with the file */
extern int P_flag_fingerprint_filename;
extern char *P_char_fingerprint_filename;

/* GetCrl CRL file */
extern char *r_char_Certificate_request_file;
extern int r_flag;

/* Resume */
extern int R_flag;

/* Certificate serial number */
extern char *s_char_Certificate_serial_number;
extern int s_flag;

/* Signature algorithm */
extern char *S_char_Signature_algorithm;
extern int S_flag;

/* Polling interval */
extern int t_num_Polling_interval;
extern int t_flag;

/* Max polling time */
extern int T_num_MAX_Polling_interval;
extern int T_flag;

/* URL */
extern int u_flag;
extern char *url_char;

/* Verbose? boolean */
extern int v_flag;

/* GetCert certificate */
extern int w_flag;
extern char *w_char_GetCert_certificate;

/* Wait for connectivity */
extern int W_flag;

/* Filename of the certificate template */
extern int x_flag;
extern char *x_char_certificate_template_filename;

/* End of command line options */

