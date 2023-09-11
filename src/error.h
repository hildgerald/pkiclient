/*
 * enedis_error.h
 *
 *  Created on: 6 déc. 2022
 *      Author: gege
 */

#ifndef ENEDIS_ERROR_H_
#define ENEDIS_ERROR_H_

#include <stdint.h>

void debug(char *fmt, ...);
void notice(char *fmt, ...);
void warning(char *fmt, ...);
void error(char *fmt, ...);
void informational(char *fmt, ...);
//void add_log(char *str, int log_level);
//void print_error(int32_t error_value , const char *str);

#endif /* ENEDIS_ERROR_H_ */
