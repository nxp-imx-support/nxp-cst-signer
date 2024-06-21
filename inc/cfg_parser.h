/*
 * Copyright 2021-2024 NXP
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef CST_SIGNER_H
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define FREE(x)             do { \
                                if(x != NULL) { \
                                    free(x); \
                                    x = NULL; \
                                } \
                            } while(0)

#endif /* CST_SIGNER_H */

void cfg_parser(FILE *fp_cfgfile, char *res_val, unsigned int res_size, char *exp_key);
