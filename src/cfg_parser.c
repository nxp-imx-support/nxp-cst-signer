/*
 * Copyright 2021-2024 NXP
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <cfg_parser.h>

#define DELIMITER       "="

/*
 * @brief       Get value of the corresponding key in the configuration file
 *
 * @param[in]   line    : Line being parsed in the file
 *              exp_key : Expected key in the configuration
 *
 * @retval      Success : Pointer to the value
 */
char *get_value(char *line, const char *exp_key)
{
    char *key = NULL;
    if (NULL == line || NULL == exp_key) {
        fprintf(stderr, "ERROR: Invalid inputs to parser");
        return NULL;
    }

    key = strtok(line, DELIMITER);
    if (NULL != key && !(strncmp(key, exp_key, strlen(exp_key)))) {
        return &line[strlen(key) + 1];
    }
    return NULL;
}

/*
 * @brief       Parse an input configuration file
 *
 * @param[in]   fp_cfgfile  : Input configuration file
 *              exp_key     : Expected key
 *              res_size    : Size of result value
 * @param[out]  res_val     : Result value
 *
 */
void cfg_parser(FILE *fp_cfgfile, char *res_val, unsigned int res_size, char *exp_key)
{
    char *line_buf = NULL;
    size_t length = 0;
    ssize_t read_len = 0;
    char *res = NULL;

    /* Clear the result value */
    memset(res_val, 0, res_size);

    while(-1 != (read_len = getline(&line_buf, &length, fp_cfgfile))) {
        /* Ignore comments & empty lines */
        if (!(strncmp(line_buf, "#", 1)) || \
            !(strncmp(line_buf, "//", 2)) || \
            ('\0' == line_buf[0]))
            continue;
        /* Get value of the corresponding key */
        res = get_value(line_buf, exp_key);
        if (NULL != res) {
            /* Copy until the new line character */
            strncpy(res_val, res, strlen(res) - 1);
            break;
        }
    }

    FREE(line_buf);
}
