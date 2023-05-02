/*
 * Copyright 2022 NXP
 *
 * SPDX-License-Identifier:     GPL-2.0-or-later
 *
 */

#ifndef CST_SIGNER_H
#define CST_SIGNER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <unistd.h>

/************************
        Command line arguments
************************/
/* Valid short command line option letters. */
const char* const short_opt = "hfdi:o:c:";

/* Valid long command line options. */
const struct option long_opt[] =
{
    {"image", required_argument,  0, 'i'},
    {"offset", required_argument,  0, 'o'},
    {"cfg-file", required_argument,  0, 'c'},
    {"debug", no_argument,  0, 'd'},
    {"fdt-debug", no_argument,  0, 'f'},
    {"help", no_argument, 0, 'h'},
    {NULL, 0, NULL, 0}
};

/* Option descriptions */
const char* desc_opt[] =
{
    "Input image to be signed",
    "(Optional) Offset to the start of image",
    "CSF configuration file",
    "(Optional) Enable debug information",
    "(Optional) FDT debug information",
    "This text",
    NULL
};

#define FREE(x)             do { \
                                if(NULL != x) { \
                                    free(x); \
                                    x = NULL; \
                                } \
                            } while(0)

#define FCLOSE(x)           do { \
                                if(NULL != x) { \
                                    fclose(x); \
                                    x = NULL; \
                                } \
                            } while(0)

#define DEBUG(fmt, ...)     do { \
                                if (1 == g_debug) { \
                                    printf("%s:%s:%d: " fmt, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__); \
                                } \
                            } while(0)

#define ASSERT(x, y)        do { \
                                if (NULL == x) { \
                                    fprintf(stderr, "ERROR: ASSERT failed at %s:%d\n", __FUNCTION__, __LINE__); \
                                    return y; \
                                } \
                            } while(0)

#define BASE_HEX                    16UL
#define FILENAME_MAX_LEN            100UL
#define SYS_CMD_LEN                 400UL

#define IV_MAX_LEN                  32
#define HASH_MAX_LEN                64
#define MAX_NUM_IMGS                8
#define MAX_NUM_OF_CONTAINER        4

#define IVT_HEADER_TAG              0xD1
#define IVT_HEADER_TAG_B0           0x87
#define IVT_HEADER_TAG_MSG          0x89


#define IMAGE_TYPE_MASK             0xF

#define CONTAINER_ALIGNMENT         0x400

#define ALIGN(x,a)                  __ALIGN_MASK((x),(__typeof__(x))(a)-1)
#define __ALIGN_MASK(x,mask)        (((x)+(mask))&~(mask))

typedef enum SOC_TYPE {
    NONE = 0,
    QX,
    QM,
    DXL,
    ULP,
} soc_type_t;

#define E_OK 0
#define E_FAILURE 1

#define ASCENDING 0
#define DESCENDING 1

/* offset of the FIT images relative to IVT offset */
#define FIT_IMAGES_OFFSET 0x2000

typedef struct {
    uint8_t tag;
    uint16_t length;
    uint8_t version;
} __attribute__((packed)) ivt_header_t;

typedef struct {
    ivt_header_t ivt_hdr;
    uint32_t entry;
    uint32_t reserved1;
    uint32_t dcd;
    uint32_t boot_data;
    uint32_t self_addr;
    uint32_t csf_addr;
    uint32_t reserved2;
} __attribute__((packed)) ivt_t;


typedef struct {
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    uint16_t srk_table_offset;
    uint16_t cert_offset;
    uint16_t blob_offset;
    uint16_t signature_offset;
    uint32_t reserved;
} __attribute__((packed)) sig_blk_hdr_t;

typedef struct {
    char type;
    char core_id;
    char hash_type;
    bool encrypted;
    uint16_t boot_flags;
} img_flags_t;

typedef struct {
    uint32_t offset;
    uint32_t size;
    uint64_t dst;
    uint64_t entry;
    uint32_t hab_flags;
    uint32_t meta;
    uint8_t hash[HASH_MAX_LEN];
    uint8_t iv[IV_MAX_LEN];
} __attribute__((packed)) boot_img_t;

typedef struct {
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    uint32_t flags;
    uint16_t sw_version;
    uint8_t fuse_version;
    uint8_t num_images;
    uint16_t sig_blk_offset;
    uint16_t reserved;
    boot_img_t img[MAX_NUM_IMGS];
    sig_blk_hdr_t sig_blk_hdr;
    uint32_t sigblk_size;
    uint32_t padding;
} __attribute__((packed)) flash_header_v3_t;

/*   Global Variables   */
static bool g_debug = 0;
static char *g_csf_cfgfilename = NULL;
extern uint32_t g_image_offset;
static char *g_cst_path = NULL;

unsigned char g_ivt_v1_mask[] = {0xFF,0xFF,0xFF,0x00};
unsigned char g_ivt_v1[] = {0xD1,0x00,0x20,0x41};

/* Function prototypes */
int copy_files(char *ifname, char *ofname);
long int get_file_size(FILE *fp, char *input_file);
unsigned char *alloc_buffer(FILE *fp, char *input_file);

#endif /* CST_SIGNER_H */
