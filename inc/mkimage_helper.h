/*
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef MKIMAGE_HELPER_H
#define MKIMAGE_HELPER_H

#ifndef CST_SIGNER_H
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define IV_MAX_LEN                  32
#define HASH_MAX_LEN                64
#define MAX_NUM_IMGS                8
#define MAX_NUM_OF_CONTAINER        4

#define CONTAINER_ALIGNMENT         0x400

#define IVT_HEADER_TAG              0xD1
#define IVT_HEADER_TAG_B0           0x87

#define ALIGN(x,a)                  __ALIGN_MASK((x),(__typeof__(x))(a)-1)
#define __ALIGN_MASK(x,mask)        (((x)+(mask))&~(mask))

extern uint32_t g_image_offset;

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

#endif /* CST_SIGNER_H */

int get_container_size(flash_header_v3_t *);

int search_app_container(flash_header_v3_t *, int, flash_header_v3_t *, const uint8_t *, long int);

#endif /* MKIMAGE_HELPER_H */
