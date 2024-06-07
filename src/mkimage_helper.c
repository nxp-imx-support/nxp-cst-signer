/*
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Description: This file inherits code from NXP delivered imx-mkimage tool.
 */

#include "mkimage_helper.h"

/** AS IS FROM SOURCE. DO NOT CHANGE **/
int get_container_size(flash_header_v3_t *phdr)
{
    uint8_t i = 0;
    uint32_t max_offset = 0, img_end;

    max_offset = phdr->length;

    for (i = 0; i < phdr->num_images; i++) {
        img_end = phdr->img[i].offset + phdr->img[i].size;
        if (img_end > max_offset)
            max_offset = img_end;
    }

    if (phdr->sig_blk_offset != 0) {
        uint16_t len = phdr->sig_blk_hdr.length;

        if (phdr->sig_blk_offset + len > max_offset)
            max_offset = phdr->sig_blk_offset + len;
    }

    return max_offset;
}
/**************************************/


int search_app_container(flash_header_v3_t *container_hdrs, int num_cntrs, flash_header_v3_t *app_container_hdr, const uint8_t *infile_buf, long int infile_size)
{
    int off[MAX_NUM_OF_CONTAINER];
    int end = 0, last = g_image_offset;

    off[0] = 0;

    for (int i = 0; i < num_cntrs; i++) {
        end = get_container_size(&container_hdrs[i]);
        if (end + off[i] > last)
            last = end + off[i];

        if ((i + 1) < num_cntrs)
            off[i + 1] = off[i] + ALIGN(container_hdrs[i].length, CONTAINER_ALIGNMENT);
    }

    /* Check app container tag at each 1KB beginning until 16KB */
    last = ALIGN(last, 0x400);
    for (int i = 0; i < 16; i++) {
        last = last + (i * 0x400);
        if (last >= infile_size)
            break;

        memcpy((void *)app_container_hdr, \
            (last + infile_buf), \
            16);

        /* check that the current container has a valid tag */
        if (app_container_hdr->tag != IVT_HEADER_TAG_B0)
            continue;

        if (app_container_hdr->num_images > MAX_NUM_IMGS) {
            fprintf(stderr, "This container includes %d images, beyond max 8 images\n", app_container_hdr->num_images);
            break;
        }

        return last;
    }

    return 0;
}
