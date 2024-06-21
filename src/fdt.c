/*
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Description: This file inherits code from NXP delivered imx-mkimage tool.
 */


#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <fdt.h>

static struct fdt_errtabent fdt_errtable[] = {
    FDT_ERRTABENT(FDT_ERR_NOTFOUND),
    FDT_ERRTABENT(FDT_ERR_EXISTS),
    FDT_ERRTABENT(FDT_ERR_NOSPACE),

    FDT_ERRTABENT(FDT_ERR_BADOFFSET),
    FDT_ERRTABENT(FDT_ERR_BADPATH),
    FDT_ERRTABENT(FDT_ERR_BADPHANDLE),
    FDT_ERRTABENT(FDT_ERR_BADSTATE),

    FDT_ERRTABENT(FDT_ERR_TRUNCATED),
    FDT_ERRTABENT(FDT_ERR_BADMAGIC),
    FDT_ERRTABENT(FDT_ERR_BADVERSION),
    FDT_ERRTABENT(FDT_ERR_BADSTRUCTURE),
    FDT_ERRTABENT(FDT_ERR_BADLAYOUT),
    FDT_ERRTABENT(FDT_ERR_INTERNAL),
    FDT_ERRTABENT(FDT_ERR_BADNCELLS),
    FDT_ERRTABENT(FDT_ERR_BADVALUE),
    FDT_ERRTABENT(FDT_ERR_BADOVERLAY),
    FDT_ERRTABENT(FDT_ERR_NOPHANDLES),
    FDT_ERRTABENT(FDT_ERR_BADFLAGS),
};
#define FDT_ERRTABSIZE    (sizeof(fdt_errtable) / sizeof(fdt_errtable[0]))

bool g_fdt_debug = 0;

const char *fdt_strerror(int errval)
{
    if (errval > 0)
        return "<valid offset/length>";
    else if (errval == 0)
        return "<no error>";
    else if (errval > -FDT_ERRTABSIZE) {
        const char *s = fdt_errtable[-errval].str;

        if (s)
            return s;
    }

    return "<unknown error>";
}

/** fdt_chk_basic() - see if basic checking of params and DT data is enabled */
static inline bool fdt_chk_basic(void)
{
    return !(FDT_ASSUME_MASK & FDT_ASSUME_SANE);
}

/** fdt_chk_version() - see if we need to handle old versions of the DT */
static inline bool fdt_chk_version(void)
{
    return !(FDT_ASSUME_MASK & FDT_ASSUME_LATEST);
}

/** fdt_chk_extra() - see if extra checking is enabled */
static inline bool fdt_chk_extra(void)
{
    return !(FDT_ASSUME_MASK & FDT_ASSUME_FRIENDLY);
}


static inline const void *fdt_offset_ptr_(const void *fdt, int offset)
{
    return (const char *)fdt + fdt_off_dt_struct(fdt) + offset;
}

const void *fdt_offset_ptr(const void *fdt, int offset, unsigned int len)
{
    unsigned absoffset = offset + fdt_off_dt_struct(fdt);

    if (fdt_chk_basic())
        if ((absoffset < offset)
            || ((absoffset + len) < absoffset)
            || (absoffset + len) > fdt_totalsize(fdt))
            return NULL;

    if (!fdt_chk_version() || fdt_version(fdt) >= 0x11)
        if (((offset + len) < offset)
            || ((offset + len) > fdt_size_dt_struct(fdt)))
            return NULL;

    return fdt_offset_ptr_(fdt, offset);
}


uint32_t fdt_next_tag(const void *fdt, int startoffset, int *nextoffset)
{
    const fdt32_t *tagp, *lenp;
    uint32_t tag;
    int offset = startoffset;
    const char *p;

    *nextoffset = -FDT_ERR_TRUNCATED;
    tagp = fdt_offset_ptr(fdt, offset, FDT_TAGSIZE);
    if (fdt_chk_basic() && !tagp)
        return FDT_END; /* premature end */
    tag = fdt32_to_cpu(*tagp);
    offset += FDT_TAGSIZE;

    *nextoffset = -FDT_ERR_BADSTRUCTURE;
    switch (tag) {
    case FDT_BEGIN_NODE:
        /* skip name */
        do {
            p = fdt_offset_ptr(fdt, offset++, 1);
        } while (p && (*p != '\0'));
        if (fdt_chk_basic() && !p)
            return FDT_END; /* premature end */
        break;

    case FDT_PROP:
        lenp = fdt_offset_ptr(fdt, offset, sizeof(*lenp));
        if (fdt_chk_basic() && !lenp)
            return FDT_END; /* premature end */
        /* skip-name offset, length and value */
        offset += sizeof(struct fdt_property) - FDT_TAGSIZE
            + fdt32_to_cpu(*lenp);
        if (fdt_chk_version() &&
            fdt_version(fdt) < 0x10 && fdt32_to_cpu(*lenp) >= 8 &&
            ((offset - fdt32_to_cpu(*lenp)) % 8) != 0)
            offset += 4;
        break;

    case FDT_END:
    case FDT_END_NODE:
    case FDT_NOP:
        break;

    default:
        return FDT_END;
    }

    if (fdt_chk_basic() &&
        !fdt_offset_ptr(fdt, startoffset, offset - startoffset))
        return FDT_END; /* premature end */

    *nextoffset = FDT_TAGALIGN(offset);
    return tag;
}

const char *fdt_get_name(const void *fdt, int nodeoffset, int *len)
{
    const struct fdt_node_header *nh = fdt_offset_ptr_(fdt, nodeoffset);
    const char *nameptr;
    int err;

    if (fdt_chk_extra() &&
        (((err = fdt_ro_probe_(fdt)) < 0)
         || ((err = fdt_check_node_offset_(fdt, nodeoffset)) < 0)))
        goto fail;

    nameptr = nh->name;

    if (fdt_chk_version() && fdt_version(fdt) < 0x10) {
        /*
         * For old FDT versions, match the naming conventions of V16:
         * give only the leaf name (after all /). The actual tree
         * contents are loosely checked.
         */
        const char *leaf;
        leaf = strrchr(nameptr, '/');
        if (leaf == NULL) {
            err = -FDT_ERR_BADSTRUCTURE;
            goto fail;
        }
        nameptr = leaf+1;
    }

    if (len)
        *len = strlen(nameptr);

    return nameptr;

 fail:
    if (len)
        *len = err;
    return NULL;
}


static int fdt_nodename_eq_(const void *fdt, int offset,
                const char *s, int len)
{
    int olen;
    const char *p = fdt_get_name(fdt, offset, &olen);

    if (!p || (fdt_chk_extra() && olen < len))
        /* short match */
        return 0;

    if (memcmp(p, s, len) != 0)
        return 0;

    if (p[len] == '\0')
        return 1;
    else if (!memchr(s, '@', len) && (p[len] == '@'))
        return 1;
    else
        return 0;
}

static int nextprop_(const void *fdt, int offset)
{
    uint32_t tag;
    int nextoffset;

    do {
        tag = fdt_next_tag(fdt, offset, &nextoffset);

        switch (tag) {
        case FDT_END:
            if (nextoffset >= 0)
                return -FDT_ERR_BADSTRUCTURE;
            else
                return nextoffset;

        case FDT_PROP:
            return offset;
        }
        offset = nextoffset;
    } while (tag == FDT_NOP);

    return -FDT_ERR_NOTFOUND;
}

int fdt_check_node_offset_(const void *fdt, int offset)
{
    if ((offset < 0) || (offset % FDT_TAGSIZE)
        || (fdt_next_tag(fdt, offset, &offset) != FDT_BEGIN_NODE))
        return -FDT_ERR_BADOFFSET;

    return offset;
}

int fdt_check_prop_offset_(const void *fdt, int offset)
{
    if ((offset < 0) || (offset % FDT_TAGSIZE)
        || (fdt_next_tag(fdt, offset, &offset) != FDT_PROP))
        return -FDT_ERR_BADOFFSET;

    return offset;
}


int fdt_first_property_offset(const void *fdt, int nodeoffset)
{
    int offset;

    if ((offset = fdt_check_node_offset_(fdt, nodeoffset)) < 0)
        return offset;

    return nextprop_(fdt, offset);
}

int fdt_next_property_offset(const void *fdt, int offset)
{
    if ((offset = fdt_check_prop_offset_(fdt, offset)) < 0)
        return offset;

    return nextprop_(fdt, offset);
}

static const struct fdt_property *fdt_get_property_by_offset_(const void *fdt,
                                      int offset,
                                      int *lenp)
{
    int err;
    const struct fdt_property *prop;

    if (fdt_chk_basic() && (err = fdt_check_prop_offset_(fdt, offset)) < 0) {
        if (lenp)
            *lenp = err;
        return NULL;
    }

    prop = fdt_offset_ptr_(fdt, offset);

    if (lenp)
        *lenp = fdt32_to_cpu(prop->len);

    return prop;
}

const char *fdt_get_string(const void *fdt, int stroffset, int *lenp)
{
    int32_t totalsize;
    uint32_t absoffset;
    size_t len;
    int err;
    const char *s, *n;

    if (!fdt_chk_extra()) {
        s = (const char *)fdt + fdt_off_dt_strings(fdt) + stroffset;

        if (lenp)
            *lenp = strlen(s);
        return s;
    }
    totalsize = fdt_ro_probe_(fdt);
    err = totalsize;
    if (totalsize < 0)
        goto fail;

    err = -FDT_ERR_BADOFFSET;
    absoffset = stroffset + fdt_off_dt_strings(fdt);
    if (absoffset >= totalsize)
        goto fail;
    len = totalsize - absoffset;

    if (fdt_magic(fdt) == FDT_MAGIC) {
        if (stroffset < 0)
            goto fail;
        if (!fdt_chk_version() || fdt_version(fdt) >= 17) {
            if (stroffset >= fdt_size_dt_strings(fdt))
                goto fail;
            if ((fdt_size_dt_strings(fdt) - stroffset) < len)
                len = fdt_size_dt_strings(fdt) - stroffset;
        }
    } else if (fdt_magic(fdt) == FDT_SW_MAGIC) {
        if ((stroffset >= 0)
            || (stroffset < -fdt_size_dt_strings(fdt)))
            goto fail;
        if ((-stroffset) < len)
            len = -stroffset;
    } else {
        err = -FDT_ERR_INTERNAL;
        goto fail;
    }

    s = (const char *)fdt + absoffset;
    n = memchr(s, '\0', len);
    if (!n) {
        /* missing terminating NULL */
        err = -FDT_ERR_TRUNCATED;
        goto fail;
    }

    if (lenp)
        *lenp = n - s;
    return s;

fail:
    if (lenp)
        *lenp = err;
    return NULL;
}


static int fdt_string_eq_(const void *fdt, int stroffset,
              const char *s, int len)
{
    int slen;
    const char *p = fdt_get_string(fdt, stroffset, &slen);

    return p && (slen == len) && (memcmp(p, s, len) == 0);
}

static const struct fdt_property *fdt_get_property_namelen_(const void *fdt,
                                    int offset,
                                    const char *name,
                                    int namelen,
                                int *lenp,
                                int *poffset)
{
    for (offset = fdt_first_property_offset(fdt, offset);
         (offset >= 0);
         (offset = fdt_next_property_offset(fdt, offset))) {
        const struct fdt_property *prop;

        prop = fdt_get_property_by_offset_(fdt, offset, lenp);
        if (fdt_chk_extra() && !prop) {
            offset = -FDT_ERR_INTERNAL;
            break;
        }
        if (fdt_string_eq_(fdt, fdt32_to_cpu(prop->nameoff),
                   name, namelen)) {
            if (poffset)
                *poffset = offset;
            return prop;
        }
    }

    if (lenp)
        *lenp = offset;
    return NULL;
}

const void *fdt_getprop_namelen(const void *fdt, int nodeoffset,
                const char *name, int namelen, int *lenp)
{
    int poffset;
    const struct fdt_property *prop;

    prop = fdt_get_property_namelen_(fdt, nodeoffset, name, namelen, lenp,
                     &poffset);
    if (!prop)
        return NULL;

    /* Handle realignment */
    if (fdt_chk_version() && fdt_version(fdt) < 0x10 &&
        (poffset + sizeof(*prop)) % 8 && fdt32_to_cpu(prop->len) >= 8)
        return prop->data + 4;
    return prop->data;
}

const char *fdt_get_alias_namelen(const void *fdt,
                  const char *name, int namelen)
{
    int aliasoffset;

    aliasoffset = fdt_path_offset(fdt, "/aliases");
    if (aliasoffset < 0)
        return NULL;

    return fdt_getprop_namelen(fdt, aliasoffset, name, namelen, NULL);
}


/*
 * Minimal sanity check for a read-only tree. fdt_ro_probe_() checks
 * that the given buffer contains what appears to be a flattened
 * device tree with sane information in its header.
 */
int32_t fdt_ro_probe_(const void *fdt)
{
    uint32_t totalsize = fdt_totalsize(fdt);

    if (fdt_magic(fdt) == FDT_MAGIC) {
        /* Complete tree */
        if (fdt_chk_version()) {
            if (fdt_version(fdt) < FDT_FIRST_SUPPORTED_VERSION)
                return -FDT_ERR_BADVERSION;
            if (fdt_last_comp_version(fdt) >
                    FDT_LAST_SUPPORTED_VERSION)
                return -FDT_ERR_BADVERSION;
        }
    } else if (fdt_magic(fdt) == FDT_SW_MAGIC) {
        /* Unfinished sequential-write blob */
        if (fdt_size_dt_struct(fdt) == 0)
            return -FDT_ERR_BADSTATE;
    } else {
        return -FDT_ERR_BADMAGIC;
    }

    if (totalsize < INT32_MAX)
        return totalsize;
    else
        return -FDT_ERR_TRUNCATED;
}

#define FDT_RO_PROBE(fdt)                    \
    {                            \
        int totalsize_;                    \
        if (fdt_chk_basic()) {                \
            totalsize_ = fdt_ro_probe_(fdt);    \
            if (totalsize_ < 0)            \
                return totalsize_;        \
        }                        \
    }

int fdt_next_node(const void *fdt, int offset, int *depth)
{
    int nextoffset = 0;
    uint32_t tag;

    if (offset >= 0)
        if ((nextoffset = fdt_check_node_offset_(fdt, offset)) < 0)
            return nextoffset;

    do {
        offset = nextoffset;
        tag = fdt_next_tag(fdt, offset, &nextoffset);

        switch (tag) {
        case FDT_PROP:
        case FDT_NOP:
            break;

        case FDT_BEGIN_NODE:
            if (depth)
                (*depth)++;
            break;

        case FDT_END_NODE:
            if (depth && ((--(*depth)) < 0))
                return nextoffset;
            break;

        case FDT_END:
            if ((nextoffset >= 0)
                || ((nextoffset == -FDT_ERR_TRUNCATED) && !depth))
                return -FDT_ERR_NOTFOUND;
            else
                return nextoffset;
        }
    } while (tag != FDT_BEGIN_NODE);

    return offset;
}

int fdt_subnode_offset_namelen(const void *fdt, int offset,
                   const char *name, int namelen)
{
    int depth;

    FDT_RO_PROBE(fdt);

    for (depth = 0;
         (offset >= 0) && (depth >= 0);
         offset = fdt_next_node(fdt, offset, &depth))
        if ((depth == 1)
            && fdt_nodename_eq_(fdt, offset, name, namelen))
            return offset;

    if (depth < 0)
        return -FDT_ERR_NOTFOUND;
    return offset; /* error */
}


int fdt_path_offset_namelen(const void *fdt, const char *path, int namelen)
{
    const char *end = path + namelen;
    const char *p = path;
    int offset = 0;

    FDT_RO_PROBE(fdt);

    /* see if we have an alias */
    if (*path != '/') {
        const char *q = memchr(path, '/', end - p);

        if (!q)
            q = end;

        p = fdt_get_alias_namelen(fdt, p, q - p);
        if (!p)
            return -FDT_ERR_BADPATH;
        offset = fdt_path_offset(fdt, p);

        p = q;
    }

    while (p < end) {
        const char *q;

        while (*p == '/') {
            p++;
            if (p == end)
                return offset;
        }
        q = memchr(p, '/', end - p);
        if (! q)
            q = end;

        offset = fdt_subnode_offset_namelen(fdt, offset, p, q-p);
        if (offset < 0)
            return offset;

        p = q;
    }

    return offset;
}


int fdt_path_offset(const void *fdt, const char *path)
{
    return fdt_path_offset_namelen(fdt, path, strlen(path));
}

static inline const char *fit_get_name(const void *fit_hdr,
        int noffset, int *len)
{
    return fdt_get_name(fit_hdr, noffset, len);
}

const void *fdt_getprop(const void *fdt, int nodeoffset,
            const char *name, int *lenp)
{
    return fdt_getprop_namelen(fdt, nodeoffset, name, strlen(name), lenp);
}



/**
 * Get 'data-position' property from a given image node.
 *
 * @fit: pointer to the FIT image header
 * @noffset: component image node offset
 * @data_position: holds the data-position property
 *
 * returns:
 *     0, on success
 *     -ENOENT if the property could not be found
 */
int fit_image_get_data_position(const void *fit, int noffset,
                int *data_position)
{
    const fdt32_t *val;

    val = fdt_getprop(fit, noffset, FIT_DATA_POSITION_PROP, NULL);
    if (!val)
        return -ENOENT;

    *data_position = fdt32_to_cpu(*val);

    return 0;
}

/**
 * Get 'data-offset' property from a given image node.
 *
 * @fit: pointer to the FIT image header
 * @noffset: component image node offset
 * @data_offset: holds the data-offset property
 *
 * returns:
 *     0, on success
 *     -ENOENT if the property could not be found
 */
int fit_image_get_data_offset(const void *fit, int noffset, int *data_offset)
{
    const fdt32_t *val;

    val = fdt_getprop(fit, noffset, FIT_DATA_OFFSET_PROP, NULL);
    if (!val)
        return -ENOENT;

    *data_offset = fdt32_to_cpu(*val);

    return 0;
}

/**
 * Get 'data-size' property from a given image node.
 *
 * @fit: pointer to the FIT image header
 * @noffset: component image node offset
 * @data_size: holds the data-size property
 *
 * returns:
 *     0, on success
 *     -ENOENT if the property could not be found
 */
int fit_image_get_data_size(const void *fit, int noffset, int *data_size)
{
    const fdt32_t *val;

    val = fdt_getprop(fit, noffset, FIT_DATA_SIZE_PROP, NULL);
    if (!val)
        return -ENOENT;

    *data_size = fdt32_to_cpu(*val);

    return 0;
}

static void fit_get_debug(const void *fit, int noffset,
        char *prop_name, int err)
{
    if (g_fdt_debug) {
        printf("Can't get '%s' property from FIT 0x%08lx, node: offset %d, name %s (%s)\n",
               prop_name, (unsigned long)fit, noffset,
               fit_get_name(fit, noffset, NULL),
               fdt_strerror(err));
    }
}

/**
 * fit_image_get_data - get data property and its size for a given component image node
 * @fit: pointer to the FIT format image header
 * @noffset: component image node offset
 * @data: double pointer to void, will hold data property's data address
 * @size: pointer to size_t, will hold data property's data size
 *
 * fit_image_get_data() finds data property in a given component image node.
 * If the property is found its data start address and size are returned to
 * the caller.
 *
 * returns:
 *     0, on success
 *     -1, on failure
 */
int fit_image_get_data(const void *fit, int noffset,
        const void **data, size_t *size)
{
    int len;

    *data = fdt_getprop(fit, noffset, FIT_DATA_PROP, &len);
    if (*data == NULL) {
        fit_get_debug(fit, noffset, FIT_DATA_PROP, len);
        *size = 0;
        return -1;
    }

    *size = len;
    return 0;
}


/**
 * fit_image_get_data_and_size - get data and its size including
 *                 both embedded and external data
 * @fit: pointer to the FIT format image header
 * @noffset: component image node offset
 * @data: double pointer to void, will hold data property's data address
 * @size: pointer to size_t, will hold data property's data size
 *
 * fit_image_get_data_and_size() finds data and its size including
 * both embedded and external data. If the property is found
 * its data start address and size are returned to the caller.
 *
 * returns:
 *     0, on success
 *     otherwise, on failure
 */
int fit_image_get_data_and_size(const void *fit, int noffset,
                const void **data, size_t *size)
{
    bool external_data = false;
    int offset;
    int len;
    int ret;

    if (!fit_image_get_data_position(fit, noffset, &offset)) {
        external_data = true;
    } else if (!fit_image_get_data_offset(fit, noffset, &offset)) {
        external_data = true;
        /*
         * For FIT with external data, figure out where
         * the external images start. This is the base
         * for the data-offset properties in each image.
         */
        offset += ((fdt_totalsize(fit) + 3) & ~3);
    }

    if (external_data) {
        //printf("External Data\n");
        ret = fit_image_get_data_size(fit, noffset, &len);
        if (!ret) {
            *data = fit + offset;
            *size = len;
        }
    } else {
        ret = fit_image_get_data(fit, noffset, data, size);
    }

    return ret;
}

static int fit_image_get_address(const void *fit, int noffset, char *name,
              unsigned long *load)
{
    int len, cell_len;
    const fdt32_t *cell;
    uint64_t load64 = 0;

    cell = fdt_getprop(fit, noffset, name, &len);
    if (cell == NULL) {
        fit_get_debug(fit, noffset, name, len);
        return -1;
    }

    if (len > sizeof(unsigned long)) {
        if (g_fdt_debug) {
            printf("Unsupported %s address size\n", name);
        }
        return -1;
    }

    cell_len = len >> 2;
    /* Use load64 to avoid compiling warning for 32-bit target */
    while (cell_len--) {
        load64 = (load64 << 32) | be32_to_cpu(*cell);
        cell++;
    }
    *load = (unsigned long)load64;

    return 0;
}

/**
 * fit_image_get_load() - get load addr property for given component image node
 * @fit: pointer to the FIT format image header
 * @noffset: component image node offset
 * @load: pointer to the uint32_t, will hold load address
 *
 * fit_image_get_load() finds load address property in a given component
 * image node. If the property is found, its value is returned to the caller.
 *
 * returns:
 *     0, on success
 *     -1, on failure
 */
int fit_image_get_load(const void *fit, int noffset, unsigned long *load)
{
    return fit_image_get_address(fit, noffset, FIT_LOAD_PROP, load);
}



int parse_fdt(fdt_header_t *fit, image_block_t *images)
{
    int images_noffset;
    int noffset;
    int ndepth;
    int count = 0;
    int ret;
    const char *p;

    if (!images)
        return -1;

    p = "   ";
    /* Find images parent node offset */
    images_noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
    if (images_noffset < 0) {
        if (g_fdt_debug) {
            printf("Can't find images parent node '%s' (%s)\n",
                FIT_IMAGES_PATH, fdt_strerror(images_noffset));
        }
        return -1;
    }

    /* Process its subnodes, print out component images details */
    for (ndepth = 0, count = 0,
        noffset = fdt_next_node(fit, images_noffset, &ndepth);
         (noffset >= 0) && (ndepth > 0);
         noffset = fdt_next_node(fit, noffset, &ndepth)) {
        if (ndepth == 1) {
            const void *data;
            images->valid = true;

            if (g_fdt_debug) {
                /*
                 * Direct child node of the images parent node,
                 * i.e. component image node.
                 */
                printf("%s Image %u (%s)\n", p, count++,
                       fit_get_name(fit, noffset, NULL));
            }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
            ret = fit_image_get_data_and_size(fit, noffset, &data,
                              &images->size);
#pragma GCC diagnostic pop
            if (g_fdt_debug) {
                if(ret)
                    printf("Could not get image size\n");
            }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
            ret = fit_image_get_load(fit, noffset,
                         &images->load_addr);
#pragma GCC diagnostic pop
            if (g_fdt_debug) {
                if(ret)
                    printf("Could not get image address\n");
            }
            images++;
        }
    }
    return 0;
}
