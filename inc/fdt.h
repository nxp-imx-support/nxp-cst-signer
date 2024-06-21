/*
 * libfdt - Flat Device Tree manipulation
 * Copyright (C) 2006 David Gibson, IBM Corporation.
 * Copyright 2012 Kim Phillips, Freescale Semiconductor.
 * Copyright 2022-2024 NXP
 * 
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef FDT_H
#define FDT_H

typedef struct {
    unsigned long load_addr;
    unsigned long offset;
    size_t size;
    bool valid;
} __attribute__((packed)) image_block_t;


typedef struct {
    uint32_t magic;             /* magic word FDT_MAGIC */
    uint32_t totalsize;         /* total size of DT block */
    uint32_t off_dt_struct;         /* offset to structure */
    uint32_t off_dt_strings;         /* offset to strings */
    uint32_t off_mem_rsvmap;         /* offset to memory reserve map */
    uint32_t version;         /* format version */
    uint32_t last_comp_version;     /* last compatible version */

    /* version 2 fields below */
    uint32_t boot_cpuid_phys;     /* Which physical CPU id we're
                        booting on */
    /* version 3 fields below */
    uint32_t size_dt_strings;     /* size of the strings block */

    /* version 17 fields below */
    uint32_t size_dt_struct;         /* size of the structure block */
} __attribute__((packed)) fdt_header_t;

struct fdt_reserve_entry {
    uint64_t address;
    uint64_t size;
};

struct fdt_node_header {
    uint32_t tag;
    char name[0];
};

struct fdt_property {
    uint32_t tag;
    uint32_t len;
    uint32_t nameoff;
    char data[0];
};

#define FDT_MAGIC    0xd00dfeed    /* 4: version, 4: total size */

#define FIT_IMAGES_PATH        "/images"
#define FIT_CONFS_PATH        "/configurations"

/* hash/signature/key node */
#define FIT_HASH_NODENAME    "hash"
#define FIT_ALGO_PROP        "algo"
#define FIT_VALUE_PROP        "value"
#define FIT_IGNORE_PROP        "uboot-ignore"
#define FIT_SIG_NODENAME    "signature"
#define FIT_KEY_REQUIRED    "required"
#define FIT_KEY_HINT        "key-name-hint"

/* cipher node */
#define FIT_CIPHER_NODENAME    "cipher"
#define FIT_ALGO_PROP        "algo"

/* image node */
#define FIT_DATA_PROP        "data"
#define FIT_DATA_POSITION_PROP    "data-position"
#define FIT_DATA_OFFSET_PROP    "data-offset"
#define FIT_DATA_SIZE_PROP    "data-size"
#define FIT_TIMESTAMP_PROP    "timestamp"
#define FIT_DESC_PROP        "description"
#define FIT_ARCH_PROP        "arch"
#define FIT_TYPE_PROP        "type"
#define FIT_OS_PROP        "os"
#define FIT_COMP_PROP        "compression"
#define FIT_ENTRY_PROP        "entry"
#define FIT_LOAD_PROP        "load"

/* configuration node */
#define FIT_KERNEL_PROP        "kernel"
#define FIT_RAMDISK_PROP    "ramdisk"
#define FIT_FDT_PROP        "fdt"
#define FIT_LOADABLE_PROP    "loadables"
#define FIT_DEFAULT_PROP    "default"
#define FIT_SETUP_PROP        "setup"
#define FIT_FPGA_PROP        "fpga"
#define FIT_FIRMWARE_PROP    "firmware"
#define FIT_STANDALONE_PROP    "standalone"

#define FDT_FIRST_SUPPORTED_VERSION    0x02
#define FDT_LAST_SUPPORTED_VERSION    0x11

/* Error codes: informative error codes */
#define FDT_ERR_NOTFOUND    1
    /* FDT_ERR_NOTFOUND: The requested node or property does not exist */
#define FDT_ERR_EXISTS        2
    /* FDT_ERR_EXISTS: Attempted to create a node or property which
     * already exists */
#define FDT_ERR_NOSPACE        3
    /* FDT_ERR_NOSPACE: Operation needed to expand the device
     * tree, but its buffer did not have sufficient space to
     * contain the expanded tree. Use fdt_open_into() to move the
     * device tree to a buffer with more space. */

/* Error codes: codes for bad parameters */
#define FDT_ERR_BADOFFSET    4
    /* FDT_ERR_BADOFFSET: Function was passed a structure block
     * offset which is out-of-bounds, or which points to an
     * unsuitable part of the structure for the operation. */
#define FDT_ERR_BADPATH        5
    /* FDT_ERR_BADPATH: Function was passed a badly formatted path
     * (e.g. missing a leading / for a function which requires an
     * absolute path) */
#define FDT_ERR_BADPHANDLE    6
    /* FDT_ERR_BADPHANDLE: Function was passed an invalid phandle.
     * This can be caused either by an invalid phandle property
     * length, or the phandle value was either 0 or -1, which are
     * not permitted. */
#define FDT_ERR_BADSTATE    7
    /* FDT_ERR_BADSTATE: Function was passed an incomplete device
     * tree created by the sequential-write functions, which is
     * not sufficiently complete for the requested operation. */

/* Error codes: codes for bad device tree blobs */
#define FDT_ERR_TRUNCATED    8
    /* FDT_ERR_TRUNCATED: FDT or a sub-block is improperly
     * terminated (overflows, goes outside allowed bounds, or
     * isn't properly terminated).  */
#define FDT_ERR_BADMAGIC    9
    /* FDT_ERR_BADMAGIC: Given "device tree" appears not to be a
     * device tree at all - it is missing the flattened device
     * tree magic number. */
#define FDT_ERR_BADVERSION    10
    /* FDT_ERR_BADVERSION: Given device tree has a version which
     * can't be handled by the requested operation.  For
     * read-write functions, this may mean that fdt_open_into() is
     * required to convert the tree to the expected version. */
#define FDT_ERR_BADSTRUCTURE    11
    /* FDT_ERR_BADSTRUCTURE: Given device tree has a corrupt
     * structure block or other serious error (e.g. misnested
     * nodes, or subnodes preceding properties). */
#define FDT_ERR_BADLAYOUT    12
    /* FDT_ERR_BADLAYOUT: For read-write functions, the given
     * device tree has it's sub-blocks in an order that the
     * function can't handle (memory reserve map, then structure,
     * then strings).  Use fdt_open_into() to reorganize the tree
     * into a form suitable for the read-write operations. */

/* "Can't happen" error indicating a bug in libfdt */
#define FDT_ERR_INTERNAL    13
    /* FDT_ERR_INTERNAL: libfdt has failed an internal assertion.
     * Should never be returned, if it is, it indicates a bug in
     * libfdt itself. */

/* Errors in device tree content */
#define FDT_ERR_BADNCELLS    14
    /* FDT_ERR_BADNCELLS: Device tree has a #address-cells, #size-cells
     * or similar property with a bad format or value */

#define FDT_ERR_BADVALUE    15
    /* FDT_ERR_BADVALUE: Device tree has a property with an unexpected
     * value. For example: a property expected to contain a string list
     * is not NUL-terminated within the length of its value. */

#define FDT_ERR_BADOVERLAY    16
    /* FDT_ERR_BADOVERLAY: The device tree overlay, while
     * correctly structured, cannot be applied due to some
     * unexpected or missing value, property or node. */

#define FDT_ERR_NOPHANDLES    17
    /* FDT_ERR_NOPHANDLES: The device tree doesn't have any
     * phandle available anymore without causing an overflow */

#define FDT_ERR_BADFLAGS    18
    /* FDT_ERR_BADFLAGS: The function was passed a flags field that
     * contains invalid flags or an invalid combination of flags. */

#define FDT_ERR_MAX        18

#define FDT_SW_MAGIC        (~FDT_MAGIC)

//#define INT32_MAX 0x7fffffff

#define be32_to_cpu(x) \
    ((uint32_t)( \
        (((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) | \
        (((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) | \
        (((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) | \
        (((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24) ))

#define cpu_to_be32(x) be32_to_cpu(x)

#define fdt32_to_cpu(x) be32_to_cpu(x)
#define cpu_to_fdt32(x) cpu_to_be32(x)

typedef uint16_t fdt16_t;
typedef uint32_t fdt32_t;
typedef uint64_t fdt64_t;

#define NUM_IMGS 0x5

#define FDT_TAGSIZE    sizeof(fdt32_t)

#define FDT_BEGIN_NODE    0x1        /* Start node: full name */
#define FDT_END_NODE    0x2        /* End node */
#define FDT_PROP    0x3        /* Property: name off,
                       size, content */
#define FDT_NOP        0x4        /* nop */
#define FDT_END        0x9

#define FDT_V1_SIZE    (7*sizeof(fdt32_t))
#define FDT_V2_SIZE    (FDT_V1_SIZE + sizeof(fdt32_t))
#define FDT_V3_SIZE    (FDT_V2_SIZE + sizeof(fdt32_t))
#define FDT_V16_SIZE    FDT_V3_SIZE
#define FDT_V17_SIZE    (FDT_V16_SIZE + sizeof(fdt32_t))


/**********************************************************************/
#define fdt_get_header(fdt, field) \
    (fdt32_to_cpu(((fdt_header_t *)(fdt))->field))
#define fdt_magic(fdt)            (fdt_get_header(fdt, magic))
#define fdt_totalsize(fdt)        (fdt_get_header(fdt, totalsize))
#define fdt_off_dt_struct(fdt)        (fdt_get_header(fdt, off_dt_struct))
#define fdt_off_dt_strings(fdt)        (fdt_get_header(fdt, off_dt_strings))
#define fdt_off_mem_rsvmap(fdt)        (fdt_get_header(fdt, off_mem_rsvmap))
#define fdt_version(fdt)        (fdt_get_header(fdt, version))
#define fdt_last_comp_version(fdt)    (fdt_get_header(fdt, last_comp_version))
#define fdt_boot_cpuid_phys(fdt)    (fdt_get_header(fdt, boot_cpuid_phys))
#define fdt_size_dt_strings(fdt)    (fdt_get_header(fdt, size_dt_strings))
#define fdt_size_dt_struct(fdt)        (fdt_get_header(fdt, size_dt_struct))

#define FDT_ALIGN(x, a)        (((x) + (a) - 1) & ~((a) - 1))
#define FDT_TAGALIGN(x)        (FDT_ALIGN((x), FDT_TAGSIZE))

/**********************************************************************/
/* Checking controls                                                  */
/**********************************************************************/

#ifndef FDT_ASSUME_MASK
#define FDT_ASSUME_MASK 0
#endif

/*
 * Defines assumptions which can be enabled. Each of these can be enabled
 * individually. For maximum saftey, don't enable any assumptions!
 *
 * For minimal code size and no safety, use FDT_ASSUME_PERFECT at your own risk.
 * You should have another method of validating the device tree, such as a
 * signature or hash check before using libfdt.
 *
 * For situations where security is not a concern it may be safe to enable
 * FDT_ASSUME_FRIENDLY.
 */
enum {
    /*
     * This does essentially no checks. Only the latest device-tree
     * version is correctly handled. Incosistencies or errors in the device
     * tree may cause undefined behaviour or crashes.
     *
     * If an error occurs when modifying the tree it may leave the tree in
     * an intermediate (but valid) state. As an example, adding a property
     * where there is insufficient space may result in the property name
     * being added to the string table even though the property itself is
     * not added to the struct section.
     *
     * Only use this if you have a fully validated device tree with
     * the latest supported version and wish to minimise code size.
     */
    FDT_ASSUME_PERFECT    = 0xff,

    /*
     * This assumes that the device tree is sane. i.e. header metadata
     * and basic hierarchy are correct.
     *
     * These checks will be sufficient if you have a valid device tree with
     * no internal inconsistencies. With this assumption, libfdt will
     * generally not return -FDT_ERR_INTERNAL, -FDT_ERR_BADLAYOUT, etc.
     */
    FDT_ASSUME_SANE        = 1 << 0,

    /*
     * This disables checks for device-tree version and removes all code
     * which handles older versions.
     *
     * Only enable this if you know you have a device tree with the latest
     * version.
     */
    FDT_ASSUME_LATEST    = 1 << 1,

    /*
     * This disables any extensive checking of parameters and the device
     * tree, making various assumptions about correctness. Normal device
     * trees produced by libfdt and the compiler should be handled safely.
     * Malicious device trees and complete garbage may cause libfdt to
     * behave badly or crash.
     */
    FDT_ASSUME_FRIENDLY    = 1 << 2,
};

struct fdt_errtabent {
    const char *str;
};

#define FDT_ERRTABENT(val) \
    [(val)] = { .str = #val, }

extern bool g_fdt_debug;
int fdt_path_offset(const void *fdt, const char *path);
const void *fdt_getprop_namelen(const void *fdt, int nodeoffset,
                const char *name, int namelen, int *lenp);
const char *fdt_get_alias_namelen(const void *fdt,
                  const char *name, int namelen);
int parse_fdt(fdt_header_t *fit, image_block_t *images);
int32_t fdt_ro_probe_(const void *fdt);
int fdt_path_offset_namelen(const void *fdt, const char *path, int namelen);
int fdt_path_offset(const void *fdt, const char *path);

int fdt_check_node_offset_(const void *fdt, int offset);
int fdt_check_prop_offset_(const void *fdt, int offset);
int fdt_first_property_offset(const void *fdt, int nodeoffset);
uint32_t fdt_next_tag(const void *fdt, int startoffset, int *nextoffset);
const void *fdt_offset_ptr(const void *fdt, int offset, unsigned int len);
const char *fdt_get_string(const void *fdt, int stroffset, int *lenp);
const char *fdt_get_name(const void *fdt, int nodeoffset, int *len);

#endif
