/*
 * Copyright 2022 NXP
 *
 * SPDX-License-Identifier:     GPL-2.0+
 *
 */

#include "cst_signer.h"
#include "cfg_parser.h"
#include "mkimage_helper.h"

#define RSIZE   256

uint32_t g_image_offset = 0;

typedef struct {
    int cntr_num;
    uint32_t cntr_offset;
    uint32_t sig_offset;
} __attribute__((packed)) csf_params_t;

/*
 * @brief       Common function to call CST to sign the generated CSF file
 *
 * @param[in]   ifname  : Input CSF filename
 * @param[out]  ofname  : Output signed filename
 *
 * @retval      -1      : Failure
 *               0      : Success
 */
int sign_csf(char *ifname, char *ofname)
{
    ASSERT(ifname, -1);
    ASSERT(ofname, -1);

    char sys_cmd[SYS_CMD_LEN] = {0};

    /* Checking if processor is available */
    if (!(system(NULL))) {
        fprintf(stderr, "ERROR: Command processor is not available. Exiting.\n");
        return -1;
    }
#if defined(__linux__)
    if (0 > (snprintf(sys_cmd, SYS_CMD_LEN, "%s/linux64/bin/cst ", g_cst_path))) {
        fprintf(stderr, "ERROR: System command build unsuccessful. Exiting.\n");
        return -1;
    }
#elif defined(_WIN32) || defined(_WIN64)
    if (0 > (snprintf(sys_cmd, SYS_CMD_LEN, "%s/mingw32/bin/cst.exe ", g_cst_path)) {
        fprintf(stderr, "ERROR: System command build unsuccessful. Exiting.\n");
        return -1;
    }
#else
    #error Unsupported OS
#endif
    
    if (0 > (snprintf(sys_cmd + strlen(sys_cmd), (SYS_CMD_LEN - strlen(sys_cmd)), "--i %s --o %s", ifname, ofname))) {
        fprintf(stderr, "ERROR: System command build unsuccessful. Exiting.\n");
        return -1;
    }

    /* Execute command */
    printf("Executing command: %s\n", sys_cmd);
    return(system(sys_cmd));
}

/*
 * @brief       Clone input file to output file
 *
 * @param[in]   ifname  : Input file
 * @param[out]  ofname  : Output file
 *
 * @retval      -1      : Success
 *               0      : Failure
 */
int copy_files(char *ifname, char *ofname)
{
    ASSERT(ifname, -1);
    ASSERT(ofname, -1);

    char ch;
    long int ifname_size = 0;
    unsigned char *buf = NULL;
    size_t result_size = 0;
    
    /* Open input file */
    FILE *fp_ifname = fopen(ifname, "rb");
    if (NULL == fp_ifname) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", ifname, strerror(errno));
        goto err;
    }
    
    ifname_size = get_file_size(fp_ifname, ifname);
    if (0 > ifname_size) {
        fprintf(stderr, "ERROR: Invalid file size %ld of file: %s\n", ifname_size, ifname);
        goto err;
    }

    /* Open output file */
    FILE *fp_ofname = fopen(ofname, "wb");
    if (NULL == fp_ofname) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", ofname, strerror(errno));
        goto err;
    }

    /* Allocate memory to the buffer */
    buf = malloc(ifname_size);
    if (NULL == buf || 0 == buf) {
        fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
        goto err;
    }

    /* Copy input file to output file */
    result_size = fread(buf, 1, ifname_size, fp_ifname);
    if (result_size != ifname_size) {
        fprintf(stderr, "ERROR: File read error; %s\n", strerror(errno));
        goto err;
    } else {
        result_size = fwrite(buf, 1, ifname_size, fp_ofname);
        if (result_size != ifname_size) {
            fprintf(stderr, "ERROR: File write error; %s\n", strerror(errno));
            goto err;
        }
    }

    /* Cleanup */
    FREE(buf);
    FCLOSE(fp_ifname);
    FCLOSE(fp_ofname);
    return 0;

err:
    FREE(buf);
    FCLOSE(fp_ifname);
    FCLOSE(fp_ofname);
    return -1;

}

/*
 * @brief       Create CSF file for IVT type v1
 *
 * @param[in]   csf_filename    : CSF filename to be populated
 *              ifname          : Input filename
 *              csf_param       : CSF parameters config file
 *
 * @retval      -1  : Failure
 *               0  : Success
 */
static int create_csf_file_v1(char *csf_filename, char *ifname, csf_params_t *csf_param)
{
    ASSERT(csf_filename, -1);
    ASSERT(ifname, -1);
    ASSERT(csf_param, -1);

    char rvalue[RSIZE] = {0};
    bool fast_auth = false;

    /* Create CSF file with CSF parameters */
    FILE *fp_csf_file = fopen(csf_filename, "w");
    if (NULL == fp_csf_file ) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", csf_filename, strerror(errno));
        goto err;
    }

    /* Open CSF config file */
    FILE *fp_cfg = fopen(g_csf_cfgfilename, "r");
    if (NULL == fp_cfg) {
       fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", g_csf_cfgfilename, strerror(errno));
       goto err;
    }

    /* Populate CSF file with appropriate parameters */
    /* Header */
    fprintf(fp_csf_file, "[Header]\n");

    cfg_parser(fp_cfg, rvalue, RSIZE, "header_version");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tVersion = 4.3\n");
    else
        fprintf(fp_csf_file, "\tVersion = %s\n", rvalue);


    fprintf(fp_csf_file, "\tHash Algorithm = sha256\n");

    cfg_parser(fp_cfg, rvalue, RSIZE, "header_eng");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tEngine = ANY\n");
    else
        fprintf(fp_csf_file, "\tEngine = %s\n", rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "header_eng_config");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tEngine Configuration = 0\n");
    else
        fprintf(fp_csf_file, "\tEngine Configuration = %s\n", rvalue);

    fprintf(fp_csf_file, "\tCertificate Format = X509\n");

    fprintf(fp_csf_file, "\tSignature Format = CMS\n");

    /* Install SRK */
    fprintf(fp_csf_file, "[Install SRK]\n");
    cfg_parser(fp_cfg, rvalue, RSIZE, "srktable_file");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tFile = \"%s/crts/SRK_1_2_3_4_table.bin\"\n", g_cst_path);
    else
        fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_cst_path, rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_source_index");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tSource index = 0\n");
    else
        fprintf(fp_csf_file, "\tSource index = %s\n", rvalue);

    /* Choose between fast authentication and normal authentication */
    cfg_parser(fp_cfg, rvalue, RSIZE, "nocak_file");
    if ('\0' != rvalue[0]) {
        /* Prepare fast authentication parameters */
        fast_auth = true;
        /* Install NOCAK */
        fprintf(fp_csf_file, "[Install NOCAK]\n");
        fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_cst_path, rvalue);
    } else {
        /* Prepare normal authentication parameters */
        /* Install CSFK */
        fprintf(fp_csf_file, "[Install CSFK]\n");
        cfg_parser(fp_cfg, rvalue, RSIZE, "csfk_file");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tFile = \"%s/crts/CSF1_1_sha256_2048_65537_v3_usr_crt.pem\"\n", g_cst_path);
        else
            fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_cst_path, rvalue);
    }

    fprintf(fp_csf_file, "[Authenticate CSF]\n");

    /* Unlock */
#define NUM_ENGINES         4
#define NUM_FEATURES        10
#define MAX_ENGINE_LEN      6  // OCOTP
#define MAX_FEATURE_LEN     13 // FIELD RETURN

    char *key = NULL;
    int i = 0;
    char engines[NUM_ENGINES][MAX_ENGINE_LEN] = { };
    char features[NUM_FEATURES][MAX_FEATURE_LEN] = { };
    char uid[100] = { };
    /* Engines */
    cfg_parser(fp_cfg, rvalue, RSIZE, "unlock_engine");
    if ('\0' != rvalue[0]) {
        for (key = strtok(rvalue, ","); key != NULL; key = strtok(NULL, ",")) {
            strncpy((char *)engines[i++], key, MAX_ENGINE_LEN - 1);
        }

        key = NULL;
        i = 0;
        /* Features */
        cfg_parser(fp_cfg, rvalue, RSIZE, "unlock_features");
        if ('\0' != rvalue[0]) {
            for (key = strtok(rvalue, ","); key != NULL; key = strtok(NULL, ",")) {
                strncpy((char *)features[i++], key, MAX_FEATURE_LEN - 1);
            }
        }
        /* UID */
        cfg_parser(fp_cfg, rvalue, RSIZE, "unlock_uid");
        if ('\0' != rvalue[0])
            strncpy(uid, rvalue, sizeof(uid)/sizeof(uid[0]));

    }


#define PRINT_UNLOCK_CMD  do { \
                            fprintf(fp_csf_file, "[Unlock]\n"); \
                            fprintf(fp_csf_file, "\tEngine = %s\n", engines[i]); \
                            fprintf(fp_csf_file, "\tFeatures = %s\n", features[j]); \
                          } while(0)

    /* Parse engines and features*/
    if (engines[0] && features[0]) {
        for (int i = 0; i < NUM_ENGINES; i++) {
            if (!strncmp(engines[i], "SRTC", 4)) {
                fprintf(fp_csf_file, "[Unlock]\n");
                fprintf(fp_csf_file, "\tEngine = %s\n", engines[i]);
                continue;
            } else if (!strncmp(engines[i], "CAAM", 4)) {
                for (int j = 0; j < NUM_FEATURES; j++) {
                    if (!strncmp(features[j], "MID", 3) || \
                        !strncmp(features[j], "RNG", 3) || \
                        !strncmp(features[j], "MFG", 3)) {
                        PRINT_UNLOCK_CMD;
                    }
                }
            } else if (!strncmp(engines[i], "SNVS", 4)) {
                for (int j = 0; j < NUM_FEATURES; j++) {
                    if (!strncmp(features[j], "LP SWR", 6) || \
                        !strncmp(features[j], "ZMK WRITE", 9)) {
                        PRINT_UNLOCK_CMD;
                    }
                }
            } else if (!strncmp(engines[i], "OCOTP", 5)) {
                for (int j = 0; j < NUM_FEATURES; j++) {
                    if ((!strncmp(features[j], "FIELD RETURN", 12) || \
                         !strncmp(features[j], "SCS", 3) || \
                         !strncmp(features[j], "JTAG", 4)) \
                      && strlen(uid) > 0) {
                        PRINT_UNLOCK_CMD;
                        fprintf(fp_csf_file, "\tUID = %s\n", uid);
                    } else if (!strncmp(features[j], "SRK REVOKE", 10)) {
                        PRINT_UNLOCK_CMD;
                    }
                }
            }
        }
    }

    /* Choose between fast authentication and normal authentication */
    if (!fast_auth) {
        /* Install Key */
        fprintf(fp_csf_file, "[Install Key]\n");
        cfg_parser(fp_cfg, rvalue, RSIZE, "img_verification_index");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tVerification index = 0\n");
        else
            fprintf(fp_csf_file, "\tVerification index = %s\n", rvalue);

        cfg_parser(fp_cfg, rvalue, RSIZE, "img_target_index");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tTarget index = 0\n");
        else
            fprintf(fp_csf_file, "\tTarget index = %s\n", rvalue);

        cfg_parser(fp_cfg, rvalue, RSIZE, "img_file");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tFile = \"%s/crts/IMG1_1_sha256_2048_65537_v3_usr_crt.pem\"\n", g_cst_path);
        else
            fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_cst_path, rvalue);
    }

    /* Authenticate Data */
    fprintf(fp_csf_file, "[Authenticate Data]\n");

    /* Choose between fast authentication and normal authentication */
    if (!fast_auth) {
        cfg_parser(fp_cfg, rvalue, RSIZE, "auth_verification_index");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tVerification index = 2\n");
        else
            fprintf(fp_csf_file, "\tVerification index = %s\n", rvalue);
    } else {
        fprintf(fp_csf_file, "\tVerification index = 0\n");
    }

    // TODO: Add blocks statement here

    /* DONE */

    printf("INFO: %s generated\n", csf_filename);

    FCLOSE(fp_csf_file);
    FCLOSE(fp_cfg);
    return 0;

err:
    FCLOSE(fp_csf_file);
    FCLOSE(fp_cfg);
    return -1;
}


/*
 * @brief       Create CSF file for IVT type v3
 *
 * @param[in]   csf_filename    : CSF filename to be populated
 *              ifname          : Input filename
 *              csf_param       : CSF parameters config file
 *
 * @retval      -1              : Failure
 *               0              : Success
 */
static int create_csf_file_v3(char *csf_filename, char *ifname, csf_params_t *csf_param)
{
    ASSERT(csf_filename, -1);
    ASSERT(ifname, -1);
    ASSERT(csf_param, -1);

    char rvalue[RSIZE] = {0};

    /* Create CSF file with CSF parameters */
    FILE *fp_csf_file = fopen(csf_filename, "w");
    if (NULL == fp_csf_file ) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", csf_filename, strerror(errno));
        goto err;
    }

    /* Open CSF config file */
    FILE *fp_cfg = fopen(g_csf_cfgfilename, "r");
    if (NULL == fp_cfg) {
       fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", g_csf_cfgfilename, strerror(errno));
       goto err;
    }

    /* Populate CSF file with appropriate parameters */
    /* Header */
    fprintf(fp_csf_file, "[Header]\n");

    fprintf(fp_csf_file, "\tTarget = AHAB\n");

    cfg_parser(fp_cfg, rvalue, RSIZE,"header_version");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tVersion = 1.0\n");
    else
        fprintf(fp_csf_file, "\tVersion = %s\n", rvalue);

    /* Install SRK */
    fprintf(fp_csf_file, "[Install SRK]\n");

    cfg_parser(fp_cfg, rvalue, RSIZE, "srktable_file");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tFile = \"%s/crts/SRK_1_2_3_4_table.bin\"\n", g_cst_path);
    else
        fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_cst_path, rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_source");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tSource = \"%s/crts/SRK1_sha256_prime256v1_v3_ca_crt.pem\"\n", g_cst_path);
    else
        fprintf(fp_csf_file, "\tSource = \"%s/crts/%s\"\n", g_cst_path, rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_source_index");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tSource index = 0\n");
    else
        fprintf(fp_csf_file, "\tSource index = %s\n", rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_source_set");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tSource set = OEM\n");
    else
        fprintf(fp_csf_file, "\tSource set = %s\n", rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_revocations");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tRevocations = 0x0\n");
    else
        fprintf(fp_csf_file, "\tRevocations = %s\n", rvalue);

    /* Install SGK */
    /* Add SGK info only if its value is populated in config file */
    cfg_parser(fp_cfg, rvalue, RSIZE, "sgk_file");
    if ('\0' != rvalue[0]) {
        fprintf(fp_csf_file, "[Install Certificate]\n");

        fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_cst_path, rvalue);

        cfg_parser(fp_cfg, rvalue, RSIZE, "sgk_permissions");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tPermissions = 0x1\n");
        else
            fprintf(fp_csf_file, "\tPermissions = %s\n", rvalue);
    }

    /* Authenticate Data */
    fprintf(fp_csf_file, "[Authenticate Data]\n");

    fprintf(fp_csf_file, "\tFile = \"%s\"\n", ifname);

    fprintf(fp_csf_file, "\tOffsets = 0x%08X\t0x%08X\n", csf_param->cntr_offset,
    csf_param->sig_offset);

    /* DONE */

    printf("INFO: %s generated\n", csf_filename);

    FCLOSE(fp_csf_file);
    FCLOSE(fp_cfg);
    return 0;

err:
    FCLOSE(fp_csf_file);
    FCLOSE(fp_cfg);
    return -1;
}

/*
 * @brief       Sign image of IVT type v1
 *
 * @param[in]   infile_buf  : Input file buffer
 *              infile_size : Input file size
 *              ifname_full : Input filename
 * @param[out]  ofname      : Ouput filename
 *
 * @retval      -1          : Failure
 *               0          : Success
 */
static int sign_image(const uint8_t *infile_buf, long int infile_size, char *ifname_full, char *ofname)
{
    puts("Nothing Yet!!");
    return -1;
}

/*
 * @brief       Sign image of IVT type v3
 *
 * @param[in]   infile_buf  : Input file buffer
 *              infile_size : Input file size
 *              ifname_full : Input filename
 * @param[out]  ofname      : Ouput filename
 *
 * @retval      0           : Success
 *              -1          : Failure
 */
static int sign_container(const uint8_t *infile_buf, long int infile_size, char *ifname_full, char *ofname)
{
    ASSERT(infile_buf, -1);
    ASSERT(ifname_full, -1);
    ASSERT(ofname, -1);

    int cntr_num = 0; /* number of containers in binary */
    uint32_t file_off = 0; /* offset within container binary */
    uint32_t img_array_size = 0; /* number of images in container */
    flash_header_v3_t container_headers[MAX_NUM_OF_CONTAINER];
    flash_header_v3_t app_container_header;
    int app_cntr_off;
    
    csf_params_t csf_param[MAX_NUM_OF_CONTAINER] = {0};
    
    /* initialize region of memory where flash header will be stored */
    memset((void *)container_headers, 0, sizeof(container_headers));
    
    while (cntr_num < MAX_NUM_OF_CONTAINER && \
        ((file_off + g_image_offset) < infile_size)) {

        /* read in next container header up to the image array */
        memcpy((void *)&container_headers[cntr_num], \
                (file_off + g_image_offset + infile_buf), \
                16);
    
        /* check that the current container has a valid tag */
        if (container_headers[cntr_num].tag != IVT_HEADER_TAG_B0)
            break;

        /* Validate number of images */
        if (container_headers[cntr_num].num_images > MAX_NUM_IMGS) {
            fprintf(stderr, "ERROR: This container includes %d images, beyond max %d images\n", container_headers[cntr_num].num_images, MAX_NUM_IMGS);
            break;
        }
        
        /* compute the size of the image array */
        img_array_size = container_headers[cntr_num].num_images * sizeof(boot_img_t);

        /* read in the full image array */
        memcpy((void *)&container_headers[cntr_num].img, \
            &((flash_header_v3_t *)(file_off + g_image_offset + infile_buf))->img, \
            img_array_size);
    
        /* determine the type of image */
        boot_img_t img = container_headers[cntr_num].img[0];
        img_flags_t img_flags;
        img_flags.type = img.hab_flags & IMAGE_TYPE_MASK;
        DEBUG("Image Flag type: 0x%X\n", img_flags.type);

        /* If container contains signed images provided by NXP like SECO/SENTINEL/V2X, then no need to sign this container. Skip to next one. */
        if (img_flags.type == 0x6 || \
            img_flags.type == 0xB || \
            img_flags.type == 0xC) {
            DEBUG("Container %d already signed\n", cntr_num);
            /* calculate next container offset in binary */
            file_off += ALIGN(container_headers[cntr_num].length, CONTAINER_ALIGNMENT);
            DEBUG("file_off = 0x%08X\n", file_off);

            /* increment current container count */
            cntr_num++;
            continue;
        }

        /* Fill CSF parameters */
        csf_param[cntr_num].cntr_num = cntr_num + 1;
        csf_param[cntr_num].cntr_offset = file_off + g_image_offset;
        csf_param[cntr_num].sig_offset = csf_param[cntr_num].cntr_offset + container_headers[cntr_num].sig_blk_offset;

        /* calculate next container offset in binary */
        file_off += ALIGN(container_headers[cntr_num].length, CONTAINER_ALIGNMENT);
        DEBUG("file_off = 0x%08X\n", file_off);

        /* increment current container count */
        cntr_num++;
    }

    app_cntr_off = search_app_container(container_headers, cntr_num, &app_container_header, infile_buf, infile_size);
    
    if(0 < app_cntr_off) {
        DEBUG("APP container offset = 0x%08X\n", app_cntr_off);
        DEBUG("APP container signature offset = 0x%08X\n", app_cntr_off +  app_container_header.sig_blk_offset);
    
        /* Fill CSF parameters with APP container parameters */
        csf_param[cntr_num].cntr_num = cntr_num + 1;
        csf_param[cntr_num].cntr_offset = app_cntr_off;
        csf_param[cntr_num].sig_offset = csf_param[cntr_num].cntr_offset + app_container_header.sig_blk_offset;
    } else {
        /* Reduce the total containers by 1 if no APP container is found */
        cntr_num--;
    }

    for(int i=0; i<MAX_NUM_OF_CONTAINER; i++) {
        DEBUG("CSF Container:\t Container Number : %d\n", csf_param[i].cntr_num);
        DEBUG("Container Offset : 0x%08X\n", csf_param[i].cntr_offset);
        DEBUG("Signature Offset : 0x%08X\n", csf_param[i].sig_offset);
    }


    /* TODO: Signing logic would be simpler when multiple blocks can be signed in the same CSF file */
    char *csf_filename = NULL;
    char *itemp_fname = "itemp.bin";
    char *otemp_fname = "otemp.bin";

    /* Copy file to be signed to a temporary file */
    if(copy_files(ifname_full, itemp_fname)) {
        fprintf(stderr, "ERROR: Failed to copy files: %s and %s\n", ifname_full, itemp_fname);
        return -1;
    }
    
    /* Create CSF files & sign them */
    for (int i = 0; i <= cntr_num; i++) {
        /* Skip creating CSF for NXP signed images */
        if (0 == csf_param[i].cntr_offset && 0 == csf_param[i].sig_offset)
            continue;

        csf_filename = calloc(FILENAME_MAX_LEN, sizeof(char));
        if (NULL == csf_filename) {
            fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
            goto err;
        }

        /* Prepare CSF filename */
        if (0 > (snprintf(csf_filename, FILENAME_MAX_LEN, "container_%d.csf", i + 1))) {
            fprintf(stderr, "ERROR: CSF filename build unsuccessful. Exiting.\n");
            goto err;
        }

        DEBUG("CSF filename = %s\n", csf_filename);

        /* Create CSF file with input filename */
        if (create_csf_file_v3(csf_filename, itemp_fname, &csf_param[i])) {
            fprintf(stderr, "ERROR: Failed to create CSF file properly: %s\n", csf_filename);
            goto err;
        }
        DEBUG("CSF filename created = %s\n", csf_filename);
                
        if (i != cntr_num) {
            /* Sign into a temp output file */
            if (sign_csf(csf_filename, otemp_fname)) {
                fprintf(stderr, "ERROR: Failed to sign the image using: %s\n", csf_filename);
                goto err;
            }
            /* Remove input temp file */
            if (remove(itemp_fname)) {
                fprintf(stderr, "ERROR: Couldn't remove file: %s; %s\n", itemp_fname, strerror(errno));
                goto err;
            }
            /* Rename output temp file to input temp file to be signed again */
            if (rename(otemp_fname, itemp_fname)) {
                fprintf(stderr, "ERROR: Couldn't rename file: %s to %s; %s\n", otemp_fname, itemp_fname, strerror(errno));
                goto err;
            }
        } else {
            /* If last container is being signed then create final signed image */
            if (sign_csf(csf_filename, ofname)) {
                fprintf(stderr, "ERROR: Failed to sign the image using: %s\n", csf_filename);
                goto err;
            }
            /* Remove input temporary file */
            if (remove(itemp_fname)) {
                fprintf(stderr, "ERROR: Couldn't remove file: %s; %s\n", itemp_fname, strerror(errno));
                goto err;
            }
        }
        
        FREE(csf_filename);
    }

    return 0;

err:
    FREE(csf_filename);
    return -1;
}

/*
 * @brief       This function reads the inputs file and returns size
 *
 * @param[in]   fp         - Input file pointer
 *              input_file - Input file name
 *
 * @retval      Return file size
 */
long int get_file_size(FILE *fp, char *input_file)
{
    int ret = -1;

    if (NULL == input_file) {
        fprintf(stderr, "ERROR: Invalid file: %s\n", input_file);
        return -1;
    }

    /* Open file */
    fp = fopen(input_file, "rb");
    if (NULL == fp) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", input_file, strerror(errno));
        return -1;
    }
    
    /* Seek to the end of file to calculate size */
    if (fseek(fp , 0 , SEEK_END)) {
        errno = ENOENT; 
        fprintf(stderr, "ERROR: Couldn't seek to end of file: %s; %s\n", input_file, strerror(errno));
        FCLOSE(fp);
        return -1;
    }

    /* Get size and go back to start of the file */
    ret = ftell(fp);
    rewind(fp);

    FCLOSE(fp);
    
    return ret;
}

/*
 * @brief       This function allocates buffer with size from input file
 *
 * @param[in]   fp         - Input file pointer
 *              input_file - Input file name
 *
 * @retval      return buffer pointer
 */
unsigned char *alloc_buffer(FILE *fp, char *input_file)
{
    long int file_size = 0;
    unsigned char *buf = NULL;

    file_size = get_file_size(fp, input_file);
    if (0 > file_size) {
        fprintf(stderr, "ERROR: Invalid file size %ld of file: %s\n", file_size, input_file);
        return NULL;
    }
    
    /* Open file */
    fp = fopen(input_file, "rb");
    if (NULL == fp) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", input_file, strerror(errno));
        return NULL;
    }
    
    /* Allocate memory to the buffer */
    buf = malloc(file_size);
    if (NULL == buf || 0 == buf) {
        fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
        FCLOSE(fp);
        return NULL;
    }

    /* Copy the file into the buffer */
    size_t result = fread(buf, 1, file_size, fp);
    if (result != file_size) {
        fprintf(stderr, "ERROR: File read error; %s\n", strerror(errno));
        FCLOSE(fp);
        FREE(buf);
        return NULL;
    }
    FCLOSE(fp);

    return buf;
}

/*
 * @brief       Prints the usage information for running encrypt_image
 */
static void print_usage(void) {
    int i = 0;
    printf("CST Signer: CST helper tool to auto-sign image.\n"
        "Usage: CST_PATH=<cst-path> ./cst_signer ");
    do {
        printf("-%c <%s> ", long_opt[i].val, long_opt[i].name);
        i++;
    } while (long_opt[i + 1].name != NULL);
    printf("\n");

    i = 0;
    printf("Options:\n");
    do {
        printf("\t-%c|--%s  -->  %s\n", long_opt[i].val, long_opt[i].name, desc_opt[i]);
        i++;
    } while (long_opt[i].name != NULL && desc_opt[i] != NULL);
    puts("\nNote: Only one image can be signed at once.\n");
}

/*
 * @brief       Handle each command line option
 *
 * @param[in]   argc    : Number of input arguments
 *              argv    : Input arguments
 */
static void handle_cl_opt(int argc, char **argv)
{
    int next_opt = 0;
    int n_long_opt = 1; // Includes the command itself
    int mandatory_opt = 0;
    int i = 0;

    do {
        n_long_opt++;
        if (long_opt[i].has_arg == required_argument) {
            n_long_opt++;
        }
        i++;
    } while (long_opt[i + 1].name != NULL);

    /* Start from the first command-line option */
    optind = 0;
    /* Handle command line options*/
    do {
        next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
        switch (next_opt)
        {
        case 'i':
        case 'c':
            mandatory_opt += 1;
            break;
        /* Display usage */
        case 'h':
            print_usage();
            exit(EXIT_SUCCESS);
            break;
        case '?':
            /* Unknown character returned */
            print_usage();
            exit(EXIT_FAILURE);
            break;
        /* At the end reach here and check if mandatory options are present */
        default:
            if (mandatory_opt != 2 && next_opt == -1) {
                fprintf(stderr, "ERROR: -i & -c option is required\n");
                print_usage();
                exit(EXIT_FAILURE);
            }
            break;
        }
    } while (next_opt != -1);
     /* Check for valid arguments */
    if (argc < 2 || argc > n_long_opt) {
        printf("Error: Incorrect number of options\n");
        print_usage();
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    char *ifname = NULL;
    char *ifname_full = NULL;
    char ofname[FILENAME_MAX_LEN] = "signed-";

    FILE *fp_in = NULL;
    
    uint8_t *ibuf = NULL;
    long int ibuf_size = 0;
    
    bool ret = 0;
    int next_opt = 0;

    /* Get CST_PATH environment value. getenv is cross platform compatible */
    g_cst_path = getenv("CST_PATH");
    if(!g_cst_path){
        fprintf(stderr, "ERROR: Environment variable \"CST_PATH\" is mandatory\n");
        goto err;
    }

    /* Handle command line options */
    handle_cl_opt(argc, argv);

    /* Start from the first command-line option */
    optind = 0;
    /* Perform actions according to command-line option */
    do {
        next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
        switch (next_opt)
        {
            /* Input image */
            case 'i':
                ifname_full = optarg;
                ifname = basename(optarg);
                /* Report long input filename */
                if (0 >= (int)(FILENAME_MAX_LEN - strlen(ifname) - strlen(ofname) - 1)) {
                    fprintf(stderr, "ERROR: Input filename too long: %s\n", ifname);
                    goto err;
                }
                /* Prepare output filename based on input filename */
                strncat(ofname, ifname, strlen(ifname));
                break;
            /* Image offset */
            case 'o':
                g_image_offset = strtol(optarg, NULL, BASE_HEX);
                break;
            /* Input YAML config file */
            case 'c':
                g_csf_cfgfilename = optarg;
                break;
            /* Enable debug log */
            case 'd':
                g_debug = 1;
                break;
            /* Display usage */
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
                break;
            /* Invalid Option */
            default:
                break;
        }
    } while (next_opt != -1);
    
    DEBUG("Input filename = %s\n", ifname);
    DEBUG("Output filename = %s\n", ofname);
    if (NULL != g_csf_cfgfilename)
        DEBUG("Input CSF Configuration filename = %s\n", g_csf_cfgfilename);

    /* Allocate buffer for input file */
    ibuf = alloc_buffer(fp_in, ifname_full);
    if (NULL == ibuf) {
        fprintf(stderr, "ERROR: File read error: %s\n", ifname_full);
        goto err;
    }
    
    ibuf_size = get_file_size(fp_in, ifname_full);
    DEBUG("Input filesize = %ld bytes\n", ibuf_size);
    
    /* Parse w.r.t type of IVT */
    ivt_header_t *hdr_v1 = (ivt_header_t *)(ibuf + g_image_offset);
    flash_header_v3_t *hdr_v3 = (flash_header_v3_t *)(ibuf + g_image_offset);
    if (IVT_HEADER_TAG_B0 == hdr_v3->tag) {
        DEBUG("IVT header = TAG:0x%02X | LEN:0x%04X | VER:0x%02X\n", hdr_v3->tag, hdr_v3->length, hdr_v3->version);
        ret = sign_container(ibuf, ibuf_size, ifname_full, ofname);
        if (!ret) {
            goto err;
        }
    } else if (IVT_HEADER_TAG == hdr_v1->tag) {
        DEBUG("IVT header = TAG:0x%02X | LEN:0x%04X | VER:0x%02X\n", hdr_v1->tag, hdr_v1->length, hdr_v1->version);
        ret = sign_image(ibuf, ibuf_size, ifname_full, ofname);
        if (!ret) {
            goto err;
        }
    } else {
        fprintf(stderr, "ERROR: Invalid image header\n");
        goto err;
    }
    
    return EXIT_SUCCESS;
err:
    FCLOSE(fp_in);
    FREE(ibuf);
    return EXIT_FAILURE;
}
