#==============================================================================
#    Copyright 2022 NXP
#
#    SPDX-License-Identifier: GPL-2.0-or-later
#==============================================================================

CC = gcc

COPTS = -g -Wall
#-Werror
CFLAGS = -I../inc/.

DEPS = cst_signer.h cfg_parser.h mkimage_helper.h
SRCS = cst_signer.c cfg_parser.c mkimage_helper.c

.PHONY: all clean

all: cst_signer

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

cst_signer: cst_signer.c
	$(CC) $(COPTS) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -rvf cst_signer
