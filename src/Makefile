#==============================================================================
#    Copyright 2022-23 NXP
#
#    SPDX-License-Identifier: GPL-2.0-or-later
#==============================================================================

CC = gcc

COPTS = -g -Wall -Werror
CFLAGS = -I../inc/.

DEPS = cst_signer.h cfg_parser.h mkimage_helper.h
SRCS = cst_signer.c cfg_parser.c mkimage_helper.c fdt.o

.PHONY: all clean

all: cst_signer fdt.o

fdt.o: fdt.c
	$(CC) -c -w -o $@ $< $(CFLAGS)

cst_signer: cst_signer.c fdt.o
	$(CC) $(COPTS) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -rf cst_signer fdt.o
