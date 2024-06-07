#==============================================================================
#    Copyright 2022-2024 NXP
#
#    SPDX-License-Identifier: GPL-2.0-only
#==============================================================================

CC        ?= gcc
CFLAGS    ?= -g -Wall -Werror
CPPFLAGS  ?=
LDFLAGS   ?=
INCLUDES  = -I../inc/

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
DATADIR  ?= $(PREFIX)/share

#DEPS = cst_signer.h cfg_parser.h mkimage_helper.h
SRCS = cst_signer.c cfg_parser.c mkimage_helper.c fdt.c
OBJS = $(SRCS:.c=.o)

.PHONY: all install clean

all: cst_signer

%.o: %.c
	$(CC) -c $(INCLUDES) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) $< -o $@

cst_signer: $(OBJS)
	$(CC) $(INCLUDES) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) -o $@ $^

install: cst_signer
	install -D -m 0755 cst_signer $(DESTDIR)/$(BINDIR)/cst_signer
	install -D -m 0755 -t $(DESTDIR)$(DATADIR)/doc/cst_signer \
            ../csf_ahab.cfg.sample \
            ../csf_hab4.cfg.sample
clean:
	$(RM) cst_signer *.o
