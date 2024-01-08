#==============================================================================
#    Copyright 2022-2023 NXP
#
#    SPDX-License-Identifier: GPL-2.0-or-later
#==============================================================================

CC       ?= gcc
CFLAGS   ?= -g -Wall -Werror
CPPFLAGS ?=
LDFLAGS  ?=
INCLUDES  = -I../inc/

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
DATADIR  ?= $(PREFIX)/share

SRCS = cst_signer.c cfg_parser.c mkimage_helper.c fdt.c

all: cst-signer

%.o : %.c
	$(CC) -c $(INCLUDES) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) $< -o $@

cst-signer: $(SRCS:.c=.o)
	$(CC) $(INCLUDES) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) -o $@ $(SRCS:.c=.o)

install: cst-signer
	install -D -m 0755 cst-signer $(DESTDIR)/$(BINDIR)/cst-signer
	install -D -m 0755 -t $(DESTDIR)$(DATADIR)/doc/cst-signer \
            ../csf_ahab.cfg.sample \
            ../csf_hab4.cfg.sample

clean:
	rm -rf cst-signer *.o

.PHONY: all install clean
