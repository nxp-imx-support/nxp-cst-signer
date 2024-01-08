#==============================================================================
#    Copyright 2022-2023 NXP
#
#    SPDX-License-Identifier: GPL-2.0-or-later
#==============================================================================

all:
	@$(MAKE) -C src

install:
	@$(MAKE) -C src install

clean:
	@$(MAKE) -C src clean

.PHONY: all install clean
