#==============================================================================
#    Copyright 2022-2024 NXP
#
#    SPDX-License-Identifier: GPL-2.0-only
#==============================================================================

SRC_DIR := src

.PHONY: all clean

all:
	@$(MAKE) -C $(SRC_DIR)/

install:
	@$(MAKE) -C src install

clean:
	@$(MAKE) -C src clean
