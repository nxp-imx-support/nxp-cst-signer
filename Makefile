#==============================================================================
#    Copyright 2022 NXP
#
#    SPDX-License-Identifier: GPL-2.0+
#==============================================================================

SRC_DIR := src

.PHONY: all clean

all:
	@$(MAKE) -C $(SRC_DIR)/
	@mv $(SRC_DIR)/cst_signer .

clean:
	@rm -rf cst_signer
