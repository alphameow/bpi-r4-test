// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 MediaTek Inc.
 */

#include <config.h>
#include <asm/global_data.h>

DECLARE_GLOBAL_DATA_PTR;

int board_init(void)
{
	/* address of boot parameters */
	gd->bd->bi_boot_params = CFG_SYS_SDRAM_BASE + 0x100;

	return 0;
}

uint32_t spl_nand_get_uboot_raw_page(void)
{
	return CONFIG_SPL_PAD_TO;
}
