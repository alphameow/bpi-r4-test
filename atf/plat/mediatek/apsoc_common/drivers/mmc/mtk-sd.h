#ifndef __MTK_MMC_H__
#define __MTK_MMC_H__

struct msdc_compatible {
	uint8_t clk_div_bits;
	bool pad_tune0;
	bool async_fifo;
	bool async_fifo_crcsts;
	bool data_tune;
	bool busy_check;
	bool stop_clk_fix;
	bool enhance_rx;
	bool r_smpl;
	uint32_t latch_ck;
};

void mtk_mmc_init(uintptr_t reg_base, uintptr_t top_reg_base,
		  const struct msdc_compatible *compat,
		  uint32_t src_clk, enum mmc_device_type type,
		  uint32_t bus_width);

uint64_t mtk_mmc_device_size(void);
uint32_t mtk_mmc_block_count(void);
enum mmc_device_type mtk_mmc_device_type(void);

#endif
