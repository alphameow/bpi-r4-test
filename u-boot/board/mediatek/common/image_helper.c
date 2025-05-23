// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 MediaTek Inc. All Rights Reserved.
 *
 * Author: Weijie Gao <weijie.gao@mediatek.com>
 *
 * Generic image parsing helper
 */

#include <errno.h>
#include <image.h>
#include <vsprintf.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <asm/byteorder.h>
#include <u-boot/crc.h>

#include "image_helper.h"
#include "untar.h"

struct rootfs_info {
	u64 size;
	u32 padding_size;
};

/* Only supports native byte-order for squashfs */
#define SQUASHFS_MAGIC		0x73717368

struct squashfs_super_block {
	u32 s_magic;
	u32 padding0[9];
	u64 bytes_used;
};

/*
 * Two UBI image types are supported:
 * 1. Kernel in individual MTD partition, and rootfs in MTD partition 'ubi'
 * 2. Both kernel and rootfs in MTD partition 'ubi'
 */
#define UBI_EC_HDR_MAGIC	0x55424923

struct ubi_ec_hdr {
	__be32 magic;
	__u8   version;
	__u8   padding1[3];
	__be32 padding2[13];
	__be32 hdr_crc;
};

#define UBI_EC_HDR_SIZE		sizeof(struct ubi_ec_hdr)
#define UBI_EC_HDR_SIZE_CRC	(UBI_EC_HDR_SIZE  - sizeof(__be32))

#define UBI_CRC32_INIT		0xFFFFFFFFU

/**
 * find_rootfs_ram() - Find squashfs rootfs in RAM
 *
 * @description:
 * There may be padding between kernel image and rootfs. This function will
 * find the rootfs by searching squashfs magic after the kernel image.
 *
 * @param data: start data address to be searched
 * @param size: size to be searched
 * @param trailing: trailing bytes of the kernel in last block
 * @param blocksize: blocksize for padding
 * @param ri: on success storing the rootfs information
 *
 * @return 0 if found, -ENODEV if not found, -E2BIG if data corruption,
 *                     -ENOENT is no extra data after kernel
 */
static int find_rootfs_ram(const void *data, size_t size, u32 trailing,
			   u32 blocksize, struct rootfs_info *ri)
{
	struct squashfs_super_block sb;
	bool rootfs_truncated = false;
	uintptr_t offset;

	debug("%s: data = 0x%p, end = 0x%p\n", __func__, data, data + size);

	if (size < sizeof(sb))
		return -ENOENT;

	/*
	 * For the first round, the search offset will not be aligned to
	 * the block boundary (i.e. no padding)
	 */
	offset = 0;

	while (offset < size - sizeof(sb)) {
		memcpy(&sb, data + offset, sizeof(sb));

		debug("%s: checking at 0x%p, magic = 0x%08x, size = 0x%llx\n",
		      __func__, data + offset, sb.s_magic, sb.bytes_used);

		/* Check native-endian magic only */
		if (sb.s_magic != SQUASHFS_MAGIC)
			goto next_offset;

		/* Whether the size field in the superblock is valid */
		if (offset + sb.bytes_used > size) {
			/*
			 * This may be a fake superblock, so we continue to
			 * check the next block. Mark this so we can return
			 * precise error code if no rootfs found at last.
			 */
			rootfs_truncated = true;
			goto next_offset;
		}

		/*
		 * We can't check the entire rootfs here, assuming this is a
		 * valid superblock.
		 */
		ri->padding_size = offset;
		ri->size = sb.bytes_used;

		debug("%s: found at 0x%lx, size = 0x%llx\n", __func__, offset,
		      sb.bytes_used);

		return 0;

	next_offset:
		/* blocksize == 0 means no padding */
		if (!blocksize)
			break;

		/* Align the search offset to next block */
		offset += blocksize - trailing;
		trailing = 0;
	}

	if (rootfs_truncated)
		return -E2BIG;

	return -ENODEV;
}

static int fill_ubi_info(const void *data, size_t size, u32 blocksize,
			 struct owrt_image_info *ii)
{
	struct ubi_ec_hdr ec;
	uintptr_t offset = 0;
	u32 crc;

	while (offset < size - blocksize) {
		memcpy(&ec, data + offset, sizeof(ec));

		debug("%s: checking at 0x%p, magic = 0x%08x\n",
		      __func__, data + offset, be32_to_cpu(ec.magic));

		if (be32_to_cpu(ec.magic) != UBI_EC_HDR_MAGIC)
			break;

		/* Check the CRC32 of EC header */
		crc = crc32_no_comp(UBI_CRC32_INIT, (u8 *)&ec,
				    UBI_EC_HDR_SIZE_CRC);

		if (crc != be32_to_cpu(ec.hdr_crc))
			break;

		if (ec.padding1[0] == 'E' && ec.padding1[1] == 'O' &&
		    ec.padding1[2] == 'F')
			break;

		offset += blocksize;
	}

	if (!offset)
		return -1;

	ii->rootfs_size = offset;
	ii->marker_size = size - offset;

	return 0;
}

int find_ubi_start(const void *data, size_t size, u32 blocksize,
		   size_t *retoffset)
{
	struct ubi_ec_hdr ec;
	size_t offset = 0;
	u32 crc;

	while (offset < size - blocksize) {
		memcpy(&ec, data + offset, sizeof(ec));

		debug("%s: checking at 0x%p, magic = 0x%08x\n",
		      __func__, data + offset, be32_to_cpu(ec.magic));

		if (be32_to_cpu(ec.magic) != UBI_EC_HDR_MAGIC)
			goto next_block;

		*retoffset = offset;

		debug("%s: UBI start at 0x%p + 0x%zx\n", __func__, data,
		       offset);

		/* Check the CRC32 of EC header */
		crc = crc32_no_comp(UBI_CRC32_INIT, (u8 *)&ec,
				    UBI_EC_HDR_SIZE_CRC);

		if (crc != be32_to_cpu(ec.hdr_crc))
			return -EBADMSG;

		return 0;

	next_block:
		offset += blocksize;
	}

	return 1;
}

static int parse_image_ubi1(const void *data, size_t size, u32 trailing,
			    u32 blocksize, struct owrt_image_info *ii)
{
	uintptr_t offset = 0;
	int ret;

	debug("%s: data = 0x%p, end = 0x%p\n", __func__, data, data + size);

	if (trailing)
		offset += blocksize - trailing;

	while (offset < size) {
		ret = fill_ubi_info(data + offset, size - offset, blocksize,
				    ii);
		if (!ret) {
			ii->type = IMAGE_UBI1;
			ii->padding_size = offset;

			debug("%s: kernel size = 0x%x, padding = 0x%lx\n",
			      __func__, ii->kernel_size, offset);

			debug("%s: UBI size = 0x%x, marker size = 0x%x\n",
			      __func__, ii->ubi_size, ii->marker_size);

			return 0;
		}

		offset += blocksize;
	}

	return -1;
}

int parse_image_ubi2_ram(const void *data, size_t size, u32 blocksize,
			 struct owrt_image_info *ii)
{
	int ret;

	if (!data || !size || !ii)
		return -EINVAL;

	if (!blocksize || !is_power_of_2(blocksize))
		return -EINVAL;

	ret = fill_ubi_info(data, size, blocksize, ii);
	if (!ret) {
		ii->type = IMAGE_UBI2;
		ii->header_type = HEADER_UNKNOWN;
		ii->kernel_size = 0;
		ii->padding_size = 0;

		debug("%s: UBI size = 0x%x, marker size = 0x%x\n",
		      __func__, ii->ubi_size, ii->marker_size);

		return 0;
	}

	return -1;
}

bool fit_image_conf_exists(const void *fit, const char *conf)
{
	int noffset;

	if (genimg_get_format(fit) != IMAGE_FORMAT_FIT)
		return false;

	noffset = fit_conf_get_node(fit, conf);
	if (noffset < 0)
		return false;

	return true;
}

const char *fit_image_conf_def(const void *fit)
{
	int noffset;

	if (genimg_get_format(fit) != IMAGE_FORMAT_FIT)
		return NULL;

	noffset = fit_conf_get_node(fit, NULL);
	if (noffset < 0) {
		printf("FIT image default configuration node not found\n");
		return NULL;
	}

	return fit_get_name(fit, noffset, NULL);
}

u32 itb_image_size(const void *fit)
{
	int images_noffset, noffset, ndepth, count, ret;
	u32 offset, len, end = 0;

	images_noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (images_noffset < 0) {
		debug("itb node '%s' not found\n", FIT_IMAGES_PATH);
		return 0;
	}

	for (ndepth = 0, count = 0,
	     noffset = fdt_next_node(fit, images_noffset, &ndepth);
			(noffset >= 0) && (ndepth > 0);
			noffset = fdt_next_node(fit, noffset, &ndepth)) {
		if (ndepth == 1) {
			ret = fit_image_get_data_offset(fit, noffset, &offset);
			if (ret) {
				debug("itb image '%s' has no external data\n",
				      fit_get_name(fit, noffset, NULL));
				continue;
			}

			ret = fit_image_get_data_size(fit, noffset, &len);
			if (ret)
				len = 0;

			if (offset + len > end)
				end = offset + len;

			debug("image '%s' offs = 0x%x, len = 0x%x\n",
			      fit_get_name(fit, noffset, NULL), offset, len);
		}
	}

	if (!end) {
		debug("FIT image has no external data\n");
		return 0;
	}

	end += ((fdt_totalsize(fit) + 3) & ~3);

	debug("itb image size = %uB (0x%xB)\n", end, end);

	return end;
}

static int itb_external_image_data_info(const void *fit, int cfg_noffset,
					const char *prop_name, u32 *data_offset,
					u32 *data_len)
{
	int ret, noffset, offset, len;

	noffset = fit_conf_get_prop_node_index(fit, cfg_noffset, prop_name, 0);
	if (noffset < 0) {
		debug("itb cfg prop '%s' not found\n", prop_name);
		return noffset;
	}

	debug("itb cfg prop '%s' = %u\n", prop_name, noffset);

	ret = fit_image_get_data_offset(fit, noffset, &offset);
	if (ret) {
		debug("itb cfg prop '%s' has no external data\n", prop_name);
		return ret;
	}

	/*
	 * For FIT with external data, figure out where
	 * the external images start. This is the base
	 * for the data-offset properties in each image.
	 */
	offset += ((fdt_totalsize(fit) + 3) & ~3);

	debug("itb cfg prop '%s' external data offset = 0x%x\n", prop_name,
	      offset);

	ret = fit_image_get_data_size(fit, noffset, &len);
	if (ret) {
		debug("itb cfg prop '%s' has no external data size\n",
		       prop_name);
		return ret;
	}

	debug("itb cfg prop '%s' external data size = 0x%x\n", prop_name, len);

	if (data_offset)
		*data_offset = offset;

	if (data_len)
		*data_len = len;

	return 0;
}

static int parse_image_itb(const void *fit, size_t size, u32 blocksize,
			   struct owrt_image_info *ii)
{
	int ret, cfg_noffset;
	u32 image_size;

	image_size = itb_image_size(fit);
	if (!image_size || image_size > size) {
		if (image_size) {
			printf("itb image size is invalid (%u >= %zu)\n",
			       image_size, size);
		}

		return -1;
	}

	/* Find default configuration node */
	cfg_noffset = fit_conf_get_node(fit, NULL);
	if (cfg_noffset < 0) {
		printf("itb configuration node not found\n");
		return -1;
	}

	debug("itb configuration node = %u\n", cfg_noffset);

	ret = itb_external_image_data_info(fit, cfg_noffset, FIT_KERNEL_PROP,
					   NULL, NULL);
	if (ret)
		return ret;

	ret = itb_external_image_data_info(fit, cfg_noffset, FIT_LOADABLE_PROP,
					   &ii->padding_size, &ii->rootfs_size);
	if (ret)
		return ret;

	ii->type = IMAGE_ITB;
	ii->header_type = HEADER_FIT;
	ii->kernel_size = image_size; /* kernel size = valid itb image size */
	ii->marker_size = size - image_size;

	return 0;
}

bool fit_image_check_kernel_conf(const void *fit, const char *conf)
{
	int noffset, ret;

	if (genimg_get_format(fit) != IMAGE_FORMAT_FIT)
		return false;

	noffset = fit_conf_get_node(fit, conf);
	if (noffset < 0)
		return false;

	ret = itb_external_image_data_info(fit, noffset, FIT_KERNEL_PROP,
					   NULL, NULL);
	if (ret)
		return false;

	ret = itb_external_image_data_info(fit, noffset, FIT_FDT_PROP,
					   NULL, NULL);
	if (ret)
		return false;

	return true;
}

/**
 * parse_image_ram() - Parse image in RAM and record image information
 *
 * @param data: image to be parsed
 * @param size: size of the image
 * @param blocksize: blocksize for padding
 * @param ii: on success storing the image information
 *
 * @return 0 if check passed,
 *         -1 if image format not supported,
 *         -EBADMSG if image is corrupted,
 *         -EINVAL if parameter error
 */
int parse_image_ram(const void *data, size_t size, u32 blocksize,
		    struct owrt_image_info *ii)
{
	struct rootfs_info ri;
	u32 trailing_bytes;
	int ret;

	if (!data || !size || !ii)
		return -EINVAL;

	if (CONFIG_IS_ENABLED(LEGACY_IMAGE_FORMAT))
		if (size < sizeof(struct legacy_img_hdr))
			return -EINVAL;

	debug("%s: data = 0x%p, size = 0x%zx\n", __func__, data, size);

	switch (genimg_get_format(data)) {
#if defined(CONFIG_LEGACY_IMAGE_FORMAT)
	case IMAGE_FORMAT_LEGACY:
		ii->header_type = HEADER_LEGACY;

		if (!image_check_hcrc(data))
			return -EBADMSG;

		ii->kernel_size = image_get_image_size(data);
		break;
#endif
#if defined(CONFIG_FIT)
	case IMAGE_FORMAT_FIT:
		if (!parse_image_itb(data, size, blocksize, ii))
			return 0;

		ii->header_type = HEADER_FIT;
		ii->kernel_size = fit_get_size(data);
		break;
#endif
	default:
		if (!tar_header_checksum(data)) {
			ii->type = IMAGE_TAR;
			ii->header_type = HEADER_UNKNOWN;
			ii->kernel_size = ii->padding_size = 0;
			ii->ubi_size = ii->marker_size = 0;
			return 0;
		}

		return parse_image_ubi2_ram(data, size, blocksize, ii);
	}

	if (ii->kernel_size > size)
		return -EBADMSG;

	trailing_bytes = ii->kernel_size & (blocksize - 1);

	ret = find_rootfs_ram(data + ii->kernel_size, size - ii->kernel_size,
			      trailing_bytes, blocksize, &ri);

	if (!ret) {
		/* Raw image detected (Kernel + squashfs) */
		ii->type = IMAGE_RAW;
		ii->padding_size = ri.padding_size;
		ii->rootfs_size = ri.size;
		ii->marker_size = size - ii->kernel_size - ri.padding_size -
				  ri.size;

		debug("%s: kernel size = 0x%x, padding = 0x%x\n",
		      __func__, ii->kernel_size, ri.padding_size);

		debug("%s: squashfs size = 0x%llx, marker size = 0x%x\n",
		      __func__, ri.size, ii->marker_size);

		return 0;
	} else if (ret == -ENOENT) {
		/* Raw image detected (Kernel only) */
		ii->type = IMAGE_RAW;
		ii->padding_size = size - ii->kernel_size;
		ii->rootfs_size = 0;
		ii->marker_size = 0;

		debug("%s: kernel size = 0x%x, padding = 0x%x\n",
		      __func__, ii->kernel_size, ri.padding_size);

		return 0;
	}

	if (!blocksize || !is_power_of_2(blocksize))
		return -EINVAL;

	return parse_image_ubi1(data + ii->kernel_size, size - ii->kernel_size,
				trailing_bytes, blocksize, ii);
}
