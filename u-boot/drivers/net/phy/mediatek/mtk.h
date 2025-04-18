/* SPDX-License-Identifier: GPL-2.0
 *
 * Common definition for Mediatek Ethernet PHYs
 * Author: SkyLake Huang <SkyLake.Huang@mediatek.com>
 * Copyright (c) 2024 MediaTek Inc.
 */

#ifndef _MTK_EPHY_H_
#define _MTK_EPHY_H_

#define MTK_EXT_PAGE_ACCESS			0x1f
#define MTK_PHY_PAGE_STANDARD			0x0000
#define MTK_PHY_PAGE_EXTENDED_1			0x0001
#define MTK_PHY_AUX_CTRL_AND_STATUS		0x14
/* suprv_media_select_RefClk */
#define   MTK_PHY_LP_DETECTED_MASK		GENMASK(7, 6)
#define   MTK_PHY_ENABLE_DOWNSHIFT		BIT(4)

#define MTK_PHY_PAGE_EXTENDED_52B5		0x52b5

/* Registers on Token Ring debug nodes */
/* ch_addr = 0x0, node_addr = 0xf, data_addr = 0x2 */
#define   AN_STATE_MASK			GENMASK(22, 19)
#define   AN_STATE_SHIFT		19
#define   AN_STATE_TX_DISABLE		1

/* ch_addr = 0x0, node_addr = 0xf, data_addr = 0x3c */
#define AN_NEW_LP_CNT_LIMIT_MASK		GENMASK(23, 20)
#define AUTO_NP_10XEN				BIT(6)

/* Registers on MDIO_MMD_VEND1 */
#define MTK_PHY_LINK_STATUS_MISC	(0xa2)
#define   MTK_PHY_FINAL_SPEED_1000	BIT(3)

/* Registers on MDIO_MMD_VEND2 */
#define MTK_PHY_LED0_ON_CTRL			0x24
#define MTK_PHY_LED1_ON_CTRL			0x26
#define   MTK_GPHY_LED_ON_MASK			GENMASK(6, 0)
#define   MTK_2P5GPHY_LED_ON_MASK		GENMASK(7, 0)
#define   MTK_PHY_LED_ON_LINK1000		BIT(0)
#define   MTK_PHY_LED_ON_LINK100		BIT(1)
#define   MTK_PHY_LED_ON_LINK10			BIT(2)
#define   MTK_PHY_LED_ON_LINKDOWN		BIT(3)
#define   MTK_PHY_LED_ON_FDX			BIT(4) /* Full duplex */
#define   MTK_PHY_LED_ON_HDX			BIT(5) /* Half duplex */
#define   MTK_PHY_LED_ON_FORCE_ON		BIT(6)
#define   MTK_PHY_LED_ON_LINK2500		BIT(7)
#define   MTK_PHY_LED_ON_POLARITY		BIT(14)
#define   MTK_PHY_LED_ON_ENABLE			BIT(15)

#define MTK_PHY_LED0_BLINK_CTRL			0x25
#define MTK_PHY_LED1_BLINK_CTRL			0x27
#define   MTK_PHY_LED_BLINK_1000TX		BIT(0)
#define   MTK_PHY_LED_BLINK_1000RX		BIT(1)
#define   MTK_PHY_LED_BLINK_100TX		BIT(2)
#define   MTK_PHY_LED_BLINK_100RX		BIT(3)
#define   MTK_PHY_LED_BLINK_10TX		BIT(4)
#define   MTK_PHY_LED_BLINK_10RX		BIT(5)
#define   MTK_PHY_LED_BLINK_COLLISION		BIT(6)
#define   MTK_PHY_LED_BLINK_RX_CRC_ERR		BIT(7)
#define   MTK_PHY_LED_BLINK_RX_IDLE_ERR		BIT(8)
#define   MTK_PHY_LED_BLINK_FORCE_BLINK		BIT(9)
#define   MTK_PHY_LED_BLINK_2500TX		BIT(10)
#define   MTK_PHY_LED_BLINK_2500RX		BIT(11)

#define MTK_GPHY_LED_ON_SET			(MTK_PHY_LED_ON_LINK1000 | \
						 MTK_PHY_LED_ON_LINK100 | \
						 MTK_PHY_LED_ON_LINK10)
#define MTK_GPHY_LED_RX_BLINK_SET		(MTK_PHY_LED_BLINK_1000RX | \
						 MTK_PHY_LED_BLINK_100RX | \
						 MTK_PHY_LED_BLINK_10RX)
#define MTK_GPHY_LED_TX_BLINK_SET		(MTK_PHY_LED_BLINK_1000RX | \
						 MTK_PHY_LED_BLINK_100RX | \
						 MTK_PHY_LED_BLINK_10RX)

#define MTK_2P5GPHY_LED_ON_SET			(MTK_PHY_LED_ON_LINK2500 | \
						 MTK_GPHY_LED_ON_SET)
#define MTK_2P5GPHY_LED_RX_BLINK_SET		(MTK_PHY_LED_BLINK_2500RX | \
						 MTK_GPHY_LED_RX_BLINK_SET)
#define MTK_2P5GPHY_LED_TX_BLINK_SET		(MTK_PHY_LED_BLINK_2500RX | \
						 MTK_GPHY_LED_TX_BLINK_SET)

#define MTK_PHY_LED_STATE_FORCE_ON	0
#define MTK_PHY_LED_STATE_FORCE_BLINK	1
#define MTK_PHY_LED_STATE_NETDEV	2

void mtk_phy_select_page(struct phy_device *phydev, int page);
void mtk_phy_restore_page(struct phy_device *phydev);

u32 mtk_tr_read(struct phy_device *phydev, u8 ch_addr, u8 node_addr,
		u8 data_addr);
void __mtk_tr_modify(struct phy_device *phydev, u8 ch_addr, u8 node_addr,
		     u8 data_addr, u32 mask, u32 set);
void mtk_tr_modify(struct phy_device *phydev, u8 ch_addr, u8 node_addr,
		   u8 data_addr, u32 mask, u32 set);
void __mtk_tr_set_bits(struct phy_device *phydev, u8 ch_addr, u8 node_addr,
		       u8 data_addr, u32 set);
void __mtk_tr_clr_bits(struct phy_device *phydev, u8 ch_addr, u8 node_addr,
		       u8 data_addr, u32 clr);

#endif /* _MTK_EPHY_H_ */
