/*
 * Copyright (C) 2010 - 2018 Novatek, Inc.
 * Copyright (C) 2019 XiaoMi, Inc.
 *
 * $Revision: 43560 $
 * $Date: 2019-04-19 11:34:19 +0800 (週五, 19 四月 2019) $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/input/mt.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/pm_runtime.h>

#include <linux/msm_drm_notify.h>
#include <linux/notifier.h>
#include <linux/fb.h>

#include "nt36xxx.h"

#if WAKEUP_GESTURE
#ifdef CONFIG_TOUCHSCREEN_COMMON
#include <linux/input/tp_common.h>
#endif
#endif

#ifdef CHECK_TOUCH_VENDOR
extern char *saved_command_line;

//---Touch Vendor ID---
static uint8_t touch_vendor_id = 0;
#endif

struct nvt_ts_data *ts;
static bool driver_ready = false;

#if BOOT_UPDATE_FIRMWARE
static struct workqueue_struct *nvt_fwu_wq;
extern void Boot_Update_Firmware(struct work_struct *work);
#endif

static void nvt_ts_resume_work(struct work_struct *work);
static int nvt_drm_notifier_callback(struct notifier_block *self, unsigned long event, void *data);

#if WAKEUP_GESTURE
extern void set_lcd_reset_gpio_keep_high(bool en);
static int32_t nvt_ts_enable_regulator(bool en);
#endif

uint32_t ENG_RST_ADDR  = 0x7FFF80;
uint32_t SWRST_N8_ADDR = 0; //read from dtsi
uint32_t SPI_RD_FAST_ADDR = 0;	//read from dtsi

#if WAKEUP_GESTURE
const uint16_t gesture_key_array[] = {
	KEY_WAKEUP,  //GESTURE_WORD_C
	KEY_WAKEUP,  //GESTURE_WORD_W
	KEY_WAKEUP,  //GESTURE_WORD_V
	KEY_WAKEUP,  //GESTURE_DOUBLE_CLICK
	KEY_WAKEUP,  //GESTURE_WORD_Z
	KEY_WAKEUP,  //GESTURE_WORD_M
	KEY_WAKEUP,  //GESTURE_WORD_O
	KEY_WAKEUP,  //GESTURE_WORD_e
	KEY_WAKEUP,  //GESTURE_WORD_S
	KEY_WAKEUP,  //GESTURE_SLIDE_UP
	KEY_WAKEUP,  //GESTURE_SLIDE_DOWN
	KEY_WAKEUP,  //GESTURE_SLIDE_LEFT
	KEY_WAKEUP,  //GESTURE_SLIDE_RIGHT
};
#endif

static uint8_t bTouchIsAwake = 0;

#if WAKEUP_GESTURE
#define WAKEUP_OFF 4
#define WAKEUP_ON 5

inline int nvt_gesture_switch(struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
	if (type == EV_SYN && code == SYN_CONFIG) {

		if (!bTouchIsAwake) {
			ts->delay_gesture = true;
		}
		if (value == WAKEUP_OFF) {
			ts->is_gesture_mode = false;
            nvt_ts_enable_regulator(false);
		} else if (value == WAKEUP_ON) {
			ts->is_gesture_mode = true;
			nvt_ts_enable_regulator(true);
		}
	}
	return 0;
}

#ifdef CONFIG_TOUCHSCREEN_COMMON
static ssize_t double_tap_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", ts->is_gesture_mode);
}

static inline ssize_t double_tap_store(struct kobject *kobj, struct kobj_attribute *attr,
                                const char *buf, size_t count)
{
	int rc, val;

	rc = kstrtoint(buf, 10, &val);
	if (rc)
		return -EINVAL;
    
	ts->is_gesture_mode = !!val;
	return count;
}

static struct tp_common_ops double_tap_ops = {
	.show = double_tap_show,
	.store = double_tap_store
};
#endif

static int32_t nvt_ts_resume(struct device *dev);
static int32_t nvt_ts_suspend(struct device *dev);

typedef int(*touchpanel_recovery_cb_p_t)(void);
extern int set_touchpanel_recovery_callback(touchpanel_recovery_cb_p_t cb);

/* Fix Touch/Fingerprint wakeup crash issue */
inline int nvt_ts_recovery_callback(void)
{
	if (unlikely(bTouchIsAwake)) {
		return -1;
	}
	if (ts->is_gesture_mode) {
		nvt_ts_resume(&ts->client->dev);
		nvt_ts_suspend(&ts->client->dev);
	}
	return 0;
}
EXPORT_SYMBOL(nvt_ts_recovery_callback);
#endif

/*******************************************************
Description:
	Novatek touchscreen irq enable/disable function.

return:
	n.a.
*******************************************************/
static inline void nvt_irq_enable(bool enable)
{
	struct irq_desc *desc;

	if (enable) {
		if (!ts->irq_enabled) {
			enable_irq(ts->client->irq);
			ts->irq_enabled = true;
		}
	} else {
		if (ts->irq_enabled) {
			disable_irq(ts->client->irq);
			ts->irq_enabled = false;
		}
	}

	desc = irq_to_desc(ts->client->irq);
}

/*******************************************************
Description:
	Novatek touchscreen spi read/write core function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static inline int32_t spi_read_write(struct spi_device *client, uint8_t *buf, size_t len , NVT_SPI_RW rw)
{
	struct spi_message m;
	struct spi_transfer t = {
		.len    = len,
	};

	memcpy(ts->xbuf, buf, len);

	switch (rw) {
		case NVTREAD:
			t.tx_buf = ts->xbuf;
			t.rx_buf = ts->rbuf;
			t.len    = (len + DUMMY_BYTES);
			break;

		case NVTWRITE:
			t.tx_buf = ts->xbuf;
			break;
	}

	spi_message_init(&m);
	spi_message_add_tail(&t, &m);
	return spi_sync(client, &m);
}

/*******************************************************
Description:
	Novatek touchscreen spi read function.

return:
	Executive outcomes. 2---succeed. -5---I/O error
*******************************************************/
inline int32_t CTP_SPI_READ(struct spi_device *client, uint8_t *buf, uint16_t len)
{
	int32_t ret = -1;
	int32_t retries = 0;

	mutex_lock(&ts->xbuf_lock);

	buf[0] = SPI_READ_MASK(buf[0]);

	while (retries < 5) {
		ret = spi_read_write(client, buf, len, NVTREAD);
		if (ret == 0) break;
		retries++;
	}

	if (unlikely(retries == 5)) {
		ret = -EIO;
	} else {
		memcpy((buf+1), (ts->rbuf+2), (len-1));
	}

	mutex_unlock(&ts->xbuf_lock);

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen spi write function.

return:
	Executive outcomes. 1---succeed. -5---I/O error
*******************************************************/
inline int32_t CTP_SPI_WRITE(struct spi_device *client, uint8_t *buf, uint16_t len)
{
	int32_t ret = -1;
	int32_t retries = 0;

	mutex_lock(&ts->xbuf_lock);

	buf[0] = SPI_WRITE_MASK(buf[0]);

	while (retries < 5) {
		ret = spi_read_write(client, buf, len, NVTWRITE);
		if (ret == 0)	break;
		retries++;
	}

	if (unlikely(retries == 5)) {
		ret = -EIO;
	}

	mutex_unlock(&ts->xbuf_lock);

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen set index/page/addr address.

return:
	Executive outcomes. 0---succeed. -5---access fail.
*******************************************************/
inline int32_t nvt_set_page(uint32_t addr)
{
	uint8_t buf[4] = {0};

	buf[0] = 0xFF;	//set index/page/addr command
	buf[1] = (addr >> 15) & 0xFF;
	buf[2] = (addr >> 7) & 0xFF;

	return CTP_SPI_WRITE(ts->client, buf, 3);
}

/*******************************************************
Description:
	Novatek touchscreen write data to specify address.

return:
	Executive outcomes. 0---succeed. -5---access fail.
*******************************************************/
inline int32_t nvt_write_addr(uint32_t addr, uint8_t data)
{
	int32_t ret = 0;
	uint8_t buf[4] = {0};

	//---set xdata index---
	buf[0] = 0xFF;	//set index/page/addr command
	buf[1] = (addr >> 15) & 0xFF;
	buf[2] = (addr >> 7) & 0xFF;
	ret = CTP_SPI_WRITE(ts->client, buf, 3);
	if (ret) {
		return ret;
	}

	//---write data to index---
	buf[0] = addr & (0x7F);
	buf[1] = data;
	ret = CTP_SPI_WRITE(ts->client, buf, 2);
	if (ret) {
		return ret;
	}

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen enable hw bld crc function.

return:
	N/A.
*******************************************************/
inline void nvt_bld_crc_enable(void)
{
	uint8_t buf[2] = {0};

	//---set xdata index to BLD_CRC_EN_ADDR---
	nvt_set_page(ts->mmap->BLD_CRC_EN_ADDR);

	//---read data from index---
	buf[0] = ts->mmap->BLD_CRC_EN_ADDR & (0x7F);
	buf[1] = 0xFF;
	CTP_SPI_READ(ts->client, buf, 2);

	//---write data to index---
	buf[0] = ts->mmap->BLD_CRC_EN_ADDR & (0x7F);
	buf[1] = buf[1] | (0x01 << 7);
	CTP_SPI_WRITE(ts->client, buf, 2);
}

/*******************************************************
Description:
	Novatek touchscreen clear status & enable fw crc function.

return:
	N/A.
*******************************************************/
inline void nvt_fw_crc_enable(void)
{
	uint8_t buf[2] = {0};

	//---set xdata index to EVENT BUF ADDR---
	nvt_set_page(ts->mmap->EVENT_BUF_ADDR);

	//---clear fw reset status---
	buf[0] = EVENT_MAP_RESET_COMPLETE & (0x7F);
	buf[1] = 0x00;
	CTP_SPI_WRITE(ts->client, buf, 2);

	//---enable fw crc---
	buf[0] = EVENT_MAP_HOST_CMD & (0x7F);
	buf[1] = 0xAE;	//enable fw crc command
	CTP_SPI_WRITE(ts->client, buf, 2);
}

/*******************************************************
Description:
	Novatek touchscreen set boot ready function.

return:
	N/A.
*******************************************************/
inline void nvt_boot_ready(void)
{
	//---write BOOT_RDY status cmds---
	nvt_write_addr(ts->mmap->BOOT_RDY_ADDR, 1);

	mdelay(5);

	if (!ts->hw_crc) {
		//---write BOOT_RDY status cmds---
		nvt_write_addr(ts->mmap->BOOT_RDY_ADDR, 0);

		//---write POR_CD cmds---
		nvt_write_addr(ts->mmap->POR_CD_ADDR, 0xA0);
	}
}

/*******************************************************
Description:
	Novatek touchscreen eng reset cmd
    function.

return:
	n.a.
*******************************************************/
inline void nvt_eng_reset(void)
{
	//---eng reset cmds to ENG_RST_ADDR---
	nvt_write_addr(ENG_RST_ADDR, 0x5A);

	mdelay(1);	//wait tMCU_Idle2TP_REX_Hi after TP_RST
}

/*******************************************************
Description:
	Novatek touchscreen reset MCU
    function.

return:
	n.a.
*******************************************************/
inline void nvt_sw_reset(void)
{
	//---software reset cmds to SWRST_N8_ADDR---
	nvt_write_addr(SWRST_N8_ADDR, 0x55);

	msleep(10);
}

/*******************************************************
Description:
	Novatek touchscreen reset MCU then into idle mode
    function.

return:
	n.a.
*******************************************************/
inline void nvt_sw_reset_idle(void)
{
	//---MCU idle cmds to SWRST_N8_ADDR---
	nvt_write_addr(SWRST_N8_ADDR, 0xAA);

	msleep(15);
}

/*******************************************************
Description:
	Novatek touchscreen reset MCU (boot) function.

return:
	n.a.
*******************************************************/
inline void nvt_bootloader_reset(void)
{
	//---reset cmds to SWRST_N8_ADDR---
	nvt_write_addr(SWRST_N8_ADDR, 0x69);

	mdelay(5);	//wait tBRST2FR after Bootload RST

	if (SPI_RD_FAST_ADDR) {
		/* disable SPI_RD_FAST */
		nvt_write_addr(SPI_RD_FAST_ADDR, 0x00);
	}
}

/*******************************************************
Description:
	Novatek touchscreen clear FW status function.

return:
	Executive outcomes. 0---succeed. -1---fail.
*******************************************************/
inline int32_t nvt_clear_fw_status(void)
{
	uint8_t buf[8] = {0};
	int32_t i = 0;
	const int32_t retry = 20;

	for (i = 0; i < retry; i++) {
		//---set xdata index to EVENT BUF ADDR---
		nvt_set_page(ts->mmap->EVENT_BUF_ADDR | EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE);

		//---clear fw status---
		buf[0] = EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE;
		buf[1] = 0x00;
		CTP_SPI_WRITE(ts->client, buf, 2);

		//---read fw status---
		buf[0] = EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE;
		buf[1] = 0xFF;
		CTP_SPI_READ(ts->client, buf, 2);

		if (buf[1] == 0x00)
			break;

		usleep_range(10000, 10000);
	}

	if (i >= retry) {
		return -1;
	} else {
		return 0;
	}
}

/*******************************************************
Description:
	Novatek touchscreen check FW status function.

return:
	Executive outcomes. 0---succeed. -1---failed.
*******************************************************/
inline int32_t nvt_check_fw_status(void)
{
	uint8_t buf[8] = {0};
	int32_t i = 0;
	const int32_t retry = 50;

	for (i = 0; i < retry; i++) {
		//---set xdata index to EVENT BUF ADDR---
		nvt_set_page(ts->mmap->EVENT_BUF_ADDR | EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE);

		//---read fw status---
		buf[0] = EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE;
		buf[1] = 0x00;
		CTP_SPI_READ(ts->client, buf, 2);

		if ((buf[1] & 0xF0) == 0xA0)
			break;

		usleep_range(10000, 10000);
	}

	if (i >= retry) {
		return -1;
	} else {
		return 0;
	}
}

/*******************************************************
Description:
	Novatek touchscreen check FW reset state function.

return:
	Executive outcomes. 0---succeed. -1---failed.
*******************************************************/
inline int32_t nvt_check_fw_reset_state(RST_COMPLETE_STATE check_reset_state)
{
	uint8_t buf[8] = {0};
	int32_t ret = 0;
	int32_t retry = 0;
	int32_t retry_max = (check_reset_state == RESET_STATE_INIT) ? 10 : 50;

	//---set xdata index to EVENT BUF ADDR---
	nvt_set_page(ts->mmap->EVENT_BUF_ADDR | EVENT_MAP_RESET_COMPLETE);

	while (1) {
		//---read reset state---
		buf[0] = EVENT_MAP_RESET_COMPLETE;
		buf[1] = 0x00;
		CTP_SPI_READ(ts->client, buf, 6);

		if ((buf[1] >= check_reset_state) && (buf[1] <= RESET_STATE_MAX)) {
			ret = 0;
			break;
		}

		retry++;
		if(unlikely(retry > retry_max)) {
			ret = -1;
			break;
		}

		usleep_range(10000, 10000);
	}

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen get novatek project id information
	function.

return:
	Executive outcomes. 0---success. -1---fail.
*******************************************************/
inline int32_t nvt_read_pid(void)
{
	uint8_t buf[3] = {0};
	int32_t ret = 0;

	//---set xdata index to EVENT BUF ADDR---
	nvt_set_page(ts->mmap->EVENT_BUF_ADDR | EVENT_MAP_PROJECTID);

	//---read project id---
	buf[0] = EVENT_MAP_PROJECTID;
	buf[1] = 0x00;
	buf[2] = 0x00;
	CTP_SPI_READ(ts->client, buf, 3);

	ts->nvt_pid = (buf[2] << 8) + buf[1];

	//---set xdata index to EVENT BUF ADDR---
	nvt_set_page(ts->mmap->EVENT_BUF_ADDR);

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen get firmware related information
	function.

return:
	Executive outcomes. 0---success. -1---fail.
*******************************************************/
inline int32_t nvt_get_fw_info(void)
{
	uint8_t buf[64] = {0};
	uint32_t retry_count = 0;
	int32_t ret = 0;

info_retry:
	//---set xdata index to EVENT BUF ADDR---
	nvt_set_page(ts->mmap->EVENT_BUF_ADDR | EVENT_MAP_FWINFO);

	//---read fw info---
	buf[0] = EVENT_MAP_FWINFO;
	CTP_SPI_READ(ts->client, buf, 17);
	ts->x_num = buf[3];
	ts->y_num = buf[4];
	ts->abs_x_max = (uint16_t)((buf[5] << 8) | buf[6]);
	ts->abs_y_max = (uint16_t)((buf[7] << 8) | buf[8]);

	//---clear x_num, y_num if fw info is broken---
	if ((buf[1] + buf[2]) != 0xFF) {
		ts->x_num = 18;
		ts->y_num = 32;
		ts->abs_x_max = TOUCH_DEFAULT_MAX_WIDTH;
		ts->abs_y_max = TOUCH_DEFAULT_MAX_HEIGHT;

		if(retry_count < 3) {
			retry_count++;
			goto info_retry;
		} else {
			ret = -1;
		}
	} else {
		ret = 0;
	}

	//---Get Novatek PID---
	nvt_read_pid();

	return ret;
}

#if WAKEUP_GESTURE
#define GESTURE_WORD_C          12
#define GESTURE_WORD_W          13
#define GESTURE_WORD_V          14
#define GESTURE_DOUBLE_CLICK    15
#define GESTURE_WORD_Z          16
#define GESTURE_WORD_M          17
#define GESTURE_WORD_O          18
#define GESTURE_WORD_e          19
#define GESTURE_WORD_S          20
#define GESTURE_SLIDE_UP        21
#define GESTURE_SLIDE_DOWN      22
#define GESTURE_SLIDE_LEFT      23
#define GESTURE_SLIDE_RIGHT     24
/* customized gesture id */
#define DATA_PROTOCOL           30

/* function page definition */
#define FUNCPAGE_GESTURE         1

/*******************************************************
Description:
	Novatek touchscreen wake up gesture key report function.

return:
	n.a.
*******************************************************/
inline void nvt_ts_wakeup_gesture_report(uint8_t gesture_id, uint8_t *data)
{
	uint32_t keycode = 0;
	uint8_t func_type = data[2];
	uint8_t func_id = data[3];

	/* support fw specifal data protocol */
	if ((gesture_id == DATA_PROTOCOL) && (func_type == FUNCPAGE_GESTURE)) {
		gesture_id = func_id;
	} else if (gesture_id > DATA_PROTOCOL) {
		return;
	}

	switch (gesture_id) {
		case GESTURE_WORD_C:
			keycode = gesture_key_array[0];
			break;
		case GESTURE_WORD_W:
			keycode = gesture_key_array[1];
			break;
		case GESTURE_WORD_V:
			keycode = gesture_key_array[2];
			break;
		case GESTURE_DOUBLE_CLICK:
			keycode = gesture_key_array[3];
			break;
		case GESTURE_WORD_Z:
			keycode = gesture_key_array[4];
			break;
		case GESTURE_WORD_M:
			keycode = gesture_key_array[5];
			break;
		case GESTURE_WORD_O:
			keycode = gesture_key_array[6];
			break;
		case GESTURE_WORD_e:
			keycode = gesture_key_array[7];
			break;
		case GESTURE_WORD_S:
			keycode = gesture_key_array[8];
			break;
		case GESTURE_SLIDE_UP:
			keycode = gesture_key_array[9];
			break;
		case GESTURE_SLIDE_DOWN:
			keycode = gesture_key_array[10];
			break;
		case GESTURE_SLIDE_LEFT:
			keycode = gesture_key_array[11];
			break;
		case GESTURE_SLIDE_RIGHT:
			keycode = gesture_key_array[12];
			break;
		default:
			break;
	}

	if (keycode > 0) {
		input_report_key(ts->input_dev, keycode, 1);
		input_sync(ts->input_dev);
		input_report_key(ts->input_dev, keycode, 0);
		input_sync(ts->input_dev);
	}
}
#endif

/*******************************************************
Description:
	Novatek touchscreen parse device tree function.

return:
	n.a.
*******************************************************/
#ifdef CONFIG_OF
static int32_t nvt_parse_dt(struct device *dev)
{
	struct device_node *np = dev->of_node;
	int32_t ret = 0;

#if NVT_TOUCH_SUPPORT_HW_RST
	ts->reset_gpio = of_get_named_gpio_flags(np, "novatek,reset-gpio", 0, &ts->reset_flags);
#endif
	ts->irq_gpio = of_get_named_gpio_flags(np, "novatek,irq-gpio", 0, &ts->irq_flags);

	ret = of_property_read_u32(np, "novatek,swrst-n8-addr", &SWRST_N8_ADDR);
	if (ret) {
		return ret;
	}

	ret = of_property_read_u32(np, "novatek,spi-rd-fast-addr", &SPI_RD_FAST_ADDR);
	if (ret) {
		SPI_RD_FAST_ADDR = 0;
		ret = 0;
	}

	return ret;
}
#else
static int32_t nvt_parse_dt(struct device *dev)
{
#if NVT_TOUCH_SUPPORT_HW_RST
	ts->reset_gpio = NVTTOUCH_RST_PIN;
#endif
	ts->irq_gpio = NVTTOUCH_INT_PIN;
	return 0;
}
#endif

/*******************************************************
Description:
	Novatek touchscreen config and request gpio

return:
	Executive outcomes. 0---succeed. not 0---failed.
*******************************************************/
static inline int nvt_gpio_config(struct nvt_ts_data *ts)
{
	int32_t ret = 0;

#if NVT_TOUCH_SUPPORT_HW_RST
	/* request RST-pin (Output/High) */
	if (gpio_is_valid(ts->reset_gpio)) {
		ret = gpio_request_one(ts->reset_gpio, GPIOF_OUT_INIT_LOW, "NVT-tp-rst");
		if (ret) {
			goto err_request_reset_gpio;
		}
	}
#endif

	/* request INT-pin (Input) */
	if (gpio_is_valid(ts->irq_gpio)) {
		ret = gpio_request_one(ts->irq_gpio, GPIOF_IN, "NVT-int");
		if (ret) {
			goto err_request_irq_gpio;
		}
	}

	return ret;

err_request_irq_gpio:
#if NVT_TOUCH_SUPPORT_HW_RST
	gpio_free(ts->reset_gpio);
err_request_reset_gpio:
#endif
	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen deconfig gpio

return:
	n.a.
*******************************************************/
static inline void nvt_gpio_deconfig(struct nvt_ts_data *ts)
{
	if (gpio_is_valid(ts->irq_gpio))
		gpio_free(ts->irq_gpio);
#if NVT_TOUCH_SUPPORT_HW_RST
	if (gpio_is_valid(ts->reset_gpio))
		gpio_free(ts->reset_gpio);
#endif
}

#define POINT_DATA_LEN 65
/*******************************************************
Description:
	Novatek touchscreen work function.

return:
	n.a.
*******************************************************/
static inline irqreturn_t nvt_ts_work_func(int irq, void *data)
{
	int32_t ret = -1;
	uint8_t point_data[POINT_DATA_LEN + 1 + DUMMY_BYTES] = {0};
	uint32_t position = 0;
	uint32_t input_x = 0;
	uint32_t input_y = 0;
	uint8_t input_id = 0;
	uint8_t press_id[TOUCH_MAX_FINGER_NUM] = {0};
	int32_t i = 0;
	int32_t finger_cnt = 0;

	pm_qos_update_request(&ts->pm_spi_req, 100);

#if WAKEUP_GESTURE
#ifdef CONFIG_PM
	if (ts->dev_pm_suspend && ts->is_gesture_mode) {
		ret = wait_for_completion_timeout(&ts->dev_pm_suspend_completion, msecs_to_jiffies(700));
		if (!ret) {
			return IRQ_HANDLED;
		}
	}
#endif
#endif

	mutex_lock(&ts->lock);

	ret = CTP_SPI_READ(ts->client, point_data, POINT_DATA_LEN + 1);
	if (unlikely(ret < 0)) {
		goto XFER_ERROR;
	}

#if WAKEUP_GESTURE
	if (bTouchIsAwake == 0) {
		input_id = (uint8_t) (point_data[1] >> 3);
		nvt_ts_wakeup_gesture_report(input_id, point_data);
		goto XFER_ERROR;
	}
#endif

	for (i = 0; i < ts->max_touch_num; i++) {
		position = 1 + 6 * i;
		input_id = (uint8_t) (point_data[position + 0] >> 3);

		if ((input_id == 0) || (input_id > ts->max_touch_num))
			continue;

		if (likely(((point_data[position] & 0x07) == 0x01) || ((point_data[position] & 0x07) == 0x02))) {	//finger down (enter & moving)
			input_x = (uint32_t) (point_data[position + 1] << 4) + (uint32_t) (point_data[position + 3] >> 4);
			input_y = (uint32_t) (point_data[position + 2] << 4) + (uint32_t) (point_data[position + 3] & 0x0F);

			press_id[input_id - 1] = 1;
			input_mt_slot(ts->input_dev, input_id - 1);
			input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, true);

			input_report_abs(ts->input_dev, ABS_MT_POSITION_X, input_x);
			input_report_abs(ts->input_dev, ABS_MT_POSITION_Y, input_y);
			input_report_abs(ts->input_dev, ABS_MT_PRESSURE, TOUCH_FORCE_NUM);

			finger_cnt++;
		}
	}

	for (i = 0; i < ts->max_touch_num; i++) {
		if (likely(press_id[i] != 1)) {
			input_mt_slot(ts->input_dev, i);
			input_report_abs(ts->input_dev, ABS_MT_PRESSURE, 0);
			input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, false);
		}
	}

	input_report_key(ts->input_dev, BTN_TOUCH, (finger_cnt > 0));

	input_sync(ts->input_dev);

XFER_ERROR:
	pm_qos_update_request(&ts->pm_spi_req, PM_QOS_DEFAULT_VALUE);

	mutex_unlock(&ts->lock);

	return IRQ_HANDLED;
}


/*******************************************************
Description:
	Novatek touchscreen check chip version trim function.

return:
	Executive outcomes. 0---NVT IC. -1---not NVT IC.
*******************************************************/
static inline int8_t nvt_ts_check_chip_ver_trim(void)
{
	uint8_t buf[8] = {0};
	int32_t retry = 0;
	int32_t list = 0;
	int32_t i = 0;
	int32_t found_nvt_chip = 0;
	int32_t ret = -1;

	//---Check for 5 times---
	for (retry = 5; retry > 0; retry--) {

		nvt_bootloader_reset();

		//---set xdata index to 0x1F600---
		nvt_set_page(0x1F600);

		buf[0] = 0x4E;
		buf[1] = 0x00;
		buf[2] = 0x00;
		buf[3] = 0x00;
		buf[4] = 0x00;
		buf[5] = 0x00;
		buf[6] = 0x00;
		CTP_SPI_READ(ts->client, buf, 7);

		// compare read chip id on supported list
		for (list = 0; list < (sizeof(trim_id_table) / sizeof(struct nvt_ts_trim_id_table)); list++) {
			found_nvt_chip = 0;

			// compare each byte
			for (i = 0; i < NVT_ID_BYTE_MAX; i++) {
				if (trim_id_table[list].mask[i]) {
					if (buf[i + 1] != trim_id_table[list].id[i])
						break;
				}
			}

			if (i == NVT_ID_BYTE_MAX) {
				found_nvt_chip = 1;
			}

			if (found_nvt_chip) {
				ts->mmap = trim_id_table[list].mmap;
				ts->carrier_system = trim_id_table[list].hwinfo->carrier_system;
				ts->hw_crc = trim_id_table[list].hwinfo->hw_crc;
				ret = 0;
				goto out;
			} else {
				ts->mmap = NULL;
				ret = -1;
			}
		}

		msleep(10);
	}

out:
	return ret;
}

#if WAKEUP_GESTURE
/*******************************************************
Description:
	Novatek touchscreen driver get regulator function.

return:
	Executive outcomes. 0---succeed. negative---failed
*******************************************************/
static inline int32_t nvt_ts_get_regulator(bool get)
{
	int32_t ret = 0;

	if (!get) {
		goto put_regulator;
	}

	ts->pwr_vdd = regulator_get(&ts->client->dev, "touch_vddio");
	if (IS_ERR_OR_NULL(ts->pwr_vdd)) {
		ret = PTR_ERR(ts->pwr_vdd);
		goto put_regulator;
	} else {
		if (regulator_count_voltages(ts->pwr_vdd) > 0) {
			ret = regulator_set_voltage(ts->pwr_vdd, 1800000, 1800000);
			if (ret) {
				goto put_regulator;
			}
		}
	}

	ts->pwr_lab = regulator_get(&ts->client->dev, "touch_lab");
	if (IS_ERR_OR_NULL(ts->pwr_lab)) {
		ret = PTR_ERR(ts->pwr_lab);
		goto put_regulator;
	}

	ts->pwr_ibb = regulator_get(&ts->client->dev, "touch_ibb");
	if (IS_ERR_OR_NULL(ts->pwr_ibb)) {
		ret = PTR_ERR(ts->pwr_ibb);
		goto put_regulator;
	}

	return 0;

put_regulator:
	if (ts->pwr_vdd) {
		regulator_put(ts->pwr_vdd);
		ts->pwr_vdd = NULL;
	}

	if (ts->pwr_lab) {
		regulator_put(ts->pwr_lab);
		ts->pwr_lab = NULL;
	}

	if (ts->pwr_ibb) {
		regulator_put(ts->pwr_ibb);
		ts->pwr_ibb = NULL;
	}

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen driver enable regulator function.

return:
	Executive outcomes. 0---succeed. negative---failed
*******************************************************/
static inline int32_t nvt_ts_enable_regulator(bool en)
{
	static bool status = false;
	int32_t ret = 0;

	if (status == en) {
		return 0;
	}
	status = en;

	if (!en) {
		goto disable_ibb_regulator;
	}

	if (ts->pwr_vdd) {
		ret = regulator_enable(ts->pwr_vdd);
		if (ret < 0) {
			goto exit;
		}
	}

	if (ts->pwr_lab) {
		ret = regulator_enable(ts->pwr_lab);
		if (ret < 0) {
			goto disable_vdd_regulator;
		}
	}

	if (ts->pwr_ibb) {
		ret = regulator_enable(ts->pwr_ibb);
		if (ret < 0) {
			goto disable_lab_regulator;
		}
	}

	return 0;

disable_ibb_regulator:
	if (ts->pwr_ibb)
		regulator_disable(ts->pwr_ibb);

disable_lab_regulator:
	if (ts->pwr_lab)
		regulator_disable(ts->pwr_lab);

disable_vdd_regulator:
	if (ts->pwr_vdd)
		regulator_disable(ts->pwr_vdd);

exit:
	return ret;
}
#endif

/*******************************************************
Description:
	Novatek touchscreen driver probe function.

return:
	Executive outcomes. 0---succeed. negative---failed
*******************************************************/
static inline int32_t nvt_ts_probe(struct spi_device *client)
{
	int32_t ret = 0;
#if WAKEUP_GESTURE
	int32_t retry = 0;
#endif

	ts = kzalloc(sizeof(struct nvt_ts_data), GFP_KERNEL);
	if (IS_ERR_OR_NULL(ts)) {
		return -ENOMEM;
	}

	ts->xbuf = (uint8_t *)kzalloc((NVT_TRANSFER_LEN+1), GFP_KERNEL);
	if(IS_ERR_OR_NULL(ts->xbuf)) {
		if (ts) {
			kfree(ts);
			ts = NULL;
		}
		return -ENOMEM;
	}

#ifdef CHECK_TOUCH_VENDOR
	ts->touch_vendor_id = touch_vendor_id;
	switch(ts->touch_vendor_id) {
	case TP_VENDOR_TIANMA:
		memcpy(ts->boot_update_firmware_name, BOOT_UPDATE_TIANMA_FIRMWARE_NAME, sizeof(BOOT_UPDATE_TIANMA_FIRMWARE_NAME));
		memcpy(ts->mp_update_firmware_name, MP_UPDATE_TIANMA_FIRMWARE_NAME, sizeof(MP_UPDATE_TIANMA_FIRMWARE_NAME));
		break;
	case TP_VENDOR_EBBG:
		memcpy(ts->boot_update_firmware_name, BOOT_UPDATE_EBBG_FIRMWARE_NAME, sizeof(BOOT_UPDATE_EBBG_FIRMWARE_NAME));
		memcpy(ts->mp_update_firmware_name, MP_UPDATE_EBBG_FIRMWARE_NAME, sizeof(MP_UPDATE_EBBG_FIRMWARE_NAME));
		break;
	default:
		goto err_vendor_check;
	}
#else
	memcpy(ts->boot_update_firmware_name, BOOT_UPDATE_FIRMWARE_NAME, sizeof(BOOT_UPDATE_FIRMWARE_NAME));
	memcpy(ts->mp_update_firmware_name, MP_UPDATE_FIRMWARE_NAME, sizeof(MP_UPDATE_FIRMWARE_NAME));
#endif

	ts->client = client;
	spi_set_drvdata(client, ts);

	//---prepare for spi parameter---
	if (ts->client->master->flags & SPI_MASTER_HALF_DUPLEX) {
		ret = -EIO;
		goto err_ckeck_full_duplex;
	}
	ts->client->bits_per_word = 8;
	ts->client->mode = SPI_MODE_0;

	ret = spi_setup(ts->client);
	if (ret < 0) {
		goto err_spi_setup;
	}

	//---parse dts---
	ret = nvt_parse_dt(&client->dev);
	if (ret) {
		goto err_spi_setup;
	}

	//---config regulator---
#if WAKEUP_GESTURE
	ret = nvt_ts_get_regulator(true);
	if (ret < 0) {
		goto err_get_regulator;
	}

	ret = nvt_ts_enable_regulator(true);
	if (ret < 0) {
		goto err_enable_regulator;
	}
#endif

	//---request and config GPIOs---
	ret = nvt_gpio_config(ts);
	if (ret) {
		goto err_gpio_config_failed;
	}

	mutex_init(&ts->lock);
	mutex_init(&ts->xbuf_lock);

	//---eng reset before TP_RESX high
	nvt_eng_reset();

#if NVT_TOUCH_SUPPORT_HW_RST
	gpio_set_value(ts->reset_gpio, 1);
#endif

	// need 10ms delay after POR(power on reset)
	msleep(10);

	//---check chip version trim---
	ret = nvt_ts_check_chip_ver_trim();
	if (ret) {
		ret = -EINVAL;
		goto err_chipvertrim_failed;
	}

	ts->abs_x_max = TOUCH_DEFAULT_MAX_WIDTH;
	ts->abs_y_max = TOUCH_DEFAULT_MAX_HEIGHT;

	//---allocate input device---
	ts->input_dev = input_allocate_device();
	if (ts->input_dev == NULL) {
		ret = -ENOMEM;
		goto err_input_dev_alloc_failed;
	}

	ts->max_touch_num = TOUCH_MAX_FINGER_NUM;

	ts->int_trigger_type = INT_TRIGGER_TYPE;

	//---set input device info.---
	ts->input_dev->evbit[0] = BIT_MASK(EV_SYN) | BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS) ;
	ts->input_dev->keybit[BIT_WORD(BTN_TOUCH)] = BIT_MASK(BTN_TOUCH);
	ts->input_dev->propbit[0] = BIT(INPUT_PROP_DIRECT);

	input_mt_init_slots(ts->input_dev, ts->max_touch_num, 0);

	input_set_abs_params(ts->input_dev, ABS_MT_PRESSURE, 0, TOUCH_FORCE_NUM, 0, 0);    //pressure = TOUCH_FORCE_NUM

#if TOUCH_MAX_FINGER_NUM > 1
	input_set_abs_params(ts->input_dev, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);    //area = 255
	input_set_abs_params(ts->input_dev, ABS_MT_POSITION_X, 0, ts->abs_x_max - 1, 0, 0);
	input_set_abs_params(ts->input_dev, ABS_MT_POSITION_Y, 0, ts->abs_y_max - 1, 0, 0);
#endif //TOUCH_MAX_FINGER_NUM > 1

#if WAKEUP_GESTURE
	ts->input_dev->event =nvt_gesture_switch;
	for (retry = 0; retry < (sizeof(gesture_key_array) / sizeof(gesture_key_array[0])); retry++) {
		input_set_capability(ts->input_dev, EV_KEY, gesture_key_array[retry]);
	}
#ifdef CONFIG_TOUCHSCREEN_COMMON
	tp_common_set_double_tap_ops(&double_tap_ops);
#endif
#endif

	sprintf(ts->phys, "input/ts");
	ts->input_dev->name = NVT_TS_NAME;
	ts->input_dev->phys = ts->phys;
	ts->input_dev->id.bustype = BUS_SPI;

	//---register input device---
	ret = input_register_device(ts->input_dev);
	if (ret) {
		goto err_input_register_device_failed;
	}

	//---set int-pin & request irq---
	client->irq = gpio_to_irq(ts->irq_gpio);
	if (client->irq) {
		ts->irq_enabled = true;
		ret = request_threaded_irq(client->irq, NULL, nvt_ts_work_func,
				ts->int_trigger_type | IRQF_ONESHOT | IRQF_PERF_AFFINE, NVT_SPI_NAME, ts);
		if (ret != 0) {
			goto err_int_request_failed;
		} else {
			nvt_irq_enable(false);
		}

		ts->pm_spi_req.type = PM_QOS_REQ_AFFINE_IRQ;
		ts->pm_spi_req.irq = geni_spi_get_master_irq(client);
		irq_set_perf_affinity(ts->pm_spi_req.irq, IRQF_PERF_AFFINE);
		pm_qos_add_request(&ts->pm_spi_req, PM_QOS_CPU_DMA_LATENCY,
			PM_QOS_DEFAULT_VALUE);
	}

#if WAKEUP_GESTURE
	device_init_wakeup(&ts->input_dev->dev, 1);
#endif

#if BOOT_UPDATE_FIRMWARE
	nvt_fwu_wq = alloc_workqueue("nvt_fwu_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!nvt_fwu_wq) {
		ret = -ENOMEM;
		goto err_create_nvt_fwu_wq_failed;
	}
	INIT_DELAYED_WORK(&ts->nvt_fwu_work, Boot_Update_Firmware);
	// please make sure boot update start after display reset(RESX) sequence
	queue_delayed_work(nvt_fwu_wq, &ts->nvt_fwu_work, msecs_to_jiffies(5000));
#endif

#if WAKEUP_GESTURE
	//[IC NT36672A] LCD_RESET always keep high
	//In the Xiaomi C3J project, IOVCC will not be powered off when the screen is off.
	//Pulling LCD_RESET high causes the IC to go into deep sleep(when screen off).
	set_lcd_reset_gpio_keep_high(true);//(Only xiaomi C3J project && Only NT36672A)
#endif

	ts->workqueue = create_singlethread_workqueue("nvt_ts_workqueue");
	if (!ts->workqueue) {
		ret = -ENOMEM;
		goto err_create_nvt_ts_workqueue_failed;
	}
	INIT_WORK(&ts->resume_work, nvt_ts_resume_work);
	ts->drm_notif.notifier_call = nvt_drm_notifier_callback;
	ret = msm_drm_register_client(&ts->drm_notif);
	if(ret) {
		goto err_register_drm_notif_failed;
	}

	bTouchIsAwake = 1;

	nvt_irq_enable(true);

#ifdef CONFIG_PM
	ts->dev_pm_suspend = false;
	init_completion(&ts->dev_pm_suspend_completion);
#endif

	pm_runtime_enable(&ts->client->dev);

	set_touchpanel_recovery_callback(nvt_ts_recovery_callback);

	driver_ready = true;

	return 0;

err_create_nvt_ts_workqueue_failed:
	if (ts->workqueue)
		destroy_workqueue(ts->workqueue);
	msm_drm_unregister_client(&ts->drm_notif);
err_register_drm_notif_failed:
#if BOOT_UPDATE_FIRMWARE
	if (nvt_fwu_wq) {
		cancel_delayed_work_sync(&ts->nvt_fwu_work);
		destroy_workqueue(nvt_fwu_wq);
		nvt_fwu_wq = NULL;
	}
err_create_nvt_fwu_wq_failed:
#endif
#if WAKEUP_GESTURE
	device_init_wakeup(&ts->input_dev->dev, 0);
#endif
	free_irq(client->irq, ts);
err_int_request_failed:
	input_unregister_device(ts->input_dev);
	ts->input_dev = NULL;
err_input_register_device_failed:
	if (ts->input_dev) {
		input_free_device(ts->input_dev);
		ts->input_dev = NULL;
	}
err_input_dev_alloc_failed:
err_chipvertrim_failed:
	mutex_destroy(&ts->xbuf_lock);
	mutex_destroy(&ts->lock);
	nvt_gpio_deconfig(ts);
err_gpio_config_failed:
#if WAKEUP_GESTURE
	nvt_ts_enable_regulator(false);
err_enable_regulator:
	nvt_ts_get_regulator(false);
err_get_regulator:
#endif
err_spi_setup:
err_ckeck_full_duplex:
	spi_set_drvdata(client, NULL);
#ifdef CHECK_TOUCH_VENDOR
err_vendor_check:
#endif
	if (ts->xbuf) {
		kfree(ts->xbuf);
		ts->xbuf = NULL;
	}
	if (ts) {
		kfree(ts);
		ts = NULL;
	}
	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen driver release function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static inline int32_t nvt_ts_remove(struct spi_device *client)
{
	if (ts->workqueue)
		destroy_workqueue(ts->workqueue);
	msm_drm_unregister_client(&ts->drm_notif);

	pm_qos_remove_request(&ts->pm_spi_req);

#if BOOT_UPDATE_FIRMWARE
	if (nvt_fwu_wq) {
		cancel_delayed_work_sync(&ts->nvt_fwu_work);
		destroy_workqueue(nvt_fwu_wq);
		nvt_fwu_wq = NULL;
	}
#endif

#if WAKEUP_GESTURE
	device_init_wakeup(&ts->input_dev->dev, 0);
#endif

	nvt_irq_enable(false);
	free_irq(client->irq, ts);

	mutex_destroy(&ts->xbuf_lock);
	mutex_destroy(&ts->lock);

#if WAKEUP_GESTURE
	nvt_ts_enable_regulator(false);
	nvt_ts_get_regulator(false);
#endif

	nvt_gpio_deconfig(ts);

	if (ts->input_dev) {
		input_unregister_device(ts->input_dev);
		ts->input_dev = NULL;
	}

	spi_set_drvdata(client, NULL);

	if (ts->xbuf) {
		kfree(ts->xbuf);
		ts->xbuf = NULL;
	}

	if (ts) {
		kfree(ts);
		ts = NULL;
	}

	return 0;
}

static inline void nvt_ts_shutdown(struct spi_device *client)
{
	nvt_irq_enable(false);

	if (ts->workqueue)
		destroy_workqueue(ts->workqueue);
	msm_drm_unregister_client(&ts->drm_notif);

#if BOOT_UPDATE_FIRMWARE
	if (nvt_fwu_wq) {
		cancel_delayed_work_sync(&ts->nvt_fwu_work);
		destroy_workqueue(nvt_fwu_wq);
		nvt_fwu_wq = NULL;
	}
#endif

#if WAKEUP_GESTURE
	device_init_wakeup(&ts->input_dev->dev, 0);
#endif
}

/*******************************************************
Description:
	Novatek touchscreen driver suspend function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static inline int32_t nvt_ts_suspend(struct device *dev)
{
	uint8_t buf[4] = {0};
	uint32_t i = 0;

	if (!bTouchIsAwake) {
		return 0;
	}

#if WAKEUP_GESTURE
	//[IC NT36672A] LCD_RESET always keep high
	//In the Xiaomi C3J project, IOVCC will not be powered off when the screen is off.
	//Pulling LCD_RESET high causes the IC to go into deep sleep(when screen off).
	set_lcd_reset_gpio_keep_high(true);//(Only xiaomi C3J project && Only NT36672A)

	if (!ts->is_gesture_mode)
		nvt_irq_enable(false);
#else
	nvt_irq_enable(false);
#endif

	mutex_lock(&ts->lock);

	bTouchIsAwake = 0;

#if WAKEUP_GESTURE
	if (ts->is_gesture_mode) {
		//---write command to enter "wakeup gesture mode"---
		buf[0] = EVENT_MAP_HOST_CMD;
		buf[1] = 0x13;
		CTP_SPI_WRITE(ts->client, buf, 2);
		enable_irq_wake(ts->client->irq);
	} else {
		//---write command to enter "deep sleep mode"---
		buf[0] = EVENT_MAP_HOST_CMD;
		buf[1] = 0x11;
		CTP_SPI_WRITE(ts->client, buf, 2);
	}
#else // WAKEUP_GESTURE
	//---write command to enter "deep sleep mode"---
	buf[0] = EVENT_MAP_HOST_CMD;
	buf[1] = 0x11;
	CTP_SPI_WRITE(ts->client, buf, 2);
#endif // WAKEUP_GESTURE

	mutex_unlock(&ts->lock);

	/* release all touches */
	for (i = 0; i < ts->max_touch_num; i++) {
		input_mt_slot(ts->input_dev, i);
		input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, 0);
		input_report_abs(ts->input_dev, ABS_MT_PRESSURE, 0);
		input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 0);
	}
	input_report_key(ts->input_dev, BTN_TOUCH, 0);
	input_sync(ts->input_dev);

	msleep(50);

	return 0;
}

/*******************************************************
Description:
	Novatek touchscreen driver resume function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static inline int32_t nvt_ts_resume(struct device *dev)
{
	if (bTouchIsAwake) {
		return 0;
	}

	mutex_lock(&ts->lock);

	// please make sure display reset(RESX) sequence and mipi dsi cmds sent before this
#if NVT_TOUCH_SUPPORT_HW_RST
	gpio_set_value(ts->reset_gpio, 1);
#endif
	if (!nvt_update_firmware(ts->boot_update_firmware_name)) {
		nvt_check_fw_reset_state(RESET_STATE_REK);
	}

#if WAKEUP_GESTURE
	if (!ts->is_gesture_mode)
		nvt_irq_enable(true);
#else
	nvt_irq_enable(true);
#endif

	bTouchIsAwake = 1;

	mutex_unlock(&ts->lock);

#if WAKEUP_GESTURE
	if (ts->delay_gesture) {
		ts->delay_gesture = false;
	}
#endif

	return 0;
}

static inline void nvt_ts_resume_work(struct work_struct *work)
{
	nvt_ts_resume(&ts->client->dev);
}

static inline int nvt_drm_notifier_callback(struct notifier_block *self, unsigned long event, void *data)
{
	struct msm_drm_notifier *evdata = data;
	int *blank;
	struct nvt_ts_data *ts =
		container_of(self, struct nvt_ts_data, drm_notif);

	if (!evdata || (evdata->id != 0))
		return 0;

	if (evdata->data && ts) {
		blank = evdata->data;
		if (event == MSM_DRM_EARLY_EVENT_BLANK) {
			if (*blank == MSM_DRM_BLANK_POWERDOWN) {
				cancel_work_sync(&ts->resume_work);
				nvt_ts_suspend(&ts->client->dev);
			}
		} else if (event == MSM_DRM_EVENT_BLANK) {
			if (*blank == MSM_DRM_BLANK_UNBLANK) {
				//nvt_ts_resume(&ts->client->dev);
				queue_work(ts->workqueue, &ts->resume_work);
			}
		}
	}
	return 0;
}

#ifdef CONFIG_PM
static inline int nvt_pm_suspend(struct device *dev)
{
	struct nvt_ts_data *ts = dev_get_drvdata(dev);

	ts->dev_pm_suspend = true;
	reinit_completion(&ts->dev_pm_suspend_completion);

	return 0;
}

static inline int nvt_pm_resume(struct device *dev)
{
	struct nvt_ts_data *ts = dev_get_drvdata(dev);

	ts->dev_pm_suspend = false;
	complete(&ts->dev_pm_suspend_completion);

	return 0;
}

static const struct dev_pm_ops nvt_dev_pm_ops = {
	.suspend = nvt_pm_suspend,
	.resume = nvt_pm_resume,
};
#endif

static const struct spi_device_id nvt_ts_id[] = {
	{ NVT_SPI_NAME, 0 },
	{ }
};

#ifdef CONFIG_OF
static struct of_device_id nvt_match_table[] = {
	{ .compatible = "novatek,NVT-ts-spi",},
	{ },
};
#endif

static struct spi_driver nvt_spi_driver = {
	.probe		= nvt_ts_probe,
	.remove		= nvt_ts_remove,
	.shutdown	= nvt_ts_shutdown,
	.id_table	= nvt_ts_id,
	.driver = {
		.name	= NVT_SPI_NAME,
		.owner	= THIS_MODULE,
#ifdef CONFIG_PM
		.pm = &nvt_dev_pm_ops,
#endif
#ifdef CONFIG_OF
		.of_match_table = nvt_match_table,
#endif
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

/*******************************************************
Description:
	Driver Install function.

return:
	Executive Outcomes. 0---succeed. not 0---failed.
********************************************************/
static inline int32_t __init nvt_driver_init(void)
{
	int32_t ret = 0;

#ifdef CHECK_TOUCH_VENDOR
	//Check TP vendor
	if (IS_ERR_OR_NULL(saved_command_line)){
		ret = -ENOMEM;
		goto err_driver;
	} else {
		if (strstr(saved_command_line,"tianma") != NULL) {
			touch_vendor_id = TP_VENDOR_TIANMA;
		} else if (strstr(saved_command_line,"shenchao") != NULL) {
			touch_vendor_id = TP_VENDOR_EBBG;
		} else {
			touch_vendor_id = TP_VENDOR_UNKNOW;
			ret = -ENODEV;
			goto err_driver;
		}
	}
	//Check android mode
	if (strstr(saved_command_line, "androidboot.mode=charger") != NULL) {
		ret = -ENODEV;
		goto err_driver;
	}
#endif
	//---add spi driver---
	ret = spi_register_driver(&nvt_spi_driver);
	if (ret) {
		goto err_driver;
	}

err_driver:
	return ret;
}

/*******************************************************
Description:
	Driver uninstall function.

return:
	n.a.
********************************************************/
static inline void __exit nvt_driver_exit(void)
{
	spi_unregister_driver(&nvt_spi_driver);
}

//late_initcall(nvt_driver_init);
module_init(nvt_driver_init);
module_exit(nvt_driver_exit);

MODULE_DESCRIPTION("Novatek Touchscreen Driver");
MODULE_LICENSE("GPL");
