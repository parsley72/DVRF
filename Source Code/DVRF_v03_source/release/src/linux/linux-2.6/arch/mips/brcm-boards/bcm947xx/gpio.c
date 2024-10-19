/*
 * GPIO char driver
 *
 * Copyright (c) 2010 Broadcom Corporation 
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: gpio.c,v 1.7 2010/12/29 06:06:47 gavin.ke Exp $
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>
#include <linux/timer.h>

#include <typedefs.h>
#include <bcmutils.h>
#include <siutils.h>
#include <bcmdevs.h>
#include <bcmnvram.h>
#include <linux/sysctl.h>
#include <linux/ctype.h>

//wuzh add wrt600n support
#include "../../../../../../cy_conf.h"

//wuzh add for USB LED control 2008-2-22
#define USB_LED_GPIO 0
#define POWER_LED_GPIO 5

#define USB_ENABLE_GPIO 4

//wuzh add for USB LED 2008-2-22
static int gpio_initialized = 0;
//Jemmy add 
static uint32_t power_pulse_time = 7; //zhaoguang modify the blink frequency of Power LED to 0.7Hz on 20101217 

static si_t *gpio_sih;
static int gpio_major;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
static struct class *gpiodev_class = NULL;
#else
static devfs_handle_t gpio_dir;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
static struct {
	char *name;
	 struct class * handle;
} gpio_file[] = {
	{ "gpio_in", NULL },
	{ "gpio_out", NULL },
	{ "gpio_outen", NULL },
	{ "gpio_control", NULL }
};
#else
static struct {
	char *name;
	devfs_handle_t handle;
} gpio_file[] = {
	{ "in", NULL },
	{ "out", NULL },
	{ "outen", NULL },
	{ "control", NULL }
};
#endif

/*-- begin wuzh add 2008-7-1 --*/
#define ON 1
#define OFF 0
static unsigned int diag = 1;
static bool idle = 0;
struct timer_list timer;
static bool flag = 0;

static struct ctl_table_header *diag_sysctl_header;
/*static ctl_table mytable[] = {
         { 1, "blink_diag_led",
           &diag, sizeof(diag),
           0644, NULL,
           proc_dointvec },
         { 0 }
};*/

static ctl_table mytable[] = {
	{
                //.ctl_name       = CTL_UNNUMBERED,
                .procname		= "blink_diag_led",
                .data			= &diag,
                .maxlen			= sizeof(diag),
                .mode			= 0644,
                .proc_handler	= &proc_dointvec
        },
        {}
};
/*-- end wuzh add 2008-7-1 --*/

static int
gpio_open(struct inode *inode, struct file * file)
{
	if (MINOR(inode->i_rdev) > ARRAYSIZE(gpio_file))
		return -ENODEV;

	MOD_INC_USE_COUNT;
	return 0;
}

static int
gpio_release(struct inode *inode, struct file * file)
{
	MOD_DEC_USE_COUNT;
	return 0;
}

void usb_led(int act)
{
	u32 val_in, val_out, val_en, val_ctrl;
	u32 ctr_mask, out_mask;
	u32 usb_led_gpio;

	if(!gpio_initialized) return ;

	usb_led_gpio = USB_LED_GPIO;

	if (nvram_match("boardtype", "0x04cf")){
		/* adjust for WRT610N v2 */
		usb_led_gpio = 7;
		act = act?0:1;
	}
	else if (nvram_match("boardtype", "0x0550")){
		/* adjust for Broadcom reference board */
		return; /* Broadcom reference board has not USB LED */
	}
	else if (nvram_match("boardtype", "0xC550")){
		/* adjust for E1550 */
		return; /* E1550 has not USB LED */
	}
	else if (nvram_match("boardtype", "0xF550")){
		/* adjust for E2500 */
		return; /* E2500 has not USB LED */
	}
	else if (nvram_match("boardtype", "0xF52A")){
		/* adjust for E3200 */
		return; /* E3200 has not USB LED */
	}

	val_in = si_gpioin(gpio_sih);
	val_out = si_gpioout(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);
	val_en = si_gpioouten(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);
	val_ctrl = si_gpiocontrol(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);

	ctr_mask= ~(1 << usb_led_gpio);
	out_mask= (1 << usb_led_gpio);
		
	si_gpioouten(gpio_sih, ~0, val_en | out_mask, GPIO_DRV_PRIORITY);
	si_gpiocontrol(gpio_sih, ~0, val_ctrl & ctr_mask, GPIO_DRV_PRIORITY);

	if (!act) {
		si_gpioout(gpio_sih, ~0, val_out | out_mask, GPIO_DRV_PRIORITY);
	} else{ 
		si_gpioout(gpio_sih, ~0, val_out & ctr_mask, GPIO_DRV_PRIORITY);
	}

	return;
}

void usb_enable(int act)
{
	u32 val_in, val_out, val_en, val_ctrl;
	u32 ctr_mask, out_mask;
	u32 usb_enable_gpio;

	if(!gpio_initialized) return ;

	usb_enable_gpio = USB_ENABLE_GPIO;

	if (nvram_match("boardtype", "0x04cf")){
		/* adjust for WRT610N v2 */
		usb_enable_gpio = 12;
		return ; //no enable pin for WRT610Nv2
	}
	else if (nvram_match("boardtype", "0x0550")){
		/* adjust for Broadcom reference board */
		return ; //no enable pin for Broadcom reference board
	}
	else if (nvram_match("boardtype", "0xC550")){
		/* adjust for E1550 */
		return ; //no enable pin for E1550
	}
	else if (nvram_match("boardtype", "0xF550")){
		/* adjust for E2500 */
		return ; //no enable pin for E2500
	}
	else if (nvram_match("boardtype", "0xF52A")){
		/* adjust for E3200 */
		return ; //no enable pin for E3200
	}

	val_in = si_gpioin(gpio_sih);
	val_out = si_gpioout(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);
	val_en = si_gpioouten(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);
	val_ctrl = si_gpiocontrol(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);

	ctr_mask= ~(1 << usb_enable_gpio);
	out_mask= (1 << usb_enable_gpio);
		
	si_gpioouten(gpio_sih, ~0, val_en | out_mask, GPIO_DRV_PRIORITY);
	si_gpiocontrol(gpio_sih, ~0, val_ctrl & ctr_mask, GPIO_DRV_PRIORITY);

	if (act) {
		si_gpioout(gpio_sih, ~0, val_out | out_mask, GPIO_DRV_PRIORITY);
	} else{ 
		si_gpioout(gpio_sih, ~0, val_out & ctr_mask, GPIO_DRV_PRIORITY);
	}

	return;
}
//wuzh end

static ssize_t
gpio_read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
	u32 val;

	switch (MINOR(file->f_dentry->d_inode->i_rdev)) {
	case 0:
		val = si_gpioin(gpio_sih);
		break;
	case 1:
		val = si_gpioout(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);
		break;
	case 2:
		val = si_gpioouten(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);
		break;
	case 3:
		val = si_gpiocontrol(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);
		break;
	default:
		return -ENODEV;
	}

	if (put_user(val, (u32 *) buf))
		return -EFAULT;

	return sizeof(val);
}

static ssize_t
gpio_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
	u32 val;

	if (get_user(val, (u32 *) buf))
		return -EFAULT;

	switch (MINOR(file->f_dentry->d_inode->i_rdev)) {
	case 0:
		return -EACCES;
	case 1:
		si_gpioout(gpio_sih, ~0, val, GPIO_DRV_PRIORITY);
		break;
	case 2:
		si_gpioouten(gpio_sih, ~0, val, GPIO_DRV_PRIORITY);
		break;
	case 3:
		si_gpiocontrol(gpio_sih, ~0, val, GPIO_DRV_PRIORITY);
		break;
	default:
		return -ENODEV;
	}

	return sizeof(val);
}

/*-- begin wuzh add 2008-7-1 --*/
void
start_flash(int type)
{
#if 0
        int gpio = POWER_LED_GPIO;
 
	//if (nvram_match("boardtype", "0x04cf")){
		//gpio = 6;
	//	return; //undefined this gpio in wrt610nv2
	//}

        si_gpioouten(gpio_sih, ((uint32) 1 << gpio), ((uint32) 1 << gpio), GPIO_HI_PRIORITY);
 
        if(type == OFF) {
		//printk("%s: flash power led off!\n",__FUNCTION__);
                si_gpioout(gpio_sih, ((uint32) 1 << gpio), 0, GPIO_HI_PRIORITY);
        }
        else {
		//printk("%s: flash power led on!\n",__FUNCTION__);
                si_gpioout(gpio_sih, ((uint32) 1 << gpio), ((uint32) 1 << gpio), GPIO_HI_PRIORITY);
        }
#else
	u32 val_out, val_en, val_ctrl, real_out;
	u32 ctr_mask, out_mask;

	val_out = si_gpioout(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);
	val_en = si_gpioouten(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);
	val_ctrl = si_gpiocontrol(gpio_sih, 0, 0, GPIO_DRV_PRIORITY);

	if (nvram_match("boardtype", "0x04cf")){
		/* adjust for WRT610N v2 */
		return; //undefined this gpio in wrt610nv2
	}
	else if (nvram_match("boardtype", "0x0550")){
		/* adjust for Broadcom reference board */
		//GPIO 0, 3, 5
		ctr_mask= ~(1 | (1 << 3) | (1 << 5));
		out_mask= (1 | (1 << 3) | (1 << 5));
		real_out = ~(1 << 3);
	}
	else if (nvram_match("boardtype", "0xC550")){
		/* adjust for E1550 */
		//GPIO 6, 10
		ctr_mask= ~((1 << 6) | (1 << 10));
		out_mask= ((1 << 6) | (1 << 10));
		real_out = ~(1 << 6);
	}
	else if (nvram_match("boardtype", "0xF550")){
		/* adjust for E2500 */
		//GPIO 0, 3, 5
		ctr_mask= ~(1 | (1 << 3) | (1 << 5));
		out_mask= (1 | (1 << 3) | (1 << 5));
		real_out = ~(1 << 3);
	}
	else if (nvram_match("boardtype", "0xF52A")){
		/* adjust for E3200 */
		//GPIO 0, 3, 5
		ctr_mask= ~(1 | (1 << 3) | (1 << 5));
		out_mask= (1 | (1 << 3) | (1 << 5));
		real_out = ~(1 << 3);
	}
		
	si_gpioouten(gpio_sih, ~0, val_en | out_mask, GPIO_DRV_PRIORITY);
	si_gpiocontrol(gpio_sih, ~0, val_ctrl & ctr_mask, GPIO_DRV_PRIORITY);

        if(type == ON) {
		//si_gpioout(gpio_sih, ~0, val_out | out_mask, GPIO_DRV_PRIORITY);
		si_gpioout(gpio_sih, ~0, ((val_out | out_mask) & real_out), GPIO_DRV_PRIORITY);
	} else{ 
		si_gpioout(gpio_sih, ~0, val_out | out_mask, GPIO_DRV_PRIORITY);
	}

#endif
}

static void diag_loop(ulong data)
{
//	static int flash_count = 0;

	if(diag == 0) {
                if(!idle) {
                        start_flash(ON);
                        idle = 1;
                }
        }
        else
                idle = 0;
 
        if(!idle) {
                if(flag == 0) {
                        start_flash(OFF);
                        flag = 1;
                }
                else {
                        start_flash(ON);
                        flag = 0;
                }
        }
 
        timer.function = diag_loop;
	//Jemmy change the power led flash timer to 0.7 second 2010.08.06
        //timer.expires = jiffies + 20;
        //timer.expires = jiffies + 300;
        timer.expires = jiffies + power_pulse_time*10; 
/*
	if (flag == 1)
        	timer.expires = jiffies + 50; 
	else
        	timer.expires = jiffies + 90;
*/
/*
	if (flag == 1)
	{
		if (flash_count == 0)
        		timer.expires = jiffies + 60; 
		else			
        		timer.expires = jiffies + 10;
	}else{
		flash_count++;
		if (flash_count < 3)
        		timer.expires = jiffies + 10;
		else{
			flash_count = 0;
        		timer.expires = jiffies + 150;
		}
	}
*/
        add_timer(&timer);
}

static void diag_show(void)
{
	printk("Register DIAG LED in /proc/sys/diag_blink.\n");
	diag_sysctl_header = register_sysctl_table(mytable);

	start_flash(ON);
        timer.function = diag_loop;
        //timer.expires = jiffies + 90;
        timer.expires = jiffies + power_pulse_time*10;
        add_timer(&timer);
}
/*-- end wuzh add 2008-7-1 --*/

static struct file_operations gpio_fops = {
	owner:		THIS_MODULE,
	open:		gpio_open,
	release:	gpio_release,
	read:		gpio_read,
	write:		gpio_write,
};

__inline static int atoi(char *s) 
{
	int i=0;
	while (isdigit(*s)) {
		i = i*10 + *(s++) - '0';
	}
	return i;
}

static int __init
gpio_init(void)
{
	int i;

	if (!(gpio_sih = si_kattach(SI_OSH)))
		return -ENODEV;

	si_gpiosetcore(gpio_sih);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
	if ((gpio_major = register_chrdev(0, "gpio", &gpio_fops)) < 0)
		return gpio_major;

#if 0
	gpiodev_class = class_create(THIS_MODULE, "gpio");
	if (IS_ERR(gpiodev_class)) {
		printk("Error creating gpio class\n");
		return -1;
	}

	/* Add the device gpio0 */
	class_device_create(gpiodev_class, NULL, MKDEV(gpio_major, 0), NULL, "gpio");
#endif

	for (i = 0; i < ARRAYSIZE(gpio_file); i++) 
	{
		gpio_file[i].handle = class_create(THIS_MODULE, gpio_file[i].name);
		if (IS_ERR(gpio_file[i].handle)) 
		{
			printk("Error creating gpio class\n");
			return -1;
		}
		class_device_create(gpio_file[i].handle, NULL, MKDEV(gpio_major, i), NULL, gpio_file[i].name);
	}
#else
	if ((gpio_major = devfs_register_chrdev(0, "gpio", &gpio_fops)) < 0)
		return gpio_major;

	gpio_dir = devfs_mk_dir(NULL, "gpio", NULL);

	for (i = 0; i < ARRAYSIZE(gpio_file); i++) {
		gpio_file[i].handle = devfs_register(gpio_dir,
						     gpio_file[i].name,
						     DEVFS_FL_DEFAULT, gpio_major, i,
						     S_IFCHR | S_IRUGO | S_IWUGO,
						     &gpio_fops, NULL);
	}
#endif

	//wuzh add 2008-2-22
	gpio_initialized = 1;

	if (nvram_invmatch("power_pulse_time", ""))
		power_pulse_time = atoi(nvram_safe_get("power_pulse_time"));
	printk("%s: power pulse time %d\n", __FUNCTION__, power_pulse_time);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
	init_timer(&timer);
#endif

	diag_show();

	return 0;
}

static void __exit
gpio_exit(void)
{
	int i;

	//wuzh add 2008-222
	gpio_initialized = 0;
	unregister_sysctl_table(diag_sysctl_header);
       	del_timer(&timer);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
#if 1
	if (gpiodev_class != NULL) {
		class_device_destroy(gpiodev_class, MKDEV(gpio_major, 0));
		class_destroy(gpiodev_class);
	}

	gpiodev_class = NULL;


	for (i = 0; i < ARRAYSIZE(gpio_file); i++) 
	{
		if (gpio_file[i].handle != NULL) 
		{
			class_device_destroy(gpio_file[i].handle, MKDEV(gpio_major, i));
			class_destroy(gpio_file[i].handle);
		}

		gpiodev_class = NULL;
	}

	if (gpio_major >= 0)
		unregister_chrdev(gpio_major, "gpio");
#endif
#else
	for (i = 0; i < ARRAYSIZE(gpio_file); i++)
		devfs_unregister(gpio_file[i].handle);
	devfs_unregister(gpio_dir);
	devfs_unregister_chrdev(gpio_major, "gpio");
#endif
	si_detach(gpio_sih);
}

module_init(gpio_init);
module_exit(gpio_exit);

EXPORT_SYMBOL(usb_led);
