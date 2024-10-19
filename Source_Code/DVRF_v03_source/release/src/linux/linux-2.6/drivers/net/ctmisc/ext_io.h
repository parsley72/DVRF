#if 0
#include <asm/ioctl.h>

#define EXTIO_IOC_MAGIC 'x'

#define EXTIO_IOCRESET _IO(EXTIO_IOC_MAGIC, 0)
#define EXTIO_IOCSFUNCTION _IOW(EXTIO_IOC_MAGIC, 1, int)
#define EXTIO_IOCGOUTLEN _IOR(EXTIO_IOC_MAGIC, 2, int)
#define EXTIO_IOC_MAXNR 2

#define EXTERNAL_IF_BASE	0x1A000000
#define ASYNC_IF_BASE		0x1000000

/*
	0~2 bit -> WAN LED
	3~5 bit -> internet LED
*/
#define WAN_LED			0xc7
#define INTERNET_LED		0xf8

/*
	color of LED
*/
#define ILED_SOLID_GREEN	0x03
#define ILED_OFF		0x07
#define ILED_SOLID_AMBER	0x04
#define WLED_FLASHING_GREEN	0x30

#define GOT_IP                  0x01
#define RELEASE_IP              0x02
#define GET_IP_ERROR            0x03
#define RELEASE_WAN_CONTROL     0x04
#else

#include <asm/ioctl.h>
#include <asm/io.h>

#define EXTIO_IOC_MAGIC 'x'

#define EXTIO_IOCRESET _IO(EXTIO_IOC_MAGIC, 0)
#define EXTIO_IOCSFUNCTION _IOW(EXTIO_IOC_MAGIC, 1, int)
#define EXTIO_IOCGOUTLEN _IOR(EXTIO_IOC_MAGIC, 2, int)
#define EXTIO_IOC_MAXNR 2

#define EXTERNAL_IF_BASE	0x1A000000
#define ASYNC_IF_BASE		0x1000000

/*
	0~2 bit -> WAN LED
	3~5 bit -> internet LED
*/
#define WAN_LED			0xc7
#define INTERNET_LED		0xf8

/*
	color of LED
*/
#define ILED_SOLID_GREEN	0x03
#define ILED_OFF		0x07
#define ILED_SOLID_AMBER	0x04
#define WLED_FLASHING_GREEN	0x30

#define GOT_IP                  0x01
#define RELEASE_IP              0x02
#define GET_IP_ERROR            0x03
#define RELEASE_WAN_CONTROL     0x04
#define USB_DATA_ACCESS		0x05	//For WRTSL54GS
#define USB_CONNECT		0x06	//For WRTSL54GS
#define USB_DISCONNECT		0x07	//For WRTSL54GS

//wuzh add for USB LED control 2008-2-22
#define START_LED               0x1
#define STOP_LED                0x0
extern void usb_led(int act);

#define USB_SET_LED(cmd) \
{ \
	switch(cmd) \
	{ \
		case USB_DATA_ACCESS: \
			break; \
		case USB_CONNECT: \
			usb_led(START_LED);\
			break; \
		case USB_DISCONNECT: \
			usb_led(STOP_LED);\
			break; \
	} \
}

//wuzh add for Disable/Enable USB
#define ENABLE_USB_GPIO            0x1
#define DISABLE_USB_GPIO           0x0
extern void usb_enable(int act);

#define USB_ENABLE() usb_enable(ENABLE_USB_GPIO)
#define USB_DISABLE() usb_enable(DISABLE_USB_GPIO)

#define USB_PORT1_LED		0xfc
#define USB_PORT2_LED		0xf3

#define USB_LED1_OFF		0x03
#define USB_LED1_BLINKING	0x02
#define USB_LED1_ON		0x00
#define USB_LED2_OFF		0x0c
#define USB_LED2_BLINKING	0x08
#define USB_LED2_ON		0x00
#endif