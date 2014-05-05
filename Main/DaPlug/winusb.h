#ifndef WINUSB_H_INCLUDED
#define WINUSB_H_INCLUDED

#define WINUSB_VID 0x2581
#define WINUSB_PID 0x1808
#define PACKET_SIZE 512

struct winusb_device_;
typedef struct winusb_device_ winusb_device; //opaque structure

int listWinusbDevices(winusb_device **wdl);
int initWinusbDevice(winusb_device* winusb_dev);
void freeWinusbDevice(winusb_device *winusb);

void printWinusbDeviceInfo(winusb_device *winusb);

int ReadFromWinusbDevice(winusb_device* winusb, unsigned char*);
int writeToWinusbDevice(winusb_device* winusb, unsigned char *);

void winusbExit();

#endif // WINUSB_H_INCLUDED
