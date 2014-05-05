/**
 * \file winusb.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.0
 * \date 02/12/2013
 * \warning Functions are not documented
 *
 * Manage Winusb dongles.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <libusbx-1.0/libusb.h>
#endif // _WIN32
#ifdef __linux__
    #include <libusb-1.0/libusb.h>
#endif // __linux__

#include "winusb.h"

static const int TIMEOUT_MS = 5000;
static int initialized = 0;
libusb_context *ctx;

struct winusb_device_{

    libusb_device *device;

    /* Handle to the actual Dongle_info. */
	libusb_device_handle *device_handle;

	/* Endpoint information */
	int input_endpoint;
	int output_endpoint;
	int input_ep_max_packet_size;

	/* The interface number */
	int interface;

};

static winusb_device* createWinusbDevice(void){

    winusb_device *winusb = calloc(1,sizeof(winusb_device));
    if(winusb != NULL){
        static const winusb_device w = {NULL,NULL,0,0,0,0};
        *winusb = w;
    }

    return winusb;

}

//Check For Winusb VID & PID
static int isWinusbDevice(libusb_device *dev)
{

    struct libusb_device_descriptor desc;
    libusb_get_device_descriptor(dev,&desc);

    if(desc.idVendor == WINUSB_VID && desc.idProduct == WINUSB_PID){
    	return 1;
    }

    return 0;
}

int listWinusbDevices(winusb_device **wdl){

    libusb_device **usb_dev_list = NULL;

    int nb = 0;

    if(!initialized){
        if(libusb_init(&ctx)!=0){
            fprintf(stderr,"\nlistWinusbDevices(): Cannot initialize libusb !\n");
            return 0;
        }
        initialized = 1;
        //libusb_set_debug(ctx,4);
    }

    ssize_t cnt = libusb_get_device_list(ctx, &usb_dev_list);

    if (cnt <= 0){
        fprintf(stderr,"\nlistWinusbDevices(): No usb Dongle_info found !\n");
        return 0;
    }else{
        int i;
        for(i=0;i<cnt;i++){
            if(isWinusbDevice(usb_dev_list[i])){
                wdl[nb] = createWinusbDevice();
                wdl[nb]->device = usb_dev_list[i];
                nb++;
            }
        }
    }

    libusb_free_device_list(usb_dev_list,0);

    return nb;
}

int initWinusbDevice(winusb_device* winusb_dev){

    struct libusb_device_descriptor dev_desc;
    struct libusb_config_descriptor *config_desc = NULL;
    const struct libusb_interface *interf = NULL;
    const struct libusb_interface_descriptor *interf_desc = NULL;
    const struct libusb_endpoint_descriptor *ep_desc = NULL;

    int r = 0;
    if((r = libusb_open(winusb_dev->device,&winusb_dev->device_handle)) != 0){
        fprintf(stderr,"\ninitWinusbDevice(): libusb_open() error !\n");
        return 0;
    }
    if(libusb_get_device_descriptor(winusb_dev->device,&dev_desc) != 0){
        fprintf(stderr,"\ninitWinusbDevice(): libusb_get_device_descriptor() error !\n");
        return 0;
    }

    int i,j,k,l;
    int ep_out_ok = 0, ep_in_ok = 0;
    for(i=0;i<dev_desc.bNumConfigurations;i++){
        if(libusb_get_config_descriptor(winusb_dev->device, i, &config_desc)!=0){
            fprintf(stderr,"\ninitWinusbDevice(): libusb_get_config_descriptor() error !\n");
            return 0;
        }
        for(j=0;j<config_desc->bNumInterfaces;j++){
            interf = &config_desc->interface[j];
            for(k=0;k<interf->num_altsetting;k++){
                interf_desc = &interf->altsetting[k];
                //Intersting class is 255 : Vendor-specific
                if(interf_desc->bInterfaceClass != LIBUSB_CLASS_VENDOR_SPEC){
                    continue;
                }
                winusb_dev->interface = (int)interf_desc->bInterfaceNumber;
                ep_in_ok = 0; ep_out_ok = 0;
                for(l=0;l<interf_desc->bNumEndpoints;l++){
                    ep_desc = &interf_desc->endpoint[l];
                    //Determine endpoint type & direction
                    int is_bulk = (ep_desc->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK)
                                == LIBUSB_TRANSFER_TYPE_BULK;
                    int is_out = (ep_desc->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK)
                               == LIBUSB_ENDPOINT_OUT;
                    int is_in = (ep_desc->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK)
                              == LIBUSB_ENDPOINT_IN;
                    if(is_bulk && is_out){
                        winusb_dev->output_endpoint = ep_desc->bEndpointAddress;
                        ep_out_ok = 1;
                    }
                    if(is_bulk && is_in){
                        winusb_dev->input_endpoint = ep_desc->bEndpointAddress;
                        winusb_dev->input_ep_max_packet_size = ep_desc->wMaxPacketSize;
                        ep_in_ok = 1;
                    }
                    if(ep_in_ok && ep_out_ok){
                        break;
                    }
                }
                if(ep_in_ok && ep_out_ok){
                    break;
                }
            }
            if(ep_in_ok && ep_out_ok){
                break;
            }
        }
        if(ep_in_ok && ep_out_ok){
            break;
        }
    }

    libusb_free_config_descriptor(config_desc);

    return 1;
}

void printWinusbDeviceInfo(winusb_device *winusb){

    fprintf(stderr,"\n");
    fprintf(stderr,"\nDevice %p",winusb->device);
    fprintf(stderr,"\nHandle %p",winusb->device_handle);
    fprintf(stderr,"\nInterface %d",winusb->interface);
    fprintf(stderr,"\nInput endpoint 0x%02X",winusb->input_endpoint);
    fprintf(stderr,"\nOutput endpoint 0x%02X",winusb->output_endpoint);
    fprintf(stderr,"\nInput endpoint max packet size %d",winusb->input_ep_max_packet_size);

}

int writeToWinusbDevice(winusb_device* winusb, unsigned char *data){

    if(winusb->device_handle == NULL){
        fprintf(stderr,"\nwriteToWinusbDevice(): Unable to find the Dongle_info !\n");
        return 0;
    }

    //Claim the interface before performing I/O
    int r = libusb_claim_interface(winusb->device_handle, winusb->interface);
    if(r < 0){
        fprintf(stderr,"\nwriteToWinusbDevice(): libusb_claim_interface error !\n");
        return 0;
    }

    int bytes_transferred;
    r = libusb_bulk_transfer(
			winusb->device_handle,
			winusb->output_endpoint,
			data,
			PACKET_SIZE,
			&bytes_transferred,
			TIMEOUT_MS);

	if (r < 0)
	{
	  	fprintf(stderr,"\nwriteToWinusbDevice(): Unable to write data !\n");
	  	return 0;
    }

    return 1;
}

int ReadFromWinusbDevice(winusb_device* winusb, unsigned char* data){

    if(winusb->device_handle == NULL){
        fprintf(stderr,"\nReadFromWinusbDevice(): Unable to find the Dongle_info !\n");
        return 0;
    }

    int bytes_transferred;
    int r1 = libusb_bulk_transfer(
			winusb->device_handle,
			winusb->input_endpoint,
			data,
            PACKET_SIZE,
			&bytes_transferred,
			TIMEOUT_MS);

    //Release the interface previously claimed in winusb_write()
    int r2 = libusb_release_interface(winusb->device_handle, winusb->interface);
    if(r2){
        fprintf(stderr,"\nReadFromWinusbDevice(): libusb_release_interface error !\n");
        return 0;
    }

	if (r1 < 0 || bytes_transferred <=0)
	{
	  	fprintf(stderr,"\nReadFromWinusbDevice(): Unable to read data !\n");
	  	return 0;
    }

    return bytes_transferred;
}

void freeWinusbDevice(winusb_device *winusb){

    if(winusb != NULL){
        if(winusb->device_handle != NULL){
            libusb_close(winusb->device_handle);
        }
    }

    free(winusb);
    winusb = NULL;

}

void winusbExit(){

    if(initialized){
        libusb_exit(ctx);
        initialized = 0;
    }
}
