/**
 * \file comm.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.0
 * \date 02/12/2013
 *
 * Send/receive APDU command/response to/from dongle. Perform wrap/unwrap operations, when exchanging APDUs
 * over a secure channel, according to a given security level.
 *
 */


#include <daplug/comm.h>
#include <daplug/winusb.h>

static void wrapApduCmd(DaplugDongle* dpd, Apdu *a){

    char header[APDU_H_LEN*2+1]="", f_header[APDU_H_LEN*2+1]="",//f = final
         data[APDU_D_MAXLEN*2+1]="", f_data[APDU_D_MAXLEN*2+1]="",
         c_mac[8*2+1]="", f_apdu[(APDU_H_LEN+APDU_D_MAXLEN)*2+1]="";

    Byte header_b[APDU_H_LEN], f_header_b[APDU_H_LEN];

    memset(header_b, 0, APDU_H_LEN);
    memset(f_header_b, 0, APDU_H_LEN);

    int mac_size = 0, pad_size = 0, orCla = 0x00;

    char *tmp = NULL;
    strcpy(header,tmp = str_sub(a->c_str,0,APDU_H_LEN*2-1));
    free(tmp);
    tmp = NULL;
    strcpy(data,tmp = str_sub(a->c_str,APDU_H_LEN*2,APDU_D_MAXLEN*2-1));
    free(tmp);
    tmp = NULL;

    strcpy(f_header, header);
    strcpy(f_data, data);

    strToBytes(header, header_b);
    strToBytes(header, f_header_b);

    //Data encryption (exclude external authenticate apdu)
    if((dpd->securityLevel & C_DEC)&&(strncmp("8082",header,4))){

        //encrypt apdu data
        dataEncryption(data, dpd->s_enc_key,f_data, DES_ENCRYPT);
        pad_size = (strlen(f_data)-strlen(data))/2;

    }

    //Command integrity (forced for external authenticate command)
    if((dpd->securityLevel & C_MAC)||(!strncmp("8082",header,4))){

        char m_apdu[(APDU_H_LEN+APDU_D_MAXLEN)*2+1]="";

        mac_size = 0x08;
        orCla = 0x04;

        header_b[0]= header_b[0] | orCla; //CLA ORed with 0x04 if c-mac
        header_b[4]= header_b[4] + mac_size; //increase Lc

        bytesToStr(header_b,APDU_H_LEN,header);
        strcat(m_apdu,header);
        strcat(m_apdu,data);

        //compute c-mac
        computeRetailMac(m_apdu, dpd->c_mac_key,dpd->c_mac,c_mac,1);
        //update dpd c_mac
        strcpy(dpd->c_mac,c_mac);

    }

    f_header_b[0]= f_header_b[0] | orCla; //CLA ORed with 0x04 if c-mac
    f_header_b[4]= f_header_b[4] + pad_size + mac_size; //increase Lc
    bytesToStr(f_header_b,APDU_H_LEN,f_header);

    //final apdu to exchange
    strcat(f_apdu,f_header);
    strcat(f_apdu,f_data);
    strcat(f_apdu,c_mac);

    //update apc
    a->cmd_len = strlen(f_apdu)/2;
    strcpy(a->c_str,f_apdu);
    strToBytes(a->c_str,a->cmd);

}

static int unwrapApduRep(DaplugDongle* dpd, Apdu *a){

    char data0[APDU_D_MAXLEN*2+1]="",
         padded_clear_data[APDU_D_MAXLEN*2+1]="",
         clear_data[APDU_D_MAXLEN*2+1]="",
         temp_data[(APDU_CMD_MAXLEN+APDU_D_MAXLEN+3)*2+1]="",
         f_data[APDU_D_MAXLEN*2+1]="",

         returned_mac[8*2+1]="",
         mac[8*2+1]="";

    //initialization
    strcpy(f_data,a->r_str);

    if((dpd->securityLevel & R_MAC) && !(dpd->securityLevel & R_ENC)){

        char *tmp = NULL;
        strcpy(data0, tmp = str_sub(a->r_str,0,(a->rep_data_len-8)*2-1));
        free(tmp);
        tmp = NULL;
        strcpy(returned_mac, tmp = str_sub(a->r_str,(a->rep_data_len-8)*2,
              (a->rep_data_len-8)*2+(8*2)-1));
        free(tmp);
        tmp = NULL;

        //rep data length
        char rdl[1*2+1]="";
        sprintf(rdl,"%02X",(int)strlen(data0)/2);

        //prepare retail mac data (response)
        strcat(temp_data,a->cmd0); //unmodified apdu
        strcat(temp_data,rdl); //rep data length
        strcat(temp_data,data0); //data
        strcat(temp_data,a->sw_str); //sw

        computeRetailMac(temp_data,dpd->r_mac_key,dpd->r_mac,mac,0);

        if(strcmp(returned_mac,mac)){
            fprintf(stderr,"\nunwrapApduRep(): Response integrity failed !\n");
            //Daplug_deAuthenticate
            Daplug_deAuthenticate(dpd);
            return 0;
        }

        //update dpd
        strcpy(dpd->r_mac,mac);

        strcpy(f_data, data0);
    }

    if((dpd->securityLevel & R_ENC) && !(dpd->securityLevel & R_MAC)){

        if(strlen(f_data)>0){ //In case of apdu reponse with data only


            dataEncryption(f_data, dpd->r_enc_key, padded_clear_data, DES_DECRYPT);

            //exclude padding to obtain clear data
            Byte padded_clear_data_b[APDU_D_MAXLEN];
            strToBytes(padded_clear_data,padded_clear_data_b);
            int end = strlen(padded_clear_data)/2 - 1,
                i = end;
            while(padded_clear_data_b[i]==0x00 && i>0){
                i--;
            }
            if(padded_clear_data_b[i]==0x80){
                char* tmp = NULL;
                strcpy(clear_data, tmp = str_sub(padded_clear_data,0,i*2-1));
                free(tmp);
                tmp = NULL;
            }
            else{
                fprintf(stderr,"\nunwrapApduRep(): Response decryption failed !\n");
                //Daplug_deAuthenticate
                Daplug_deAuthenticate(dpd);
                return 0;
            }

        }

        strcpy(f_data, clear_data);
    }

    if((dpd->securityLevel & R_MAC)&&(dpd->securityLevel & R_ENC)){

        char *tmp = NULL;
        strcpy(data0, tmp = str_sub(a->r_str,0,(a->rep_data_len-8)*2-1));
        free(tmp);
        tmp = NULL;
        strcpy(returned_mac, tmp = str_sub(a->r_str,(a->rep_data_len-8)*2,
              (a->rep_data_len-8)*2+(8*2)-1));
        free(tmp);
        tmp = NULL;

        if(strlen(data0)>0){ //In case of apdu reponse with data only

            dataEncryption(data0, dpd->r_enc_key, padded_clear_data, DES_DECRYPT);

            //exclude padding to obtain clear data
            Byte padded_clear_data_b[APDU_D_MAXLEN];
            strToBytes(padded_clear_data,padded_clear_data_b);
            int end = strlen(padded_clear_data)/2 - 1,
                i = end;
            while(padded_clear_data_b[i]==0x00 && i>0){
                i--;
            }
            if(padded_clear_data_b[i]==0x80){
                char *tmp = NULL;
                strcpy(clear_data, tmp = str_sub(padded_clear_data,0,i*2-1));
                free(tmp);
                tmp = NULL;
            }
            else{
                fprintf(stderr,"\nunwrapApduRep(): Response decryption failed !\n");
                //Daplug_deAuthenticate
                Daplug_deAuthenticate(dpd);
                return 0;
            }

        }

        //rep data length
        char rdl[1*2+1]="";
        sprintf(rdl,"%02X",(int)strlen(clear_data)/2);

        //prepare retail mac data (response)
        strcat(temp_data,a->cmd0); //unmodified apdu
        strcat(temp_data,rdl); //rep data length
        strcat(temp_data,clear_data); //clear data
        strcat(temp_data,a->sw_str); //sw

        computeRetailMac(temp_data,dpd->r_mac_key,dpd->r_mac,mac,0);

        if(strcmp(returned_mac,mac)){
            fprintf(stderr,"\nunwrapApduRep(): Response integrity failed !\n");
            return 0;
        }

        //update dpd
        strcpy(dpd->r_mac,mac);

        strcpy(f_data, clear_data);

    }

    //update apdu
    strcpy(a->r_str, f_data);
    strToBytes(a->r_str,a->rep_data);
    a->rep_data_len = strlen(f_data)/2;

    return 1;

}

int exchangeApdu(DaplugDongle *dpd, Apdu *a){

    if(!dpd->di.handle) {
        fprintf(stderr,"\nexchangeApdu(): Dongle_info error !\n");
        return 0;
    }

    //wrap apdu according to the dpd state
    wrapApduCmd(dpd,a);

    //print exchanged apdus into the log file
    if(flog_apdu){
        fprintf(flog_apdu,"=> %s\n",a->c_str);
    }

    if(dpd->di.type == HID_DEVICE){ //hid Dongle_info

        int i=0,j=0,k=0,useful_data=0,reads_nb=0,nbr=0,nbw=0,pad=0;

        Byte all_read_blocks[HID_BLOCK_SIZE*5], //will contain all read blocks
        w_block[HID_BLOCK_SIZE+1],//block to write (+1 for fake report)
        r_block[HID_BLOCK_SIZE];//block to read

        //initialize blocks
        memset(w_block,0x00,HID_BLOCK_SIZE+1);
        memset(r_block,0x00,HID_BLOCK_SIZE);

        //decompose the apdu_c to blocks of T_BLOCK bytes
        i=0;
        while(i+HID_BLOCK_SIZE < a->cmd_len)
        {
            for(j=1;j<HID_BLOCK_SIZE+1;j++){
                w_block[j]=a->cmd[i+j-1];
            }

            //write block to plug-up
            nbw = hid_write((hid_device*)dpd->di.handle,w_block,HID_BLOCK_SIZE+1);
            if (nbw < 0) {
                fprintf(stderr,"\nexchangeApdu(): Write apdu failure !\n");
                return 0;
            }

            i=i+HID_BLOCK_SIZE; //next block
        }

        //Pad last block with 0x00
        pad = i+HID_BLOCK_SIZE+1-a->cmd_len;
        for(j=1;j<HID_BLOCK_SIZE+1;j++){
            if(j<HID_BLOCK_SIZE+1-pad+1){
                w_block[j]=a->cmd[i+j-1];
                //fprintf(stderr,"%02hx",w_block[i]);
            }
            else{
                w_block[j]=0x00;
            }
        }

        //Write last block
        nbw = hid_write((hid_device*)dpd->di.handle,w_block,HID_BLOCK_SIZE+1);
        if (nbw < 0) {
            fprintf(stderr,"exchangeApdu(): Write apdu failure !\n");
            return 0;
        }


        //read the apdu response
        nbr = hid_read((hid_device*)dpd->di.handle,r_block,HID_BLOCK_SIZE); //read first block
        if (nbr < 0) {
            fprintf(stderr,"\nexchangeApdu(): Read failure !\n");
            return 0;
        }

        if(r_block[0]!=0x61){ //response without data
            a->sw[0]=r_block[0];
            a->sw[1]=r_block[1];
        }
        else{ //response with data
            a->rep_data_len=r_block[1];
            useful_data=a->rep_data_len+4;//read data without padding = 2 first bytes+data+sw1+sw2
            if(useful_data%HID_BLOCK_SIZE==0) reads_nb=useful_data/HID_BLOCK_SIZE;
            else reads_nb=(useful_data/HID_BLOCK_SIZE)+1; //reads number = blocks number

            j=0;
            for(i=0;i<HID_BLOCK_SIZE;i++,j++){
                all_read_blocks[j]=r_block[i];
            }

            //reading block by block
            for(k=0;k<reads_nb-1;k++){
                nbr = hid_read((hid_device*)dpd->di.handle,r_block,HID_BLOCK_SIZE);
                if (nbr < 0) {
                    fprintf(stderr,"\nexchangeApdu(): Read failure !\n");
                    return 0;
                }

                for(i=0;i<HID_BLOCK_SIZE;i++,j++){
                    all_read_blocks[j]=r_block[i];
                }
            }

            //Extract data
            for(i=2;i<a->rep_data_len+2;i++){
                a->rep_data[i-2]=all_read_blocks[i];
            }


            //Extract status word
            for(i=a->rep_data_len+2;i<useful_data;i++){
                a->sw[i-a->rep_data_len-2]=all_read_blocks[i];
            }

        }

    }

    if(dpd->di.type == WINUSB_DEVICE){ //winusb Dongle_info

        Byte winusb_read_data0[APDU_D_MAXLEN+4];//data + sw + 2 first bytes

        writeToWinusbDevice(dpd->di.handle,a->cmd);
        ReadFromWinusbDevice(dpd->di.handle,winusb_read_data0);
        a->rep_data_len = winusb_read_data0[1];
        if(winusb_read_data0[0] == 0x61){
            int i=0;
            for(i=0;i<a->rep_data_len;i++){
                a->rep_data[i]=winusb_read_data0[i+2];
            }
            a->sw[0]= winusb_read_data0[i+2];
            a->sw[1]= winusb_read_data0[i+1+2];
        }else{
            a->sw[0]= winusb_read_data0[0];
            a->sw[1]= winusb_read_data0[1];
        }
    }

    //update apdu
    bytesToStr(a->rep_data,a->rep_data_len,a->r_str);
    bytesToStr(a->sw,2,a->sw_str);

    //print apdu responses into the log file
    if(flog_apdu){
        fprintf(flog_apdu,"<= %s %s\n",a->r_str,a->sw_str);
    }

    unwrapApduRep(dpd,a);

    return 1;

}
