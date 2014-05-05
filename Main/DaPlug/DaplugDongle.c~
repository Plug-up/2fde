/**
 * \file DaplugDongle.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.0
 * \date 02/12/2013
 *
 * Daplug API is a set of functions wich are designed to help with operations on Daplug dongle.
 */

#include <daplug/DaplugDongle.h>
#include <daplug/comm.h>
#include <daplug/sc.h>
#include <daplug/winusb.h>

static void initDongle(DaplugDongle* dpd){

    strcpy(dpd->c_mac,"");
    strcpy(dpd->r_mac,"");
    strcpy(dpd->s_enc_key,"");
    strcpy(dpd->r_enc_key,"");
    strcpy(dpd->c_mac_key,"");
    strcpy(dpd->r_mac_key,"");
    strcpy(dpd->s_dek_key,"");

    dpd->securityLevel=0;
    dpd->session_opened=0;

}

static void encdec(DaplugDongle *dpd, int enc, int keyVersion, int keyID, int mode, char *iv, char *div1, char *div2,
            char *inData, char *outData){

    Apdu enc_dec_apdu;

    char enc_dec_apdu_str[APDU_CMD_MAXLEN*2+1]="";

    char enc_s[1*2+1]="", mode_s[1*2+1]="", kv_s[1*2+1]="", kid_s[1*2+1]="";
    sprintf(enc_s,"%02X",enc);
    sprintf(mode_s,"%02X",mode);
    sprintf(kv_s,"%02X",keyVersion);
    sprintf(kid_s,"%02X",keyID);

    if(enc != 0x01 && enc != 0x02){
        fprintf(stderr,"\nencdec(): Wrong value for enc !\n");
        return;
    }

    char iv_[8*2+1]="";
    if(strlen(iv)==0){
        strcpy(iv_,"0000000000000000");
    }else{
        strcpy(iv_,iv);
    }

    if(!isHexInput(iv_) || strlen(iv_)!=8*2){
        fprintf(stderr,"\nencdec(): Wrong IV !\n");
        return;
    }

    if(mode & ENC_ECB && mode & ENC_CBC){
        fprintf(stderr,"\nencdec(): Wrong mode value !\n");
        return;
    }

    char div1_[16*2+1]="";
    int lc = 10; //kv, kid, iv
    if(mode & ENC_1_DIV || mode & ENC_2_DIV){
        if(strlen(div1)==0 || strlen(div1)!=16*2 || !isHexInput(div1)){
            fprintf(stderr,"\nencdec(): Wrong value for the first diversifier !\n");
            return;
        }else{
            strcpy(div1_,div1);
            lc = lc + 16;
        }
    }

    char div2_[16*2+1]="";
    if(mode & ENC_2_DIV){

        if(strlen(div2)==0 || strlen(div2)!=16*2 || !isHexInput(div2)){
            fprintf(stderr,"\nencdec(): Wrong value for the second diversifier !\n");
            return;
        }else{
            strcpy(div2_,div2);
            lc = lc + 16;
        }
    }

    char data_[(MAX_REAL_DATA_SIZE-10)*2+1]="";

    if(!isHexInput(inData)){
        fprintf(stderr,"\nencdec(): Wrong value for input data !\n");
        return;
    }
    if(strlen(inData) == 0 || strlen(inData)%(8*2) != 0 || lc+strlen(inData)/2 > MAX_REAL_DATA_SIZE){
        fprintf(stderr,"\nencdec(): Wrong length for input data !\n");
        return;
    }

    strcpy(data_,inData);

    lc = lc + strlen(data_)/2;
    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    strcat(enc_dec_apdu_str,"D020");
    strcat(enc_dec_apdu_str,enc_s);
    strcat(enc_dec_apdu_str,mode_s);
    strcat(enc_dec_apdu_str,lc_s);
    strcat(enc_dec_apdu_str,kv_s);
    strcat(enc_dec_apdu_str,kid_s);
    strcat(enc_dec_apdu_str,iv_);
    strcat(enc_dec_apdu_str,div1_);
    strcat(enc_dec_apdu_str,div2_);
    strcat(enc_dec_apdu_str,data_);

    //Set to apdu cde
    setApduCmd(enc_dec_apdu_str,&enc_dec_apdu);

    //exchange it
    exchangeApdu(dpd,&enc_dec_apdu);

    if(strcmp(enc_dec_apdu.sw_str,"9000")){
        if(enc == 1){
            fprintf(stderr,"\nencdec(): Cannot encrypt data !\n");
        }
        if(enc == 2){
            fprintf(stderr,"\nencdec(): Cannot decrypt data !\n");
        }
        return;
    }

    strcpy(outData,enc_dec_apdu.r_str);

}

static void hmac_sha1(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData){

    Apdu hmac_apdu;

    char hmac_apdu_str[APDU_CMD_MAXLEN*2+1]="";

    char kv_s[1*2+1]="";
    sprintf(kv_s,"%02X",keyVersion);

    char opt_s[1*2+1]="";
    sprintf(opt_s,"%02X",options);

    int lc = 0;
    char div1_[16*2+1]="";

    if(options & OTP_1_DIV || options & OTP_2_DIV){
        if(strlen(div1)==0 || strlen(div1)!=16*2 || !isHexInput(div1)){
            fprintf(stderr,"\nhmac_sha1(): Wrong value for the first diversifier !\n");
            return;
        }else{
            strcpy(div1_,div1);
            lc = lc + 16;
        }
    }

    char div2_[16*2+1]="";

    if(options & OTP_2_DIV){

        if(strlen(div2)==0 || strlen(div2)!=16*2 || !isHexInput(div2)){
            fprintf(stderr,"\nhmac_sha1(): Wrong value for the second diversifier !\n");
            return;
        }else{
            strcpy(div2_,div2);
            lc = lc + 16;
        }
    }

    char data_[MAX_REAL_DATA_SIZE*2+1]="";

    if(!isHexInput(inData)){
        fprintf(stderr,"\nhmac_sha1(): Wrong value for input data !\n");
        return;
    }

    if(lc+strlen(inData)/2 > MAX_REAL_DATA_SIZE){ //for Daplug_totp, data can be null => we exclude condition strlen(inData) = 0
        fprintf(stderr,"\nhmac_sha1(): Wrong length for input data !\n");
        return;
    }

    strcpy(data_,inData);

    lc = lc + strlen(data_)/2;
    char lc_s[1*2+1]="";
    sprintf(lc_s,"%02X",lc);

    //Form the apdu
    strcat(hmac_apdu_str,"D022");
    strcat(hmac_apdu_str,kv_s);
    strcat(hmac_apdu_str,opt_s);
    strcat(hmac_apdu_str,lc_s);
    strcat(hmac_apdu_str,div1_);
    strcat(hmac_apdu_str,div2_);
    strcat(hmac_apdu_str,data_);

    //Set to apdu cde
    setApduCmd(hmac_apdu_str,&hmac_apdu);

    //exchange it
    exchangeApdu(dpd,&hmac_apdu);

    if(strcmp(hmac_apdu.sw_str,"9000")){
        fprintf(stderr,"\nhmac_sha1(): Cannot sign data !\n");
        return;
    }

    strcpy(outData,hmac_apdu.r_str);

}

int DAPLUGCALL Daplug_getDongleList(Dongle_info *dil){

    struct hid_device_info *lh;

    int i=0;

    //Enumerate & initialize hid devices
    if(!(lh=hid_enumerate(HID_VID,HID_PID))){
        //fprintf(stderr,"\ngetDongleList(): No hid Dongle_info inserted !\n");
    }
    else{
        while(lh && (i<CON_DNG_MAX_NB)){

            //if Linux OS, pass to dongle second interface
            #ifdef __linux__
            lh=lh->next;
            #endif

            dil[i].type = HID_DEVICE;
            dil[i].path = (char*)lh->path;

            lh=lh->next;
            i++;
        }

        hid_free_enumeration(lh);
    }

    //Enumerate and initialize winusb devices
    winusb_device *wdl[CON_DNG_MAX_NB];
    int nb_wd = listWinusbDevices(wdl);
    int j = 0;
    if(nb_wd <= 0) return i;
    while(j < nb_wd && i < CON_DNG_MAX_NB){
        dil[i].type = WINUSB_DEVICE;
        dil[i].handle = (winusb_device *) wdl[j];
        j++;
        i++;
    }

    return i; //number of connected plug-ups
}

int DAPLUGCALL Daplug_getDongleById(Dongle_info* di,DaplugDongle *dpd){

    if(di->type == HID_DEVICE){
        if((di->handle = (hid_device *)hid_open_path(di->path)) == NULL){
            fprintf(stderr,"\ngetDongleById(): Cannot open hid dongle !\n");
            return 0;
        }
    }

    if(di->type == WINUSB_DEVICE){
        if(initWinusbDevice(di->handle) == 0){
            fprintf(stderr,"\ngetDongleById(): Cannot open winusb dongle !\n");
            return 0;
        }
    }

    initDongle(dpd);
    dpd->di = (Dongle_info) *di;

    return 1;
}

void DAPLUGCALL Daplug_free(DaplugDongle *dpd, Dongle_info *dil, int nb){

    Daplug_deAuthenticate(dpd);

    //if Hid device
    if(dpd->di.type == 0) hid_close(dpd->di.handle);

    //free winusb devices list
    int i;
    for(i=0;i<nb;i++){
        if(dil[i].type == WINUSB_DEVICE){
            freeWinusbDevice(dil[i].handle);
        }
    }
}

void DAPLUGCALL Daplug_exit(){
    winusbExit();
    hid_exit();
}

int DAPLUGCALL Daplug_exchange(DaplugDongle *dpd, const char *cmd, char *resp, char *sw){

    Apdu a;
    setApduCmd(cmd,&a);

    exchangeApdu(dpd,&a);

    if(strcmp(a.sw_str,"9000")){
        fprintf(stderr,"\nDaplug_exchange(): An error occured when exchanging command !\n");
        return 0;
    }

    strcpy(resp,a.r_str);
    strcpy(sw,a.sw_str);

    return 1;
}

int DAPLUGCALL Daplug_getDongleSerial(DaplugDongle *dpd, char* serial){

    Apdu apc_get_serial;
    setApduCmd("80E6000000",&apc_get_serial);

    exchangeApdu(dpd,&apc_get_serial);

    if(strcmp(apc_get_serial.sw_str,"9000")){
        fprintf(stderr,"\ngetDongleSerial(): An error occured when exchanging command !\n");
        return 0;
    }

    strcpy(serial,apc_get_serial.r_str);

    return 1;
}

int DAPLUGCALL Daplug_getDongleStatus(DaplugDongle *dpd, int *status){

    Apdu apc_get_status;
    setApduCmd("80F2400000",&apc_get_status);

    exchangeApdu(dpd,&apc_get_status);

    if(strcmp(apc_get_status.sw_str,"9000")){
        fprintf(stderr,"\ngetDongleStatus(): An error occured when exchanging command !\n");
        return 0;
    }

    *status = apc_get_status.rep_data[9];

    return 1;

}

int DAPLUGCALL Daplug_setDongleStatus(DaplugDongle *dpd, int status){

    char set_status[5*2+1]="80F040",
         st[1*2+1]="";

    sprintf(st,"%02X",status);

    strcat(set_status,st);
    strcat(set_status,"00");

    Apdu apc_set_status;
    setApduCmd(set_status,&apc_set_status);

    exchangeApdu(dpd,&apc_set_status);

    if(strcmp(apc_set_status.sw_str,"9000")){
        fprintf(stderr,"\nsetDongleStatus(): An error occured when exchanging command !\n");
        return 0;
    }

    return 1;

}

void DAPLUGCALL Daplug_authenticate(DaplugDongle *dpd, Keyset keys, int mode, char *div, char *chlg){

    Byte hostChallenge[8];

    char counter[2*2+1] = "",
         cardChallenge[6*2+1] = "",
         returnedCardCryptogram[8*2+1]="",
         computedCardCryptogram[8*2+1]="",
         hostCryptogram[8*2+1] = "",
         s_hostChallenge[8*2+1]="",
         temp[APDU_CMD_MAXLEN*2+1]="";

    Apdu initialize_update,
         external_authenticate;

    //close any sc previously opened
    Daplug_deAuthenticate(dpd);

    if(!strcmp(chlg,"")){
        //generate host challenge
        generateChallenge(hostChallenge,8);
        bytesToStr(hostChallenge,8,s_hostChallenge);
    }else{
        if(strlen(chlg)!=8*2 || !isHexInput(chlg)){
            fprintf(stderr,"\nDaplug_authenticate(): Wrong value for challenge !\n");
            return;
        }
        strncpy(s_hostChallenge,chlg,16);
        s_hostChallenge[16]='\0';
    }

    //Keyset version
    char version[1*2+1]="";
    sprintf(version,"%02X",keys.version);

    //Any diversifier?
    if(strlen(div) != 0){
        if(strlen(div)!=16*2 || !isHexInput(div)){
        fprintf(stderr,"\nDaplug_authenticate(): Wrong value for diversifier !\n");
        return;
        }
    }

    if(strlen(div) == 0){
        //initialize update without diversifier
        strcat(temp,"8050");
        strcat(temp,version);
        strcat(temp,"0008");
        strcat(temp,s_hostChallenge);
        setApduCmd(temp,&initialize_update);
    }else{
        //diversified initialize update
        strcat(temp,"D050");
        strcat(temp,version);
        strcat(temp,"1018");
        strcat(temp,s_hostChallenge);
        strcat(temp,div);
        setApduCmd(temp,&initialize_update);
    }

    //exchange
    exchangeApdu(dpd,&initialize_update);

    if(strcmp(initialize_update.sw_str,"9000")){
        fprintf(stderr,"\nauthenticate(): initialize update error ! sw = %s\n",
                initialize_update.sw_str);
        return;
    }

    //extract data returned by the card
    char *tmp = NULL;
    strcpy(counter,tmp = str_sub(initialize_update.r_str, 24, 27));
    free(tmp);
    tmp = NULL;
    strcpy(cardChallenge,tmp = str_sub(initialize_update.r_str, 28, 39));
    free(tmp);
    tmp = NULL;
    strcpy(returnedCardCryptogram,tmp = str_sub(initialize_update.r_str, 40, 55));
    free(tmp);
    tmp = NULL;

    //compute session keys & update dpd
    char enc_key[GP_KEY_SIZE*2+1]="",
         mac_key[GP_KEY_SIZE*2+1]="",
         dek_key[GP_KEY_SIZE*2+1]="";

    bytesToStr(keys.key[0],GP_KEY_SIZE,enc_key);
    bytesToStr(keys.key[1],GP_KEY_SIZE,mac_key);
    bytesToStr(keys.key[2],GP_KEY_SIZE,dek_key);

    //session s-enc key
    computeSessionKey(counter,"0182",enc_key,dpd->s_enc_key);

    //session s-enc key
    computeSessionKey(counter,"0183",enc_key,dpd->r_enc_key);

    //session c-mac key
    computeSessionKey(counter, "0101", mac_key, dpd->c_mac_key);

    //session r-mac key
    computeSessionKey(counter, "0102", mac_key, dpd->r_mac_key);

    //session dek key. In case of need it will be used. (to form "put key" command for example)
    computeSessionKey(counter,"0181", dek_key, dpd->s_dek_key);

    //compute card cryptogram
    computeCardCryptogram(s_hostChallenge,cardChallenge,counter,dpd->s_enc_key,computedCardCryptogram);

    //check card cryptogram
    if(!checkCardCryptogram(returnedCardCryptogram,computedCardCryptogram)){
        fprintf(stderr,"\nauthenticate(): Card Cryptogram verification failed !\n");
        return;
    }
    else{
        //compute data that an external Daplug_authenticate apdu needs
        computeHostCryptogram(s_hostChallenge, cardChallenge, counter, dpd->s_enc_key, hostCryptogram);

        //mode
        char sec_l[1*2+1]="";
        sprintf(sec_l,"%02X",mode);

        //external Daplug_authenticate
        strcpy(temp,""),
        strcat(temp,"8082");
        strcat(temp,sec_l);
        strcat(temp,"0008");
        strcat(temp,hostCryptogram);
        setApduCmd(temp,&external_authenticate);

        //exchange
        exchangeApdu(dpd,&external_authenticate);

        if(strcmp(external_authenticate.sw_str,"9000")){
            fprintf(stderr,"\nauthenticate(): external Daplug_authenticate error ! sw = %s\n",
                    external_authenticate.sw_str);
            return;
        }

    }

    fprintf(stderr,"\nauthenticate() : Successful authentication !\n");

    //update dpd
    strcpy(dpd->r_mac,dpd->c_mac);
    dpd->securityLevel = mode;
    dpd->session_opened = 1;
}

void DAPLUGCALL Daplug_computeDiversifiedKeys(Keyset keys, Keyset *div_keys, char *div){

    char enc_key[GP_KEY_SIZE*2+1]="",
         mac_key[GP_KEY_SIZE*2+1]="",
         dek_key[GP_KEY_SIZE*2+1]="";

    char div_enc_key[GP_KEY_SIZE*2+1]="",
         div_mac_key[GP_KEY_SIZE*2+1]="",
         div_dek_key[GP_KEY_SIZE*2+1]="";

    if(strlen(div)==0 || strlen(div)!=16*2 || !isHexInput(div)){
        fprintf(stderr,"\nDaplug_ComputeDiversifiedKeys(): Wrong value for diversifier !\n");
        return;
    }

    bytesToStr(keys.key[0],GP_KEY_SIZE,enc_key);
    bytesToStr(keys.key[1],GP_KEY_SIZE,mac_key);
    bytesToStr(keys.key[2],GP_KEY_SIZE,dek_key);

    computeDiversifiedKey(enc_key,div,div_enc_key);
    computeDiversifiedKey(mac_key,div,div_mac_key);
    computeDiversifiedKey(dek_key,div,div_dek_key);

    strToBytes(div_enc_key,div_keys->key[0]);
    strToBytes(div_mac_key,div_keys->key[1]);
    strToBytes(div_dek_key,div_keys->key[2]);

}

void DAPLUGCALL Daplug_deAuthenticate(DaplugDongle *dpd){

    if(dpd->session_opened){

        strcpy(dpd->c_mac,"");
        strcpy(dpd->r_mac,"");
        strcpy(dpd->s_enc_key,"");
        strcpy(dpd->r_enc_key,"");
        strcpy(dpd->c_mac_key,"");
        strcpy(dpd->r_mac_key,"");
        strcpy(dpd->s_dek_key,"");

        dpd->securityLevel=0;
        dpd->session_opened=0;

        //send any apdu to close the SC
        Apdu any_apdu;
        setApduCmd("0000000000",&any_apdu);
        exchangeApdu(dpd,&any_apdu);

        fprintf(stderr,"\ndeAuthenticate() : De-authentication !\n");

    }
}

void DAPLUGCALL Daplug_putKey(DaplugDongle *dpd, Keyset new_keys){

    char putkey_apdu_str[APDU_CMD_MAXLEN*2+1]="";

    //key version
    char kv[1*2+1]="";
    sprintf(kv,"%02X",new_keys.version);

    //default mode : regular
    char *mode = "81";


    //the new Keyset gp keys
    char enc_key[16*2+1]="",
         mac_key[16*2+1]="",
         dek_key[16*2+1]="";

    bytesToStr(new_keys.key[0],GP_KEY_SIZE,enc_key);
    bytesToStr(new_keys.key[1],GP_KEY_SIZE,mac_key);
    bytesToStr(new_keys.key[2],GP_KEY_SIZE,dek_key);

    //key usage
    char ku[1*2+1]="";
    sprintf(ku,"%02X",new_keys.usage);

    //key access
    char ka[2*2+1]="";
    bytesToStr(new_keys.access,2,ka);

    //Form the put key apdu
    createPutKeyCommand(kv,mode,dpd->s_dek_key,enc_key,mac_key,dek_key,ku,ka,putkey_apdu_str);

    //set to apdu cde
    Apdu putkey_apdu;
    setApduCmd(putkey_apdu_str,&putkey_apdu);

    //exchange it
    exchangeApdu(dpd,&putkey_apdu);

    if(strcmp(putkey_apdu.sw_str,"9000")){
        fprintf(stderr,"\nputKey(): Cannot create/modify Keyset !\n");
        return;
    }else{
        fprintf(stderr,"\nputKey(): Keyset %02X successfully created/modified.\n",new_keys.version);
    }


}

void DAPLUGCALL Daplug_deleteKey(DaplugDongle *dpd, int version){

    char kid[2*2+1]="10",
         v[1*2+1]="";

    int keyset_fileId;

    sprintf(v,"%02X",version);
    strcat(kid,v);
    sscanf(kid,"%04X",&keyset_fileId);

    Daplug_selectPath(dpd,"3f00c00fc0de0001");
    Daplug_deleteFileOrDir(dpd,keyset_fileId);

}

void DAPLUGCALL Daplug_exportKey(DaplugDongle *dpd,int version,int id, char *expkey){

    char exp_tr_keyset_apdu_str[APDU_CMD_MAXLEN*2+1]="";

    //version
    char v_str[1*2+1]="";
    sprintf(v_str,"%02X",version);

    //id
    char id_str[1*2+1]="";
    sprintf(id_str,"%02X",id);

    //Form the export transient Keyset apdu
    strcat(exp_tr_keyset_apdu_str,"D0A0");
    strcat(exp_tr_keyset_apdu_str,v_str);
    strcat(exp_tr_keyset_apdu_str,id_str);
    strcat(exp_tr_keyset_apdu_str,"00");

    //Set to apdu cde
    Apdu exp_tr_keyset_apdu;
    setApduCmd(exp_tr_keyset_apdu_str,&exp_tr_keyset_apdu);

    //exchange it
    exchangeApdu(dpd,&exp_tr_keyset_apdu);

    if(strcmp(exp_tr_keyset_apdu.sw_str,"9000")){
        fprintf(stderr,"\nexportKey(): Cannot export key !\n");
        return;
    }else{
        strcpy(expkey,exp_tr_keyset_apdu.r_str);
        fprintf(stderr,"\nexportKey(): Key successfully exported.\n");
        return;
    }
}

void DAPLUGCALL Daplug_importKey(DaplugDongle *dpd,int version,int id, char *impkey){

    char imp_tr_keyset_apdu_str[APDU_CMD_MAXLEN*2+1]="";

    //version
    char v_str[1*2+1]="";
    sprintf(v_str,"%02X",version);

    //id
    char id_str[2+1]="";
    sprintf(id_str,"%02X",id);

    //Cde data length
    char lc_str[1*2+1]="";
    sprintf(lc_str,"%02X",(int)strlen(impkey)/2);

    //Form the export transient Keyset apdu
    strcat(imp_tr_keyset_apdu_str,"D0A2");
    strcat(imp_tr_keyset_apdu_str,v_str);
    strcat(imp_tr_keyset_apdu_str,id_str);
    strcat(imp_tr_keyset_apdu_str,lc_str);
    strcat(imp_tr_keyset_apdu_str,impkey);

    //Set to apdu cde
    Apdu imp_tr_keyset_apdu;
    setApduCmd(imp_tr_keyset_apdu_str,&imp_tr_keyset_apdu);

    //exchange it
    exchangeApdu(dpd,&imp_tr_keyset_apdu);

    if(strcmp(imp_tr_keyset_apdu.sw_str,"9000")){
        fprintf(stderr,"\nimportKey(): Cannot import key !\n");
        return;
    }else{
        fprintf(stderr,"\nimportKey(): Key successfully imported.\n");
        return;
    }

}

void DAPLUGCALL Daplug_createFile(DaplugDongle *dpd, int id, int size, int ac[3], int isFileEnc, int isCntFile){

    char create_file_apdu_str[APDU_CMD_MAXLEN*2+1]="80e000001c6214820201218302";

    char id_s[2*2+1]="", size_s[2*2+1]="", ac1_s[1*2+1]="",
         ac2_s[1*2+1]="", ac3_s[1*2+1]="",
         ife[1*2+1]="", icf[1*2+1]="";

    sprintf(id_s,"%04X",id);
    if(isCntFile){ sprintf(size_s,"%04X",8);} //A counter file shall be created with a length set to 8 bytes
    else{ sprintf(size_s,"%04X",size);}
    sprintf(ac1_s,"%02X",ac[0]);
    sprintf(ac2_s,"%02X",ac[1]);
    sprintf(ac3_s,"%02X",ac[2]);

    if(isFileEnc){strcpy(ife,"01");}
    else {strcpy(ife,"00");}

    if(isCntFile){strcpy(icf,"01");}
    else {strcpy(icf,"00");}

    strcat(create_file_apdu_str,id_s);
    strcat(create_file_apdu_str,"8102");
    strcat(create_file_apdu_str,size_s);
    strcat(create_file_apdu_str,"8c0600");
    strcat(create_file_apdu_str,ac1_s);
    strcat(create_file_apdu_str,"0000");
    strcat(create_file_apdu_str,ac2_s);
    strcat(create_file_apdu_str,ac3_s);
    strcat(create_file_apdu_str,"8601");
    strcat(create_file_apdu_str,ife);
    strcat(create_file_apdu_str,"8701");
    strcat(create_file_apdu_str,icf);

    //Set to apdu cde
    Apdu create_file_apdu;
    setApduCmd(create_file_apdu_str,&create_file_apdu);

    //exchange it
    exchangeApdu(dpd,&create_file_apdu);

    if(strcmp(create_file_apdu.sw_str,"9000")){
        fprintf(stderr,"\ncreateFile(): Cannot create file %s !\n",id_s);
        return;
    }else{
        fprintf(stderr,"\ncreateFile(): File %s created.\n",id_s);
    }
}

void DAPLUGCALL Daplug_createDir(DaplugDongle *dpd, int id, int ac[3]){

    char create_dir_apdu_str[APDU_CMD_MAXLEN*2+1]="80e0000010620e820232218302";


    char id_s[2*2+1]="", ac1_s[1*2+1]="",
         ac2_s[1*2+1]="", ac3_s[1*2+1]="";

    sprintf(id_s,"%04X",id);
    sprintf(ac1_s,"%02X",ac[0]);
    sprintf(ac2_s,"%02X",ac[1]);
    sprintf(ac3_s,"%02X",ac[2]);

    strcat(create_dir_apdu_str,id_s);
    strcat(create_dir_apdu_str,"8c0400");
    strcat(create_dir_apdu_str,ac1_s);
    strcat(create_dir_apdu_str,ac2_s);
    strcat(create_dir_apdu_str,ac3_s);

    //Set to apdu cde
    Apdu create_dir_apdu;
    setApduCmd(create_dir_apdu_str,&create_dir_apdu);

    //exchange it
    exchangeApdu(dpd,&create_dir_apdu);

    if(strcmp(create_dir_apdu.sw_str,"9000")){
        fprintf(stderr,"\ncreateDir(): Cannot create directory %s !\n",id_s);
        return;
    }else{
        fprintf(stderr,"\ncreateDir(): Directory %s created.\n",id_s);
    }
}

void DAPLUGCALL Daplug_deleteFileOrDir(DaplugDongle *dpd, int id){

    char delete_file_apdu_str[APDU_CMD_MAXLEN*2+1]="80e4000002";
    char id_s[2*2+1]="";

    sprintf(id_s,"%04X",id);

    strcat(delete_file_apdu_str,id_s);

    //Set to apdu cde
    Apdu delete_file_apdu;
    setApduCmd(delete_file_apdu_str,&delete_file_apdu);

    //exchange it
    exchangeApdu(dpd,&delete_file_apdu);

    if(strcmp(delete_file_apdu.sw_str,"9000")){
        fprintf(stderr,"\ndeleteFileOrDir(): Cannot delete file %s !\n",id_s);
        return;
    }else{
        fprintf(stderr,"\ndeleteFileOrDir(): File %s deleted.\n",id_s);
    }

}

void DAPLUGCALL Daplug_selectFile(DaplugDongle *dpd, int id){

    char select_file_apdu_str[APDU_CMD_MAXLEN*2+1]="80a4000002";

    char id_s[2*2+1]="";

    sprintf(id_s,"%04X",id);

    strcat(select_file_apdu_str,id_s);

    //Set to apdu cde
    Apdu select_file_apdu;
    setApduCmd(select_file_apdu_str,&select_file_apdu);

    //exchange it
    exchangeApdu(dpd,&select_file_apdu);

    if(strcmp(select_file_apdu.sw_str,"9000")){
        fprintf(stderr,"\nselectFile(): Cannot select file %s !\n",id_s);
        return;
    }else{
        fprintf(stderr,"\nselectFile(): File %s selected.\n",id_s);
    }

}

void DAPLUGCALL Daplug_selectPath(DaplugDongle *dpd, char *path){

    if(!isHexInput(path) || strlen(path)%4 != 0){
        fprintf(stderr,"\nselectFile(): Wrong path : %s !\n",path);
        return;
    }

    int i = 0, j = 0, id;

    while(j<strlen(path)/4){
        char *tmp = NULL;
        sscanf(tmp = str_sub(path,i,i+3),"%04X",&id);
        free(tmp);
        tmp = NULL;
        Daplug_selectFile(dpd,id);
        i = i+4;
        j++;

    }

}

void DAPLUGCALL Daplug_readData(DaplugDongle *dpd, int offset, int length, char *read_data){

    char read_binary_apdu_str[APDU_CMD_MAXLEN*2+1]="";
    char pos[2*2+1]="";
    char ret[MAX_FS_FILE_SIZE]=""; //0xffff : file max size

    int p = offset;

    Apdu read_binary_apdu;

    if(length <=0 || length + p > MAX_FS_FILE_SIZE){
        fprintf(stderr,"\nreadData(): Wrong length !\n");
        return;
    }

    sprintf(pos,"%04X",p);

    //We read parts of MAX_FS_DATA_RW_SIZE bytes : EF = FF - 8 - 8 (data max len - possible mac - possible pad when enc)
    int reads_nb = 0;
    if(length % MAX_REAL_DATA_SIZE == 0)
        reads_nb = length/MAX_REAL_DATA_SIZE;
    else reads_nb = (int)length/MAX_REAL_DATA_SIZE+1;

    //when reads_nb = 1 it means that length is < MAX_FS_DATA_RW_SIZE
    while(reads_nb>0){

        strcpy(read_binary_apdu_str,"");
        strcat(read_binary_apdu_str,"80b0");
        strcat(read_binary_apdu_str,pos);
        strcat(read_binary_apdu_str,"00");

        //Set to apdu cde
        setApduCmd(read_binary_apdu_str,&read_binary_apdu);

        //exchange it
        exchangeApdu(dpd,&read_binary_apdu);

        if(strcmp(read_binary_apdu.sw_str,"9000")){
            fprintf(stderr,"\nreadData(): Read failure !\n");
            return;
        }

        strcat(ret,read_binary_apdu.r_str);

        sscanf(pos,"%04X",&p);
        p = p + MAX_REAL_DATA_SIZE;
        sprintf(pos,"%04X",p);

        reads_nb--;

    }

    strcpy(read_data,ret);

}

void DAPLUGCALL Daplug_writeData(DaplugDongle *dpd, int  offset, char* data_to_write){

    Apdu update_binary_apdu;

    char update_binary_apdu_str[APDU_CMD_MAXLEN*2+1]="";
    char pos[2*2+1]="";
    char last_part_len_str[2*2+1]="";

    int p = offset, length = strlen(data_to_write)/2,
        last_part_len = length % MAX_REAL_DATA_SIZE;

    sprintf(last_part_len_str,"%02X",last_part_len);

    if(length%2 !=0 || length <=0 || length + p > MAX_FS_FILE_SIZE || !isHexInput(data_to_write)){
        fprintf(stderr,"\nwriteData(): Wrong data !\n");
        return;
    }

    sprintf(pos,"%04X",p);

    //We write parts of MAX_FS_DATA_RW_SIZE bytes : EF = FF - 8 - 8 (data max len - possible mac - possible pad when enc)
    int write_nb = 0;
    if(length % MAX_REAL_DATA_SIZE== 0) write_nb = length/MAX_REAL_DATA_SIZE; else write_nb = (int)length/MAX_REAL_DATA_SIZE+1;

    char part[MAX_REAL_DATA_SIZE*2+1]="";

    int i = 0;

    while(write_nb > 0){

        strcpy(update_binary_apdu_str,"");
        strcat(update_binary_apdu_str,"80d6");
        strcat(update_binary_apdu_str,pos);

        if(write_nb > 1 || length % MAX_REAL_DATA_SIZE == 0){
            strcat(update_binary_apdu_str,"EF");
            char *tmp = NULL;
            strcpy(part,tmp = str_sub(data_to_write,i,i+MAX_REAL_DATA_SIZE*2-1));
            free(tmp);
            tmp = NULL;
        }else{
            char *tmp = NULL;
            strcat(update_binary_apdu_str,last_part_len_str);
            strcpy(part,tmp = str_sub(data_to_write,i,i+(length%MAX_REAL_DATA_SIZE)*2-1));
            free(tmp);
            tmp = NULL;
        }

        strcat(update_binary_apdu_str,part);

        //Set to apdu cde
        setApduCmd(update_binary_apdu_str,&update_binary_apdu);

        //exchange it
        exchangeApdu(dpd,&update_binary_apdu);

        if(strcmp(update_binary_apdu.sw_str,"9000")){
            fprintf(stderr,"\nwriteData(): Write failure !\n");
            return;
        }

        sscanf(pos,"%04X",&p);
        p = p + MAX_REAL_DATA_SIZE;
        sprintf(pos,"%04X",p);

        i = i+MAX_REAL_DATA_SIZE*2;
        write_nb--;

    }
}

void DAPLUGCALL Daplug_encrypt(DaplugDongle *dpd, int keyVersion, int keyID, int mode, char *iv, char *div1, char *div2,
            char *inData, char *outData){

    encdec(dpd,0x01, keyVersion, keyID, mode, iv, div1, div2, inData, outData);

}

void DAPLUGCALL Daplug_decrypt(DaplugDongle *dpd, int keyVersion, int keyID, int mode, char *iv, char *div1, char *div2,
            char *inData, char *outData){
    encdec(dpd,0x02, keyVersion, keyID, mode, iv, div1, div2, inData, outData);

}

void DAPLUGCALL Daplug_getRandom(DaplugDongle *dpd, int length, char* random){

    char gen_rand_apdu_str[APDU_CMD_MAXLEN*2+1]="D0240000";

    char len_s[2*2+1]="";

    if(length <=0 || length > MAX_REAL_DATA_SIZE){
        fprintf(stderr,"\ngetRandom(): Invalid random length ! Correct length is between 1 and 239 bytes.\n");
        return;
    }

    sprintf(len_s,"%02X",length);

    strcat(gen_rand_apdu_str,len_s);
    //the length here is the returned data length (the apdu does not contain input data)
    //for wrap reason, we use non meaningful data with size Lc
    int i = length;
    while(i>0){
        strcat(gen_rand_apdu_str,"00");
        i--;
    }

    //Set to apdu cde
    Apdu gen_rand_apdu;
    setApduCmd(gen_rand_apdu_str,&gen_rand_apdu);

    //exchange it
    exchangeApdu(dpd,&gen_rand_apdu);

    if(strcmp(gen_rand_apdu.sw_str,"9000")){
        fprintf(stderr,"\ngetRandom(): Cannot generate random !\n");
        return;
    }

    strcpy(random,gen_rand_apdu.r_str);
}

void DAPLUGCALL Daplug_hmac(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData){

    if(options & OTP_6_DIGIT || options & OTP_7_DIGIT || options & OTP_8_DIGIT){
        fprintf(stderr,"\nhmac(): Invalid option for Daplug_hmac !\n");
        return;
    }

    hmac_sha1(dpd, keyVersion, options, div1, div2, inData, outData);
}

void DAPLUGCALL Daplug_hotp(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData){

    char tmp[MAX_REAL_DATA_SIZE*2+1]="";

    if(!(options & OTP_6_DIGIT) && !(options & OTP_7_DIGIT) && !(options & OTP_8_DIGIT)){
        fprintf(stderr,"\nhotp(): Invalid option for Daplug_hotp !\n");
        return;
    }

    if(strlen(inData)/2 != 2 && strlen(inData)/2 != 8){
        fprintf(stderr,"\nhotp(): Invalid data for Daplug_hotp !\n");
        return;
    }

    hmac_sha1(dpd, keyVersion, options, div1, div2, inData, tmp);

    hexToAscii(tmp,outData);

}

void DAPLUGCALL Daplug_totp(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData){

    char tmp[MAX_REAL_DATA_SIZE*2+1]="";

    if(!(options & OTP_6_DIGIT) && !(options & OTP_7_DIGIT) && !(options & OTP_8_DIGIT)){
        fprintf(stderr,"\ntotp(): Invalid option for Daplug_totp !\n");
        return;
    }

    if(strlen(inData)/2 != 0 && strlen(inData)/2 != 8){
        fprintf(stderr,"\ntotp(): Invalid data for Daplug_totp !\n");
        return;
    }

    hmac_sha1(dpd, keyVersion, options, div1, div2, inData, tmp);

    hexToAscii(tmp,outData);

}

void DAPLUGCALL Daplug_setTimeOTP(DaplugDongle *dpd, int keyVersion, int keyId, char *timeSrcKey, int step, int t){

    char set_time_ref_apdu_str[APDU_CMD_MAXLEN*2+1]="D0B2";
    char kv_s[1*2+1]="", kid_s[1*2+1]="";

    sprintf(kid_s,"%02X",keyId);
    sprintf(kv_s,"%02X",keyVersion);

    //Signature
    char temp_in[(11+1+4)*2+1]="",
         temp_out[(11+1+4)*2+1]="",
         signature[8*2+1]="";

    Byte nonce[11];
    char nonce_s[11*2+1]="";
    generateChallenge(nonce,11);
    bytesToStr(nonce,11,nonce_s);

    char step_s[1*2+1]="";
    if(step == 0){step = HOTP_TIME_STEP;}
    sprintf(step_s,"%02X",step);

    char time_s[4*2+1]="";
    if(t == 0){t = (int)time(NULL);}
    sprintf(time_s,"%08X",t);

    strcat(temp_in,nonce_s);
    strcat(temp_in,step_s);
    strcat(temp_in,time_s);

    tripleDES_CBC(temp_in,timeSrcKey,temp_out,DES_ENCRYPT);
    char *tmp = NULL;
    strcpy(signature, tmp = str_sub(temp_out,16,31));
    free(tmp);
    tmp = NULL;

    //Form the apdu
    strcat(set_time_ref_apdu_str,kv_s);
    strcat(set_time_ref_apdu_str,kid_s);
    strcat(set_time_ref_apdu_str,"18");
    strcat(set_time_ref_apdu_str,temp_in);
    strcat(set_time_ref_apdu_str,signature);

    //Set to apdu cde
    Apdu set_time_ref_apdu;
    setApduCmd(set_time_ref_apdu_str,&set_time_ref_apdu);

    //exchange it
    exchangeApdu(dpd,&set_time_ref_apdu);

    if(strcmp(set_time_ref_apdu.sw_str,"9000")){
        fprintf(stderr,"\nsetTimeOTP(): Cannot set time reference for dongle !\n");
        return;
    }else{
        fprintf(stderr,"\nsetTimeOTP(): Dongle_info time reference set.\n");
    }
}

void DAPLUGCALL Daplug_getTimeOTP(DaplugDongle *dpd, char* time){

    char get_time_apdu_str[5*2+1]="D0B0000000";

    //Set to apdu cde
    Apdu get_time_apdu;
    setApduCmd(get_time_apdu_str,&get_time_apdu);

    //exchange it
    exchangeApdu(dpd,&get_time_apdu);

    if(strcmp(get_time_apdu.sw_str,"9000")){
        fprintf(stderr,"\nget_time(): Cannot get dongle time !\n");
        return;
    }

    if(strcmp(str_sub(get_time_apdu.r_str,0,1),"00")){
        char *tmp = NULL;
        strcpy(time,tmp = str_sub(get_time_apdu.r_str,2,9));
        free(tmp);
        tmp = NULL;
    }else{
        char * tmp = NULL;
        fprintf(stderr,"\nget_time(): Dongle_info time reference not set yet !\n");
        free(tmp);
        tmp = NULL;
    }
}

void DAPLUGCALL Daplug_useAsKeyboard(DaplugDongle *dpd){

    char apdu_str[5*2+1]="D032000000";

    //Set to apdu cde
    Apdu apdu;
    setApduCmd(apdu_str,&apdu);

    //exchange it
    exchangeApdu(dpd,&apdu);

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nuseAsKeyboard(): Cannot set keyboard input file !\n");
        return;
    }else{
        fprintf(stderr,"\nuseAsKeyboard(): Keyboard input file set.\n");
        return;
    }
}

void DAPLUGCALL Daplug_setKeyboardAtBoot(DaplugDongle *dpd, int activated){

    char apdu_str[5*2+1]="D032";

    if(activated){
        strcat(apdu_str,"020000");
    }else{
        strcat(apdu_str,"010000");
    }

    //Set to apdu cde
    Apdu apdu;
    setApduCmd(apdu_str,&apdu);

    //exchange it
    exchangeApdu(dpd,&apdu);

    if(strcmp(apdu.sw_str,"9000")){
        if(activated){
            fprintf(stderr,"\nDaplug_setKeyboardAtBoot(): Cannot activate automatic keyboard emulation !\n");
        }else{
            fprintf(stderr,"\nDaplug_setKeyboardAtBoot(): Cannot deactivate automatic keyboard emulation !\n");
        }
        return;
    }else{
        if(activated){
            fprintf(stderr,"\nDaplug_setKeyboardAtBoot(): Automatic keyboard emulation activated.\n");
        }else{
            fprintf(stderr,"\nDaplug_setKeyboardAtBoot(): Automatic keyboard emulation deactivated.\n");
        }
        return;
    }
}

void DAPLUGCALL Daplug_triggerKeyboard(DaplugDongle *dpd){

    char apdu_str[5*2+1]="D030010000";

    //Set to apdu cde
    Apdu apdu;
    setApduCmd(apdu_str,&apdu);

    //exchange it
    exchangeApdu(dpd,&apdu);

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nDaplug_triggerKeyboard(): Cannot trigger keyboard input !\n");
        return;
    }else{
        fprintf(stderr,"\nDaplug_triggerKeyboard(): Keyboard triggered.\n");
        return;
    }
}

void DAPLUGCALL Daplug_hidToWinusb(DaplugDongle *dpd){

    char apdu_str[5*2+1]="d052080200";

    //Set to apdu cde
    Apdu apdu;
    setApduCmd(apdu_str,&apdu);

    //exchange it
    exchangeApdu(dpd,&apdu);

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nDaplug_hidToWinusb(): Cannot switch to winusb mode !\n");
        return;
    }else{
        fprintf(stdout,"\nDaplug_hidToWinusb(): Winusb mode activated.\n");
        return;
    }
}

void DAPLUGCALL Daplug_winusbToHid(DaplugDongle *dpd){

    char apdu_str[5*2+1]="d052080100";

    //Set to apdu cde
    Apdu apdu;
    setApduCmd(apdu_str,&apdu);

    //exchange it
    exchangeApdu(dpd,&apdu);

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nDaplug_winusbToHid(): Cannot switch to hid mode !\n");
        return;
    }else{
        fprintf(stdout,"\nDaplug_winusbToHid(): Hid mode activated.\n");
        return;
    }

}

void DAPLUGCALL Daplug_reset(DaplugDongle *dpd){

    char apdu_str[5*2+1]="d052010000";

    //Set to apdu cde
    Apdu apdu;
    setApduCmd(apdu_str,&apdu);

    //exchange it
    exchangeApdu(dpd,&apdu);

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nDaplug_reset(): Cannot reset dongle !\n");
        return;
    }else{
        fprintf(stdout,"\nDaplug_reset(): Dongle successfully reset.\n");
        return;
    }

}

void DAPLUGCALL Daplug_halt(DaplugDongle *dpd){

    char apdu_str[5*2+1]="d052020000";

    //Set to apdu cde
    Apdu apdu;
    setApduCmd(apdu_str,&apdu);

    //exchange it
    exchangeApdu(dpd,&apdu);

    if(strcmp(apdu.sw_str,"9000")){
        fprintf(stderr,"\nDaplug_halt(): Cannot halt dongle !\n");
        return;
    }else{
        fprintf(stdout,"\nDaplug_halt(): Dongle successfully halted.\n");
        return;
    }

}
