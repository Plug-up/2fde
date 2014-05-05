/**
 * \file keyboard.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.0
 * \date 02/12/2013
 *
 * Helps to create the keyboard file content to be uploaded to a dongle.
 *
 */

#include "keyboard.h"

void DAPLUGCALL keyboard_init(Keyboard *k){
    strcpy(k->content,"");
    k->currentContentSize = 0;
}

void DAPLUGCALL keyboard_getContent(Keyboard *k, char *content){

    strcpy(content, k->content);
}

void DAPLUGCALL keyboard_addOSProbe(Keyboard *k, int nb, int delay, int code){

    char nb_s[1*2+1]="",
         delay_s[2*2+1]="",
         code_s[1*2+1]="";

    int added_len = 0;

    if(nb==-1) nb = 0x10;
    if(delay == -1) delay = 0xFFFF;
    if (code == -1) code = 0x00;

    sprintf(nb_s,"%02X",nb);
    sprintf(delay_s,"%04X",delay);
    sprintf(code_s,"%02X",code);

    added_len = strlen("1004")+strlen(nb_s)+strlen(delay_s)+strlen(code_s);
    added_len = added_len/2;

    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        strcat(k->content,"1004");
        strcat(k->content,nb_s);
        strcat(k->content,delay_s);
        strcat(k->content,code_s);
        k->currentContentSize = k->currentContentSize + added_len;
    }
    else{
        fprintf(stderr,"\nkeyboard_addOSProbe(): Keyboard maximum content size exceeded !\n");
        return;
    }

}

void DAPLUGCALL keyboard_addOSProbeWinR(Keyboard *k, int nb, int delay, int code){

    char nb_s[1*2+1]="",
         delay_s[2*2+1]="",
         code_s[1*2+1]="";

    int added_len = 0;

    if(nb==-1) nb = 0x14;
    if(delay == -1) delay = 0xFFFF;
    if (code == -1) code = 0x00;

    sprintf(nb_s,"%02X",nb);
    sprintf(delay_s,"%04X",delay);
    sprintf(code_s,"%02X",code);

    added_len = strlen("0204")+strlen(nb_s)+strlen(delay_s)+strlen(code_s);
    added_len = added_len/2;

    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        strcat(k->content,"0204");
        strcat(k->content,nb_s);
        strcat(k->content,delay_s);
        strcat(k->content,code_s);
        k->currentContentSize = k->currentContentSize + added_len;
    }
    else{
        fprintf(stderr,"\nkeyboard_addOSProbeWinR(): Keyboard maximum content size exceeded !\n");
        return;
    }
}

void DAPLUGCALL keyboard_addIfPC(Keyboard *k){

    int added_len = strlen("0E00");
    added_len = added_len/2;

    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        strcat(k->content,"0E00");
        k->currentContentSize = k->currentContentSize+added_len;
    }else{
        fprintf(stderr,"\nkeyboard_addOSProbe(): Keyboard maximum content size exceeded !\n");
        return;
    }
}

void DAPLUGCALL keyboard_addIfMac(Keyboard *k){

    int added_len = strlen("0F00");
    added_len = added_len/2;


    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        strcat(k->content,"0F00");
        k->currentContentSize = k->currentContentSize+added_len;
    }else{
        fprintf(stderr,"\nkeyboard_addOSProbe(): Keyboard maximum content size exceeded !\n");
        return;
    }
}

static void DAPLUGCALL addAsciiText(Keyboard *k, char *text){

    int text_len = strlen(text);

    char text_hex[text_len*2+1];

    strcpy(text_hex,"");
    asciiToHex(text,text_hex);

    int added_len = strlen(text_hex);
    added_len = added_len/2;

    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        strcat(k->content,text_hex);
        k->currentContentSize = k->currentContentSize+added_len;
    }else{
        fprintf(stderr,"\nkeyboard_addOSProbe(): Keyboard maximum content size exceeded !\n");
        return;
    }
}

void DAPLUGCALL keyboard_addTextWindows(Keyboard *k, char *text){

    int len_text = strlen(text),
        added_len,
        nb = 0,
        i = 0;

    char last_part_len_s[1*2+1]="",
         mwtl_s[1*2+1]="",
         *part = NULL;

    sprintf(mwtl_s,"%02X",MAX_WINDOWS_TEXT_LEN);


    int last_part_len = len_text % MAX_WINDOWS_TEXT_LEN;
    sprintf(last_part_len_s,"%02X",last_part_len);

    if(last_part_len == 0) nb = len_text/MAX_WINDOWS_TEXT_LEN; else nb = (int)len_text/MAX_WINDOWS_TEXT_LEN+1;

    while(nb>0){
        added_len = strlen("04")+strlen(mwtl_s);
        added_len = added_len/2;
        if(nb > 1 || last_part_len == 0){
            if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
                strcat(k->content,"04");
                strcat(k->content,mwtl_s);
                part = str_sub(text,i,i+MAX_WINDOWS_TEXT_LEN-1);
                addAsciiText(k,part);
                free(part);
                part = NULL;
                k->currentContentSize = k->currentContentSize+added_len;
            }
            else{
                fprintf(stderr,"\nkeyboard_addOSProbe(): Keyboard maximum content size exceeded !\n");
                return;
            }
        }else{
            if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
                strcat(k->content,"04");
                strcat(k->content,last_part_len_s);
                part = str_sub(text,i,i+last_part_len-1);
                addAsciiText(k,part);
                free(part);
                part = NULL;
                k->currentContentSize = k->currentContentSize+added_len;
            }
            else{
                fprintf(stderr,"\nkeyboard_addOSProbe(): Keyboard maximum content size exceeded !\n");
                return;
            }
        }

        i = i+MAX_WINDOWS_TEXT_LEN;
        nb--;
    }

}

void DAPLUGCALL keyboard_addTextMac(Keyboard *k, char *text, int azerty, int delay){

    int len_text = strlen(text),
        added_len,
        nb = 0,
        i = 0;

    char last_part_len_s[1*2+1]="",
         mmtl_s[1*2+1]="",
         azerty_s[1*2+1]="",
         delay_s[2*2+1]="",
         *part = NULL;

    if(azerty==-1) azerty = 0;
    if(delay == -1) delay = 0x1000;

    sprintf(azerty_s,"%02X",azerty);
    sprintf(delay_s,"%04X",delay);

    sprintf(mmtl_s,"%02X",MAX_MAC_TEXT_LEN+3);

    int last_part_len = len_text % MAX_MAC_TEXT_LEN;
    sprintf(last_part_len_s,"%02X",last_part_len+3);

    if(last_part_len == 0) nb = len_text/MAX_MAC_TEXT_LEN; else nb = (int)len_text/MAX_MAC_TEXT_LEN+1;

    while(nb>0){
        added_len = strlen("11")+strlen(mmtl_s)+strlen(azerty_s)+strlen(delay_s);
        added_len = added_len/2;
        if(nb > 1 || last_part_len == 0){
            if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
                strcat(k->content,"11");
                strcat(k->content,mmtl_s);
                strcat(k->content,azerty_s);
                strcat(k->content,delay_s);
                part = str_sub(text,i,i+MAX_MAC_TEXT_LEN-1);
                addAsciiText(k,part);
                free(part);
                part = NULL;
                k->currentContentSize = k->currentContentSize+added_len;
            }
            else{
                fprintf(stderr,"\nkeyboard_addOSProbe(): Keyboard maximum content size exceeded !\n");
                return;
            }
        }else{
            if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
                strcat(k->content,"11");
                strcat(k->content,last_part_len_s);
                strcat(k->content,azerty_s);
                strcat(k->content,delay_s);
                part = str_sub(text,i,i+last_part_len-1);
                addAsciiText(k,part);
                free(part);
                part = NULL;
                k->currentContentSize = k->currentContentSize+added_len;
            }
            else{
                fprintf(stderr,"\nkeyboard_addOSProbe(): Keyboard maximum content size exceeded !\n");
                return;
            }
        }

        i = i+MAX_MAC_TEXT_LEN;
        nb--;
    }

}

void DAPLUGCALL keyboard_addKeyCodeRaw(Keyboard *k, char *code){

    int len_code = strlen(code)/2;
    char len_code_s[1*2+1]="";
    sprintf(len_code_s,"%02X",len_code);

    int added_len = strlen("09")+strlen(len_code_s)+strlen(code);
    added_len = added_len/2;


    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        strcat(k->content,"09");
        strcat(k->content,len_code_s);
        strcat(k->content,code);
        k->currentContentSize = k->currentContentSize+added_len;
    }else{
        fprintf(stderr,"\nkeyboard_addKeyCodeRaw(): Keyboard maximum content size exceeded !\n");
        return;
    }

}

void DAPLUGCALL keyboard_addKeyCodeRelease(Keyboard *k,char *code){

    int len_code = strlen(code)/2;
    char len_code_s[1*2+1]="";
    sprintf(len_code_s,"%02X",len_code);

    int added_len = strlen("03")+strlen(len_code_s)+strlen(code);
    added_len = added_len/2;


    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        strcat(k->content,"03");
        strcat(k->content,len_code_s);
        strcat(k->content,code);
        k->currentContentSize = k->currentContentSize+added_len;
    }else{
        fprintf(stderr,"\nkeyboard_addKeyCodeRelease(): Keyboard maximum content size exceeded !\n");
        return;
    }

}

void DAPLUGCALL keyboard_addHotpCode(Keyboard *k, int flag, int digitsNb, int keysetVersion, int counterFileId, char *div){

    char flag_s[1*2+1]="",
         digitsNb_s[1*2+1]="",
         ksv_s[1*2+1]="",
         cfi_s[2*2+1]="",
         tmp[21*2+1]="";

    sprintf(flag_s,"%02X",flag);
    sprintf(digitsNb_s,"%02X",digitsNb);
    sprintf(ksv_s,"%02X",keysetVersion);
    sprintf(cfi_s,"%04X",counterFileId);

    strcat(tmp,flag_s);
    strcat(tmp,digitsNb_s);
    strcat(tmp,ksv_s);
    if(strcmp(div,"")){
        if(isHexInput(div) && strlen(div)/2 == 16){
            strcat(tmp,div);
        }else{
            fprintf(stderr,"\nkeyboard_addHotpCode(): Invalid diversifier !\n");
            return;
        }
    }
    strcat(tmp,cfi_s);

    int len_tmp = strlen(tmp)/2;
    char len_tmp_s[1*2+1]="";
    sprintf(len_tmp_s,"%02X",len_tmp);

    int added_len = strlen("50")+strlen(len_tmp_s)+strlen(tmp);
    added_len = added_len/2;

    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        strcat(k->content,"50");
        strcat(k->content,len_tmp_s);
        strcat(k->content,tmp);
        k->currentContentSize = k->currentContentSize+added_len;
    }else{
        fprintf(stderr,"\nkeyboard_addReturn(): Keyboard maximum content size exceeded !\n");
        return;
    }

}

void DAPLUGCALL keyboard_addReturn(Keyboard *k){

    int added_len = strlen("0D00");
    added_len = added_len/2;

    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        strcat(k->content,"0D00");
        k->currentContentSize = k->currentContentSize+added_len;
    }else{
        fprintf(stderr,"\nkeyboard_addReturn(): Keyboard maximum content size exceeded !\n");
        return;
    }

}

void DAPLUGCALL keyboard_addSleep(Keyboard *k, int duration){

    char duration_s[4*2+1]="";
    int added_len = 0;

    if(duration==-1){
        duration = 0xFFFF;
    }

    if(duration>0xFFFF){
        sprintf(duration_s,"%08X",duration);
    }else{
        sprintf(duration_s,"%04X",duration);
    }

    added_len = strlen("0104")+strlen(duration_s);
    added_len = added_len/2;

    if(k->currentContentSize+added_len <= MAX_KB_CONTENT_SIZE){
        if(duration > 0xFFFF) {strcat(k->content,"0104");}
        else {strcat(k->content,"0102");}
        strcat(k->content,duration_s);
        k->currentContentSize = k->currentContentSize+added_len;
    }else{
        fprintf(stderr,"\nkeyboard_addSleep(): Keyboard maximum content size exceeded !\n");
        return;
    }

}

void DAPLUGCALL keyboard_zeroPad(Keyboard *k, int size){

    if(size <= k->currentContentSize){
        fprintf(stderr,"\nkeyboard_zeroPad(): Keyboard content size exceeded !\n");
        return;
    }

    while(size > k->currentContentSize){

        if(k->currentContentSize+1 <= MAX_KB_CONTENT_SIZE){
            strcat(k->content,"00");
            k->currentContentSize = k->currentContentSize+1;
        }else{
            fprintf(stderr,"\nkeyboard_zeroPad(): Keyboard maximum content size exceeded !\n");
            return;
        }

    }

}
