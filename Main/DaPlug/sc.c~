/**
 * \file sc.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.0
 * \date 02/12/2013
 * \warning Functions are not documented
 *
 * Differents security functions used in a secure channel session.
 *
 */

#include <daplug/sc.h>

void generateChallenge(unsigned char *challenge,int chl_size){

    int r = 0;

    r = RAND_bytes(challenge,chl_size);

    if (!r) {
        fprintf(stderr,"\ngenerateChallenge() error !\n");
        return;
    }

}

void computeCardCryptogram(char *hostChallenge,char *cardChallenge,char *counter,char *s_encKey, char *cardCryptogram){
    char temp[24*2+1]="";

    strcat(temp,hostChallenge);
    strcat(temp,counter);
    strcat(temp,cardChallenge);

    computeFull3DesMac(temp, s_encKey,cardCryptogram);

}

void computeHostCryptogram(char *hostChallenge,char *cardChallenge,char *counter,char *s_encKey,char *hostCryptogram){
    char temp[24*2+1]="";

    strcat(temp,counter);
    strcat(temp,cardChallenge);
    strcat(temp,hostChallenge);

    computeFull3DesMac(temp, s_encKey,hostCryptogram);

}


void computeFull3DesMac(char *data, char *key, char *full3DesMac)
{
    char pad[8*2+1]="8000000000000000",
         s_out[24*2+1]="";
    unsigned char bytes_data[24],out[24],
                  key1[8], key2[8],iv[8];
    des_key_schedule ks1,ks2;

    strcat(data,pad);

    strToBytes(data,bytes_data);
    char *tmp = NULL;
    strToBytes(tmp = str_sub(key,0,15), key1);
    free(tmp);
    tmp = NULL;
    strToBytes(tmp = str_sub(key,16,31), key2);
    free(tmp);
    tmp = NULL;

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    memset(iv,0x00,8);

    des_ede3_cbc_encrypt(bytes_data, out, (long) 24, ks1,ks2,ks1, (C_Block *)iv, DES_ENCRYPT);

    bytesToStr(out,24,s_out);

    strcpy(full3DesMac,tmp = str_sub(s_out,32,48));
    free(tmp);
    tmp = NULL;
}

void computeSessionKey(char *counter,char *keyConstant, char *masterKey, char *s_sessionKey){ //OK

    char string_buf[16*2+1]="";
    unsigned char bytes_buf[16],
                  sessionKey[16];

    unsigned char key1[8], key2[8],iv[8];
    des_key_schedule ks1,ks2;

    strcat(string_buf,keyConstant);
    strcat(string_buf,counter);
    strcat(string_buf,"000000000000000000000000");

    strToBytes(string_buf,bytes_buf);
    char *tmp = NULL;
    strToBytes(tmp = str_sub(masterKey,0,15), key1);
    free(tmp);
    tmp = NULL;
    strToBytes(tmp = str_sub(masterKey,16,31), key2);
    free(tmp);
    tmp = NULL;

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    memset(iv,0x00,8);

    des_ede3_cbc_encrypt(bytes_buf, sessionKey, (long) 16, ks1,ks2,ks1, (C_Block *)iv, DES_ENCRYPT);

    bytesToStr(sessionKey,16,s_sessionKey);
}

int checkCardCryptogram(char *returnedCardCryptogram, char *computedCardCryptogram){
    int r;
    r=strncmp(returnedCardCryptogram,computedCardCryptogram,strlen(returnedCardCryptogram));

    if(r==0) return 1; else return 0;
}

void computeRetailMac(const char *data, char *key, char *previousMac, char *retailMac, int cmac)
{
    int i,l=0;
    //max = max apdu len+1+max rep data len+sw len+any retail pad len+any prevous mac len
    char temp[(5+255+1+255+2+8+8)*2+1]= "";//
    unsigned char work1[5+255+1+255+2+8],work2[8],work3[8],work4[5+255+1+255+2+8], out[8], icv[8],
                  key1[8], key2[8];
    des_key_schedule ks1,ks2;

    if(cmac) memset(icv,0,8); //null iv, c-mac case
    else strToBytes(previousMac,icv); //r-mac case

    memset(work4,0,5+255+1+255+2+8);

    if(cmac) strcpy(temp,previousMac); //c-mac case
    strcat(temp,data);
    //padding
    strcat(temp,"80");
    while(strlen(temp)%(8*2) != 0){
        strcat(temp,"00");
    }

    l=strlen(temp);

    char *tmp = NULL;
    strToBytes(tmp = str_sub(key,0,15), key1);
    free(tmp);
    tmp = NULL;
    //*simple des cbc using the first part of the key on L-8 temp bytes
    des_set_key((C_Block *)key1, ks1);

    strToBytes(tmp = str_sub(temp,0,l-8*2-1),work1); //L-8 temp bytes
    free(tmp);
    tmp = NULL;

    des_ncbc_encrypt(work1,work4,(long)(l-8*2)/2,ks1,(C_Block *)icv, DES_ENCRYPT);
    //*/

    strToBytes(tmp = str_sub(temp,l-8*2,l-1),work2); //last 8 bytes of temp
    free(tmp);
    tmp = NULL;

    //*exclusive or between last 8 bytes of temp and the last block of the last simple DES
    for(i=0;i<8;i++){
        work3[i]= work2[i] ^ work4[i+l/2-16];
    }
    //*/

    //*triple DES ecb on the last result
    strToBytes(tmp = str_sub(key,16,31), key2);
    free(tmp);
    tmp = NULL;

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    des_ecb3_encrypt((DES_cblock *)work3, (DES_cblock *)out, ks1,ks2,ks1, DES_ENCRYPT);

    //*/

    bytesToStr(out,8,retailMac);

}

int createPutKeyCommand(char *numKeyset, char *mode, char *sdekKey, char* gp_enc, char *gp_mac, char *gp_dek, char *keyUsage, char *keyAccess, char *putKeyCommand){

    char putKeyCommand_temp[(255+5)*2+1]="",
         element1[2*2+1]="80d8",
         element2[1*2+1]="", //numKeyset
         element3[1*2+1]="", //mode
         element4[1*2+1]="55", //"58", //Lc
         element5[3*2+1]="ff8010", //key type + key length
         element6[16*2+1]="", //(GP-ENC) value, wrapped by session DEK
         element7[1*2+1]="03", //KCV length
         element8[3*2+1]="", //Key1 KCV
         element9[1*2+1]="01", //key usage length
         element10[1*2+1]="", //key usage
         element11[1*2+1]="02", //key access length
         element12[2*2+1]="", //key access
         element13[16*2+1]="", //(GP-MAC) value, wrapped by session DEK
         element14[3*2+1]="", //Key2 KCV
         element15[16*2+1]="", //(GP-DEK) value, wrapped by session DEK
         element16[3*2+1]="", //Key3 KCV
         element17[10*2+1]=""; //Keyset diversifier value for a GlobalPlatform Keyset

    strcpy(element2,numKeyset);
    strcpy(element3,mode);
    strcpy(element10,keyUsage);
    strcpy(element12,keyAccess);

    /*Encrypt gp-keys*/

    char tmp[8*2+1]="";

    char *temp = NULL;
    //Daplug_encrypt key1
    if(tripleDES_ECB_encrypt(temp = str_sub(gp_enc,0,15),sdekKey,tmp)){
        free(temp);
        temp = NULL;
        strcat(element6,tmp);
    }
    else
        return 0;
    if(tripleDES_ECB_encrypt(temp = str_sub(gp_enc,16,31),sdekKey,tmp)){
        free(temp);
        temp = NULL;
        strcat(element6,tmp);
    }
    else
        return 0;
    //Daplug_encrypt key2
    if(tripleDES_ECB_encrypt(temp = str_sub(gp_mac,0,15),sdekKey,tmp)){
        free(temp);
        temp = NULL;
        strcat(element13,tmp);
    }
    else
        return 0;
    if(tripleDES_ECB_encrypt(temp = str_sub(gp_mac,16,31),sdekKey,tmp)){
        free(temp);
        temp = NULL;
        strcat(element13,tmp);
    }
    else
        return 0;
    //Daplug_encrypt key3
    if(tripleDES_ECB_encrypt(temp = str_sub(gp_dek,0,15),sdekKey,tmp)){
        free(temp);
        temp = NULL;
        strcat(element15,tmp);
    }
    else
        return 0;
    if(tripleDES_ECB_encrypt(temp = str_sub(gp_dek,16,31),sdekKey,tmp)){
        free(temp);
        temp = NULL;
        strcat(element15,tmp);
    }
    else
        return 0;

    /*Compute KCVs*/

    //kcv1
    computeKCV(gp_enc,element8);
    //kcv2
    computeKCV(gp_mac,element14);
    //kcv3
    computeKCV(gp_dek,element16);

    //form the put key command
    strcat(putKeyCommand_temp,element1);
    strcat(putKeyCommand_temp,element2);
    strcat(putKeyCommand_temp,element3);
    strcat(putKeyCommand_temp,element4);
    strcat(putKeyCommand_temp,element2);
    strcat(putKeyCommand_temp,element5);
    strcat(putKeyCommand_temp,element6);
    strcat(putKeyCommand_temp,element7);
    strcat(putKeyCommand_temp,element8);
    strcat(putKeyCommand_temp,element9);
    strcat(putKeyCommand_temp,element10);
    strcat(putKeyCommand_temp,element11);
    strcat(putKeyCommand_temp,element12);
    strcat(putKeyCommand_temp,element5);
    strcat(putKeyCommand_temp,element13);
    strcat(putKeyCommand_temp,element7);
    strcat(putKeyCommand_temp,element14);
    strcat(putKeyCommand_temp,element9);
    strcat(putKeyCommand_temp,element10);
    strcat(putKeyCommand_temp,element11);
    strcat(putKeyCommand_temp,element12);
    strcat(putKeyCommand_temp,element5);
    strcat(putKeyCommand_temp,element15);
    strcat(putKeyCommand_temp,element7);
    strcat(putKeyCommand_temp,element16);
    strcat(putKeyCommand_temp,element9);
    strcat(putKeyCommand_temp,element10);
    strcat(putKeyCommand_temp,element11);
    strcat(putKeyCommand_temp,element12);
    strcat(putKeyCommand_temp,element17);

    strcpy(putKeyCommand,putKeyCommand_temp);

    return 1;
}

int tripleDES_ECB_encrypt(char *data, char *key, char *encrypted_data){

    if(strlen(data)!=16){
        //fprintf(stderr,"\ntripleDES_ECB_encrypt() error : wrong data length !");
        return 0;
    }

    unsigned char bytes_data_buf[8], bytes_encrypted_data_buf[8],
                  key1[8], key2[8];
    des_key_schedule ks1,ks2;

    //prepare key compenents
    char * tmp = NULL;
    strToBytes(tmp = str_sub(key,0,15), key1);
    free(tmp);
    tmp = NULL;
    strToBytes(tmp = str_sub(key,16,31), key2);
    free(tmp);
    tmp = NULL;
    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    //prepare data
    strToBytes(data,bytes_data_buf);

    //Daplug_encrypt
    des_ecb3_encrypt((DES_cblock *)bytes_data_buf, (DES_cblock *) bytes_encrypted_data_buf, ks1,ks2,ks1, DES_ENCRYPT);

    //the result
    bytesToStr(bytes_encrypted_data_buf,8,encrypted_data);

    return 1;

}

int computeKCV(char *key, char *kcv){

    char buf[8*2+1]="", *kcv_temp = NULL;
    tripleDES_ECB_encrypt("0000000000000000",key,buf);
    kcv_temp = str_sub(buf,0,5);
    strncpy(kcv,kcv_temp,6);
    free(kcv_temp);
    kcv_temp = NULL;

    return 1;
}

void computeDiversifiedKey(char *key, char *s_diversifier, char *divKey){

    unsigned char bytes_diversifiedKey[16], diversifier[16];

    unsigned char key1[8], key2[8],iv[8];

    des_key_schedule ks1,ks2;

    char diversifiedKey[16*2+1]="";

    strToBytes(s_diversifier,diversifier);
    char *tmp = NULL;
    strToBytes(tmp = str_sub(key,0,15), key1);
    free(tmp);
    tmp = NULL;
    strToBytes(tmp = str_sub(key,16,31), key2);
    free(tmp);
    tmp = NULL;

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    memset(iv,0x00,8);

    des_ede3_cbc_encrypt(diversifier, bytes_diversifiedKey, (long) 16, ks1,ks2,ks1, (C_Block *)iv, DES_ENCRYPT);

    bytesToStr(bytes_diversifiedKey,16,diversifiedKey);

    strcpy(divKey,diversifiedKey);

}

void dataEncryption(const char *old_data, const char *key, char *new_data, int enc){

    char padded_old_data[255*2+1]="",
         temp[255*2+1]="";

    Byte new_data_bytes[255],
         padded_old_data_bytes[255],
         key1[8], key2[8],null_iv[8];

    des_key_schedule ks1,ks2;

    memset(null_iv,0x00,8);

    //*padding if encryption
    strncpy(padded_old_data,old_data,sizeof(padded_old_data));
    if(enc){
        strcat(padded_old_data,"80");

        while((strlen(padded_old_data)/2)%8 != 0){
            strcat(padded_old_data,"00");
        }
        //*/
    }

    strToBytes(padded_old_data,padded_old_data_bytes);
    char *tmp = NULL;
    strToBytes(tmp = str_sub(key,0,15), key1);
    free(tmp);
    tmp = NULL;
    strToBytes(tmp = str_sub(key,16,31), key2);
    free(tmp);
    tmp = NULL;

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    //3-DES-CBC
    des_ede3_cbc_encrypt(padded_old_data_bytes, new_data_bytes, (long) strlen(padded_old_data)/2, ks1,ks2,ks1, (C_Block *)null_iv, enc);

    bytesToStr(new_data_bytes,strlen(padded_old_data)/2,temp);

    strcpy(new_data,temp);

}

void tripleDES_CBC(char *data, char *key, char *encrypted_data, int enc){

    Byte encrypted_data_bytes[255], data_bytes[255],
         key1[8], key2[8],null_iv[8];

    des_key_schedule ks1,ks2;

    memset(null_iv,0x00,8);

    strToBytes(data,data_bytes);
    char *tmp = NULL;
    strToBytes(tmp = str_sub(key,0,15), key1);
    free(tmp);
    tmp = NULL;
    strToBytes(tmp = str_sub(key,16,31), key2);
    free(tmp);
    tmp = NULL;

    des_set_key((C_Block *)key1, ks1);
    des_set_key((C_Block *)key2, ks2);

    //3-DES-CBC
    des_ede3_cbc_encrypt(data_bytes, encrypted_data_bytes, (long) strlen(data)/2, ks1,ks2,ks1, (C_Block *)null_iv, enc);

    bytesToStr(encrypted_data_bytes,strlen(data)/2,encrypted_data);

}
