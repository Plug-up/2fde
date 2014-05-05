/**
 * \file keyset.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.0
 * \date 02/12/2013
 *
 * Helps to manipulate keysets.
 *
 */

#include <daplug/keyset.h>

void DAPLUGCALL keyset_createKeys(Keyset *keys, int version,const char* encKey,const char* macKey,const char* dekKey){

    keys->version = version;

    if(!strcmp(encKey,"")){
        fprintf(stderr,"keyset_createKeys(): \nNo ENC key !");
        return;
    }
    else
    {
        strToBytes(encKey,keys->key[0]);

        if(strcmp(macKey,""))
            strToBytes(macKey,keys->key[1]);
        else
            strToBytes(encKey,keys->key[1]);

        if(strcmp(dekKey,""))
            strToBytes(dekKey,keys->key[2]);
        else
            strToBytes(encKey,keys->key[2]);
    }

    memset(keys->access,0x00,2);
    keys->usage = 0x00;

}

void DAPLUGCALL keyset_setVersion(Keyset *keys, int version){
    keys->version = version;
}

void DAPLUGCALL keyset_getVersion(Keyset keys, int *version){
    *version = keys.version;
}

void DAPLUGCALL keyset_setKey(Keyset *keys,int id, char *key_value){

    strToBytes(key_value,keys->key[id]);

}

void DAPLUGCALL keyset_getKey(Keyset keys,int id, char *key_value){

    bytesToStr(keys.key[id],GP_KEY_SIZE, key_value);

}

void DAPLUGCALL keyset_getKeyUsage(Keyset keys, keyset_usage *ku){
    *ku=keys.usage;
}

void DAPLUGCALL keyset_setKeyAccess(Keyset *keys,Byte access[2]){
    keys->access[0]=access[0];
    keys->access[1]=access[1];
}

void DAPLUGCALL keyset_getKeyAccess(Keyset keys,Byte access[2]){
    access[0] = keys.access[0];
    access[1] = keys.access[1];
}
