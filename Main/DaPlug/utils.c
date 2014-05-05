/**
 * \file utils.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.0
 * \date 02/12/2013
 * \warning Functions are not documented
 *
 * Differents utility functions.
 *
 */

#include "utils.h"

char *str_sub (const char *s, int start, int end)
{
    char *new_s = NULL;

    if (s != NULL)
    {
    int lastIndex = strlen(s) - 1;

        if(end > lastIndex){ //end index can't exceed s last index
            end = lastIndex;
        }

        if((end < start) || (start > lastIndex)){ //returns the empty string if end index < start index or if start index exceeds s last index
            new_s = malloc(sizeof (*new_s));
            if(new_s != NULL){
                new_s[0] = '\0';
                return new_s;
            }
            else{
                free(new_s);
                fprintf (stderr, "\nstr_sub(): Insufficient memory !\n");
                exit (EXIT_FAILURE);
            }
        }

        new_s = malloc (sizeof (*new_s) * (end - start + 2)); //2 = 1 (because index strats at 0) + 1 (null character at the end of a string)
        if (new_s != NULL)
        {
            int i;
            for (i = start; i <= end; i++){
            new_s[i-start] = s[i];
            }
            new_s[i-start] = '\0';
        }
        else
        {
            free(new_s);
            fprintf (stderr, "\nstr_sub(): Insufficient memory !\n");
            exit (EXIT_FAILURE);
        }
    }

    return new_s;
}

void strToBytes(const char *str, Byte *bytes_array){

    int i,j,tmp, str_size;
    char *extracted_byte = NULL;

    str_size=strlen(str);

    for(i=0,j=0;i<str_size-1;i=i+2,j++){
        extracted_byte=str_sub(str,i,i+1);
        sscanf(extracted_byte,"%x",&tmp);
        bytes_array[j]=tmp;
        free(extracted_byte);
        extracted_byte = NULL;
    }

}

void bytesToStr(Byte *bytes,int bytes_s,char *str){

    int i;
    char tmp[2+1]="";
    strcpy(str,"");

    for(i=0;i<bytes_s;i++){
        sprintf(tmp,"%02hx",bytes[i]);
        strncat(str,tmp,2);
    }

    str[bytes_s*2]='\0';

}

int isHexInput(const char *input){

    int i=0,j,is_hex=1,
    input_length=strlen(input);
    char *hex_nb = "0123456789abcdefABCDEF";

    if(input_length%2 != 0){
        return 0;
    }

    while((i<input_length) && (is_hex==1))
    {
        j=0;
        while(j<22){
            if(input[i]!=hex_nb[j]){
                is_hex=0;
                j++;
            }
            else{
                is_hex=1;
                break;
            }
        }
        i++;
    }

    return is_hex;
}

void asciiToHex(const char *s,char* s_hex){

    int i;
    char tmp[3]="";

    strcpy(s_hex,"");

    for(i=0;i<strlen(s);i++){
        sprintf(tmp,"%02hX",s[i]);
        strcat(s_hex,tmp);
    }
}

void hexToAscii(const char *s_hex,char* s){

    int i, len = strlen(s_hex)/2;
    char tmp[2]="";
    unsigned char b_s_hex[len];

    if(!isHexInput(s_hex)){
        fprintf(stderr,"\nhexToAscii(): Invalid data !\n");
        return;
    }

    strcpy(s,"");
    strToBytes(s_hex,b_s_hex);

    for(i=0;i<len;i++){
       sprintf(tmp,"%c",b_s_hex[i]);
       strcat(s,tmp);
    }

}
