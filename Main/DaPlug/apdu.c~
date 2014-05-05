/**
 * \file apdu.c
 * \brief
 * \author S.BENAMAR s.benamar@plug-up.com
 * \version 1.0
 * \date 02/12/2013
 *
 * Define Apdu object to manipulate APDU commands/responses.
 *
 */

#include <daplug/apdu.h>

static void initApdu(Apdu *a){

    memset(a->cmd,0x00, APDU_CMD_MAXLEN);
    memset(a->rep_data,0x00,APDU_D_MAXLEN);
    memset(a->sw,0x00,2);

    a->cmd_len = 0;
    a->rep_data_len = 0;

    a->c_str[0]='\0';
    a->r_str[0]='\0';
    a->sw_str[0]='\0';
    a->cmd0[0]='\0';
}

int setApduCmd(const char *user_input, Apdu *a){

    int user_input_length=strlen(user_input);

    //initialization
    initApdu(a);

    //Is everything ok?
    if((user_input_length == 0) || (!isHexInput(user_input))||(user_input_length/2>APDU_CMD_MAXLEN)){
        fprintf(stderr, "\nsetApduCmd(): Not a valid apdu !\n");
        return 0;
    }
    else{
        //update apdu
        strcpy(a->c_str,user_input);
        strcpy(a->cmd0,a->c_str);
        a->cmd_len = user_input_length/2;
        strToBytes(a->c_str,a->cmd);

        return 1;
    }

}
