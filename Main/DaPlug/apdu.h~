#ifndef APDU_H_INCLUDED
#define APDU_H_INCLUDED

#include <daplug/utils.h>

#define APDU_H_LEN 5
#define APDU_D_MAXLEN 255
#define APDU_CMD_MAXLEN 260

/**
 * \ingroup Comm
 * \struct Apdu
 * \brief A tructure describing all informations about an APDU
 *
 * Apdu is a structure describing all informations about an APDU, like command data, command length, response data, etc...
 * Apdu command is set before sending the apdu to a dongle using the setApduCmd() function.
 * At the end of the exchange, apdu response and status word are set.
 * To facilitate apdu handling, the Apdu structure contain two formats. Bytes array and string.
 * Bytes arrays are used when sending/receiving a command/response to/from a dongle.
 * Strings are used for input/output operations.
 * When exchanging Apdu, over a secure channel the command data may be modified, according to a given security level (wrapping command).
 * For this reason, Apdu command field is copied to cmd0 before the Apdu is exchanged.
 */
typedef struct{

    Byte cmd[APDU_CMD_MAXLEN], /**< Command data (Bytes array). Can be modified during the exchange. */
         rep_data[APDU_D_MAXLEN], /**< Response data (Bytes array). */
         sw[2]; /**< Status word (Bytes array). Code the response status. */

    int cmd_len, /**< Command data length.*/
        rep_data_len; /**< Response data length. */

    char c_str[APDU_CMD_MAXLEN*2+1], /**< Command data (String). Can be modified during the exchange.*/
         r_str[APDU_D_MAXLEN*2+1], /**< Response data (String). */
         sw_str[2*2+1], /**< Status word (String). */

    cmd0[APDU_CMD_MAXLEN*2+1]; /**< The same as c_str. Used to keep the initial value of command before the exchange. */

} Apdu;

/**
 * \ingroup Comm
* \fn int setApduCmd(const char*, Apdu*)
* \brief
* \param user_input A string that contain the apdu command to be exchanged.
* \return 1 if success, 0 if failure.
*
* Function used to set an apdu command wich will be sent to a dongle.
*/
int setApduCmd(const char*, Apdu*);

#endif // APDU_H_INCLUDED

