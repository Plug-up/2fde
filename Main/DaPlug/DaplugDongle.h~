/*! \mainpage C Daplug API
 *
 * \section intro Introduction
 *
 * C Daplug API is a high level library for communication with Daplug dongles. It maps the Daplug dongle specification in an user friendly format.
 *
 * \section compil Linked libraries
 * libusb-1.0, libcrypto and libpthread. (Linux64)
 * <br/>libusb-1.0, libeay32 and setupapi. (Win32)
 *
 * \section use Use
 *
 * Different sets of tests are in the main.c file.
 *
 * \warning Daplug dongles are not mounted world writeable on Linux OS by default, so you'll have to modify your udev rules.
 * <br/> An attached scrpit can do this for you. You can find it in the <b>"add_udev_rule"</b> directory.
 *
 * <br/>The C Daplug API is tested on Ubuntu 13.10/64 and Windows 7/32
 * <br/><br/>Please feel comfortable to send your comments or questions to s.benamar@plug-up.com
 *
 */

 /**
* \defgroup Daplug Daplug API
* \brief The main module. It Helps with operations on Daplug dongle.
*/


#ifndef PLUGUP_DONGLE_H_INCLUDED
#define PLUGUP_DONGLE_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <daplug/hidapi.h>
#include <daplug/keyset.h>
#include <daplug/apdu.h>
#include <daplug/common.h>

#define HID_DEVICE 0
#define WINUSB_DEVICE 1
#define HID_VID 0x2581
#define HID_PID 0x1807
#define CON_DNG_MAX_NB 10 //Max number of connected dongles
#define CHALLENGE_SIZE 8
#define SERIAL_SIZE 0x12
#define DIVERSIFIER_SIZE 0x10
#define MAX_FS_FILE_SIZE 0xFFFF
#define MAX_FS_PATH_SIZE 4*20 //20 is the max file number in a path (replace 20 with any value)
#define MAX_REAL_DATA_SIZE 0xEF //Max data to exchange in apdu (apdu data size(0xff) - (any mac(8)+any enc pad(8)))
#define FS_MASTER_FILE 0x3F00
#define HOTP_TIME_STEP 30
#define ACCESS_ALWAYS 0x00
#define ACCESS_NEVER 0xFF

/**
 * \ingroup Daplug
* \struct Dongle_info
* \brief
*
* A structure containing informations about a dongle.
*/
typedef struct {

    void *handle; /**< A handle to a device. According to his type, it can be an hid_device* or a winusb_device*. */
    int type; /**< Dongle type : Hid or Winusb. */
    char *path; /**< Device path (Only for Hid). */

} Dongle_info;

/**
 * \ingroup Daplug
* \struct DaplugDongle
* \brief A structure representing a Daplug dongle. It contains, informations about the dongle and the secure channel session.
*/
typedef struct {

    Dongle_info di; /**< A Dongle_info */

    char c_mac[8*2+1], /**< Session command mac */
         r_mac[8*2+1], /**< Session response mac */
         s_enc_key[GP_KEY_SIZE*2+1], /**< Session command encryption key (used for confidentiality and authentication) */
         r_enc_key[GP_KEY_SIZE*2+1], /**< Session response encryption key (used for confidentiality and authentication) */
         c_mac_key[GP_KEY_SIZE*2+1], /**< Session command integrity key (used for integrity) */
         r_mac_key[GP_KEY_SIZE*2+1], /**< Session response integrity key (used for integrity) */
         s_dek_key[GP_KEY_SIZE*2+1]; /**< Session DEK key (used for command data confidentiality in specific cases such as PUT KEY command) */

    int securityLevel; /**< Security level of the secure channel */
    int session_opened; /**< A flag indicating if a secure channel session is established or no. */


} DaplugDongle;

/**
 * \ingroup Daplug
* \enum sec_level
* \brief Security level to use for authentication
*
* C_MAC is mandatory for authentication. It is the minimum security level we must to use during authentication. Values can be combined. For example, if you want ensure,
* both response integrity and encryption (in addition to command integrity), you have to choose C_MAC + R_MAC + R_ENC.
*/
typedef enum{

    C_MAC = 0x01, /**< Ensure command integrity */
    C_DEC = 0x02, /**< Ensure command encryption */
    R_MAC = 0x10, /**< Ensure response integrity */
    R_ENC = 0x20  /**< Ensure response encryption */

} sec_level;


/**
 * \ingroup Daplug
* \enum x_otp
* \brief OTP options
*
* OTP options to use with Daplug_hotp(), Daplug_totp() and Daplug_hmac() functions.
*/
typedef enum{

    OTP_6_DIGIT = 0x10, /**< Output a 6-digits OTP */
    OTP_7_DIGIT = 0x20, /**< Output a 7-digits OTP */
    OTP_8_DIGIT = 0x40, /**< Output a 8-digits OTP */
    OTP_0_DIV = 0x00, /**< Do not use diversifiers */
    OTP_1_DIV = 0x01, /**< Use one diversifier */
    OTP_2_DIV = 0x02 /**< Use two diversifiers */

} x_otp;

/**
 * \ingroup Daplug
* \enum enc_mode
* \brief Encryption options
*
* Encryption options to use with Daplug_encrypt() and Daplug_decrypt() functions.
*/
typedef enum{

    ENC_ECB = 0x01, /**< Use ECB mode */
    ENC_CBC = 0x02, /**< Use CBC mode */
    ENC_1_DIV = 0x04, /**< Use one diversifier */
    ENC_2_DIV = 0x08 /**< Use two diversifiers */

} enc_mode;

/**
 * \ingroup Daplug
 * \fn int Daplug_getDongleList(Dongle_info *dil)
 * \param dil A list of connected dongles as a Dongle_info list. Must be freed later with Daplug_freeDongleList()
 * \return The number of connected dongles in the outputted list
 *
 * Returns a list of connected dongles. This is an entry point into finding an Hid or a Winusb dongle to operate.
 * The return value of this funtion indicates the number of dongles in the resultant list.
*/
int DAPLUGAPI DAPLUGCALL Daplug_getDongleList(Dongle_info*);

/**
 * \ingroup Daplug
 * \fn int Daplug_getDongleById(Dongle_info* di, DaplugDongle *dpd)
 * \param di A Dongle_info wich represents a dongle among the list obtained by the Daplug_getDongleList() function.
 * \param dpd Represents the session that will be used for exchanging APDUs (selected dongle and secure channel informations).
 * \return 1 is success ; 0 if failure
 *
 * Makes available the requested dongle and initialize the session data. You must use Daplug_closeDongle() later to close the selected dongle handle.
*/
int DAPLUGAPI DAPLUGCALL Daplug_getDongleById(Dongle_info*,DaplugDongle*);

/**
 * \ingroup Daplug
 * \fn void Daplug_free(DaplugDongle *dpd, Dongle_info *dil, int nb)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param dil The list obtained by the Daplug_getDongleList() function
 * \param nb The number of connected dongles. Obtained in the return value of Daplug_getDongleList() function
 *
 * Close opened secure channel session, release selected dongle and free dongles list.
*/
void DAPLUGAPI DAPLUGCALL Daplug_free(DaplugDongle *dpd, Dongle_info *dil, int nb);

/**
 * \ingroup Daplug
 * \fn void Daplug_exit()
 *
 * Deinitialize the libusb used by the Daplug API.
*/
void DAPLUGAPI DAPLUGCALL Daplug_exit();

/**
 * \ingroup Daplug
 * \fn int Daplug_exchange(DaplugDongle *dpd, char *cmd, char *resp, char *sw)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param cmd A string containing the apdu command to be exchanged
 * \param resp A string containing the returned apdu response
 * \param sw A string containing the returned apdu sw
 * \return 1 if success ; 0 if failure
 *
 * Exchange an apdu command and get the response and the status word.
*/
int DAPLUGAPI DAPLUGCALL Daplug_exchange(DaplugDongle*, const char *cmd, char *resp, char *sw);

/**
 * \ingroup Daplug
 * \fn int Daplug_getDongleSerial(DaplugDongle *dpd, char* serial)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param serial Returned serial. Must be large enough to receive the returned serial to avoid buffer overruns !
 * \return 1 if success ; 0 if failure
 *
 * Get the unique serial number for the selected dongle.
*/

int DAPLUGAPI DAPLUGCALL Daplug_getDongleSerial(DaplugDongle*, char *serial);

/**
 * \ingroup Daplug
 * \fn int Daplug_getDongleStatus(DaplugDongle *dpd, int *status)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param status Returned status.
 * \return 1 if success ; 0 if failure
 *
 * Get the current status of the selected dongle.
*/
int DAPLUGAPI DAPLUGCALL Daplug_getDongleStatus(DaplugDongle *dpd, int *status);

/**
 * \ingroup Daplug
 * \fn int Daplug_setDongleStatus(DaplugDongle *dpd, int status)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param status The new status.
 * \return 1 if success ; 0 if failure
 *
 * Set a new status for the selected dongle.
*/
int DAPLUGAPI DAPLUGCALL Daplug_setDongleStatus(DaplugDongle *dpd, int status);

/**
 * \ingroup Daplug
 * \fn void Daplug_authenticate(DaplugDongle *dpd, Keyset keys, int mode, char *div, char *chlg)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param keys The keyset values to use for authentication (if a diversifier is provided, use diversified values instead of master values).
 * \param mode Security level to use for authentication. For possible values to use, see sec_level.
 * \param div Diversifier (optional)
 * \param chlg The host challenge. (optional)
 *
 * Perform a mutual authentication between the dongle and the client. A secure channel is then created and used for exchanging APDUs acccording
 * to the security level mode. Diversified keys are obtained by difersifying each key in the master keyset by the provided diversifier (You can use Daplug_ComputeDiversifiedKeys() for that).
 * If the diversifier is not provided (empty string ""), default authentication is used. The host challenge is used for computing the host cryptogram (a value used when
 * performing the mutual authentication). If it is not provided (empty string ""), a random value is generated.
*/
void DAPLUGAPI DAPLUGCALL Daplug_authenticate(DaplugDongle *dpd, Keyset keys, int mode, char *div, char *chlg);

/**
 * \ingroup Daplug
 * \fn void Daplug_computeDiversifiedKeys(Keyset keys, Keyset *div_keys, char *div)
 * \param keys A master keyset
 * \param div_keys The resultant keyset. It will contain the diversified keys.
 * \param div Diversifier
 *
 * Diversify master keys using a diversifier.
*/
void DAPLUGAPI DAPLUGCALL Daplug_computeDiversifiedKeys(Keyset keys, Keyset *div_keys, char *div);

/**
 * \ingroup Daplug
 * \fn void Daplug_deAuthenticate(DaplugDongle *dpd)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 *
 * Close the current session.
*/
void DAPLUGAPI DAPLUGCALL Daplug_deAuthenticate(DaplugDongle *dpd);

/**
 * \ingroup Daplug
 * \fn void Daplug_putKey(DaplugDongle *dpd, Keyset new_keys)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param new_keys A new keyset
 *
 * Upload the provided keyset to the dongle.
*/
void DAPLUGAPI DAPLUGCALL Daplug_putKey(DaplugDongle *, Keyset);

/**
 * \ingroup Daplug
 * \fn void Daplug_deleteKey(DaplugDongle *dpd, int version)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param version The keyset version
 *
 * Delete the specified keyset.
*/
void DAPLUGAPI DAPLUGCALL Daplug_deleteKey(DaplugDongle *dpd, int version);

/**
 * \ingroup Daplug
 * \fn void Daplug_exportKey(DaplugDongle *dpd,int version,int id, char *expkey)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param version Version of the transient export keyset
 * \param id Key ID in the transient export keyset. Possible values are 1, 2 or 3.
 * \param expkey The resultant encrypted keyset.
 *
 * Export the current transient keyset (0xF0) using the specified key version and key id.
*/
void DAPLUGAPI DAPLUGCALL Daplug_exportKey(DaplugDongle *,int version,int id, char *expkey);

/**
 * \ingroup Daplug
 * \fn void Daplug_importKey(DaplugDongle *dpd,int version,int id, char *impkey){
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param version Version of the transient import keyset
 * \param id Key ID in the transient import keyset. Possible values are 1, 2 or 3.
 * \param impkey An encrypted keyset previously exported with Daplug_exportKey() function.
 *
 * Import the provided transient keyset (0xF0) using the specified key version and key id.
*/
void DAPLUGAPI DAPLUGCALL Daplug_importKey(DaplugDongle *,int version,int id, char *impkey);

/**
 * \ingroup Daplug
 * \fn void Daplug_createFile(DaplugDongle *dpd, int id, int size, int ac[3], int isFileEnc, int isCntFile)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param id A file ID
 * \param size The file size
 * \param ac[3] Access conditions
 * \param isFileEnc A Flag indicating if the created file content will be encrypted (1) or no (0).
 * \param isCntFile A Flag indicating if the created file is a counter file (1) or no (0).
 *
 * Create a new file with the given ID (0 to 65535) and the given size (1 to 65535) under the current directory. Access conditions are specified in a three-value array.
 * The first value codes the DELETE access condition. The second value codes the UPDATE access condtion. The third value codes the
 * READ access condition. An access condition is coded as follows : 0x00 for always, 0xFF for never, 0x01 to 0xFE for an access
 * protected by a secure channel 0x01 to 0xFE. A counter file size shall be 8 bytes.
*/
void DAPLUGAPI DAPLUGCALL Daplug_createFile(DaplugDongle *dpd, int id, int size, int ac[3], int isFileEnc, int isCntFile);

/**
 * \ingroup Daplug
 * \fn void Daplug_createDir(DaplugDongle *dpd, int id, int ac[3])
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param id A directory ID
 * \param ac[3] Access conditions
 *
 * Create a new directory with the given ID (0 to 65535) under the current directory. Access conditions are specified in a three-value array.
 * The first value codes the DELETE SELF access condition. The second value codes the CREATE DF access condition. The third value codes the
 * CREATE EF access condition. An access condition is coded as follows : 0x00 for always, 0xFF for never, 0x01 to 0xFE for an access
 * protected by a secure channel 0x01 to 0xFE.
*/
void DAPLUGAPI DAPLUGCALL Daplug_createDir(DaplugDongle *dpd, int id, int ac[3]);

/**
 * \ingroup Daplug
 * \fn void Daplug_deleteFileOrDir(DaplugDongle *dpd, int id)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param id A file/directory ID
 *
 * Delete the specified file or directory.
*/
void DAPLUGAPI DAPLUGCALL Daplug_deleteFileOrDir(DaplugDongle *dpd, int id);

/**
 * \ingroup Daplug
 * \fn void Daplug_selectFile(DaplugDongle *dpd, int id)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param id A file/directory ID
 *
 * Select the specified file
*/
void DAPLUGAPI DAPLUGCALL Daplug_selectFile(DaplugDongle *dpd, int id);

/**
 * \ingroup Daplug
 * \fn void Daplug_selectPath(DaplugDongle *dpd, char *path)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param path Path to select
 *
 * Select the specified path. A path is specified as a string containing a sequence of files IDs. Each file ID is specified as two bytes string.
 * For example, to select the file 0x0036 located under the directory 0x2214 located under the master file (0x3F00),
 * use path "3F0022140036".
*/
void DAPLUGAPI DAPLUGCALL Daplug_selectPath(DaplugDongle *dpd, char *path);

/**
 * \ingroup Daplug
 * \fn void Daplug_readData(DaplugDongle *dpd, int offset, int length, char *read_data)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param offset Indicates where start reading
 * \param length The size of data to read
 * \param read_data Read data
 *
 * Read length bytes of data from the selected file. Reading starts at the offset.
*/
void DAPLUGAPI DAPLUGCALL Daplug_readData(DaplugDongle *dpd,int offset, int length, char *read_data);

/**
 * \ingroup Daplug
 * \fn void Daplug_writeData(DaplugDongle *dpd, int  offset, char* data_to_write)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param offset Indicates where start writing
 * \param data_to_write Data to write
 *
 * Write provided data into the selected file. Writing starts at the offset.
*/
void DAPLUGAPI DAPLUGCALL Daplug_writeData(DaplugDongle *dpd,int offset, char* data_to_write);

/**
 * \ingroup Daplug
 * \fn void Daplug_encrypt(DaplugDongle *dpd, int keyVersion, int keyID, int mode, char *iv, char *div1, char *div2, char *inData, char *outData)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param keyVersion Encryption keyset version
 * \param keyID The key ID to use (1,2 or 3)
 * \param mode Specifies block cipher mode (ECB or CBC) and if we use diversifiers or not (see enc_mode)
 * \param iv initialization vector (optional, only for CBC mode)
 * \param div1 First diversifier (optional)
 * \param div2 Second diversifier (optional)
 * \param inData Sequence of bytes to encrypt.
 * \param outData Resultant encrypted data.
 *
 * Encrypt a sequence of bytes using Triple DES encryption. Data length must be a multiple of 8 bytes. The mode parameter combines options to use
 * such as block cipher mode (ENC_ECB or ENC_CBC) and the use of diversifiers or not (ENC_1_DIV, ENC_2_DIV).
 * For example, if we want to use CBC with two provided diversifiers, mode must be equal to ENC_CBC+ENC_2_DIV. If not provided, optional parameters must be specified as
 * empty string "".
*/
void DAPLUGAPI DAPLUGCALL Daplug_encrypt(DaplugDongle *dpd, int keyVersion, int keyID, int mode, char *iv, char *div1, char *div2, char *inData, char *outData);

/**
 * \ingroup Daplug
 * \fn Daplug_decrypt(DaplugDongle *dpd, int keyVersion, int keyID, int mode, char *iv, char *div1, char *div2, char *inData, char *outData)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param keyVersion Encryption keyset version
 * \param keyID The key ID to use (1,2 or 3)
 * \param mode Specifies block cipher mode (ECB or CBC) and if we use diversifiers or not (see enc_mode).
 * \param iv initialization vector (optional, only for CBC mode)
 * \param div1 First diversifier (optional)
 * \param div2 Second diversifier (optional)
 * \param inData Sequence of encrypted bytes.
 * \param outData Resultant decrypted data.
 *
 * Decrypt a sequence of bytes previously encrypted using Triple DES encryption. Encrypted Data length must be a multiple of 8 bytes. The mode parameter combines options to use
 * such as block cipher mode (ENC_ECB or ENC_CBC) and the use of diversifiers or not (ENC_1_DIV, ENC_2_DIV).
 * For example, if we want to use CBC with two provided diversifiers, mode must be equal to ENC_CBC+ENC_2_DIV. If not provided, optional parameters must be specified as
 * empty string "".
 */
void DAPLUGAPI DAPLUGCALL Daplug_decrypt(DaplugDongle *dpd, int keyVersion, int keyID, int mode, char *iv, char *div1, char *div2, char *inData, char *outData);

/**
 * \ingroup Daplug
 * \fn void Daplug_getRandom(DaplugDongle *dpd, int length, char* random)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param length Random length
 * \param random Generated random
 *
 * Generates random data.
*/
void DAPLUGAPI DAPLUGCALL Daplug_getRandom(DaplugDongle *dpd, int length, char* random);

/**
 * \ingroup Daplug
 * \fn void Daplug_hmac(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param keyVersion HMAC keyset version (see x_otp)
 * \param options Specifies if we want to use diversifiers or not
 * \param div1 First diversifier (optional)
 * \param div2 Second diversifier (optional)
 * \param inData Data to sign
 * \param outData HMAC-SHA-1 20 bytes signature
 *
 * Signs provided data using HMAC-SHA1. The resultant data is an 20-bytes signature. options parameter specifies if we want to use one (OTP_1_DIV) or two (OTP_2_DIV) provided diversifier(s).
 * If no diversifier is provided, div parameter must be equal to an empty string ("") and option parameter must be equal to OTP_0_DIV.
*/
void DAPLUGAPI DAPLUGCALL Daplug_hmac(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData);

/**
 * \ingroup Daplug
 * \fn void Daplug_hotp(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param keyVersion HOTP/HOTP_VALIDATION keyset version
 * \param options Specifies the size of the resultant HOTP and if we want to use diversifiers or not (see x_otp)
 * \param div1 First diversifier (optional)
 * \param div2 Second diversifier (optional)
 * \param inData A counter file ID if HOTP keyset is provided or counter value as an 8 bytes string if HOTP_VALIDATION keyset is provided.
 * \param outData HOTP : HMAC based One Time Password.
 *
 * Returns an HMAC based One Time Password. options parameter specifies the size of the resultant HOTP and if we want to use one (OTP_1_DIV) or two (OTP_2_DIV) provided diversifier(s).
 * If no diversifier is provided, div parameters must be equal to an empty string ("") and option parameter must be equal to OTP_0_DIV.
*/
void DAPLUGAPI DAPLUGCALL Daplug_hotp(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData);

/**
 * \ingroup Daplug
 * \fn void Daplug_totp(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param keyVersion TOTP/TOTP_VALIDATION keyset version
 * \param options Specifies the size of the resultant TOTP and if we want to use diversifiers or not (see x_otp)
 * \param div1 First diversifier (optional)
 * \param div2 Second diversifier (optional)
 * \param inData Empty string "" if TOTP keyset is provided or time data as an 8 bytes string if TOTP_VALIDATION keyset is provided.
 * \param outData TOTP : Time based One Time Password.
 *
 * Returns a Time based One Time Password. options parameter specifies the size of the resultant HOTP and if we want to use one (OTP_1_DIV) or two (OTP_2_DIV) provided diversifier(s).
 * If no diversifier is provided, div parameters must be equal to an empty string ("") and option parameter must be equal to OTP_0_DIV. If TOTP keyset is provided,
 * Daplug_setTimeOTP() function must have been called with a time source key matching the key requirement.
*/
void DAPLUGAPI DAPLUGCALL Daplug_totp(DaplugDongle *dpd, int keyVersion, int options, char *div1, char *div2, char* inData, char* outData);

/**
 * \ingroup Daplug
 * \fn void Daplug_setTimeOTP(DaplugDongle *dpd, int keyVersion, int keyId, char *timeSrcKey, int step, int t)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param keyVersion Time source keyset version
 * \param keyId Key ID to use in the keyset
 * \param timeSrcKey The Time source key identified by the keyId
 * \param step TOTP Time Step (optional)
 * \param t Time value (optional)
 *
 * Sets the time reference of the dongle. After the time reference is set, the dongle internal clock will tick from this value on until it is powered off.
 * The time value t is encoded as a big endian unsigned 32 bits integer (string format). If step parameter is not specified (=0), a typical value is used (30).
 * If t parameter is not specified, system time is used.
*/
void DAPLUGAPI DAPLUGCALL Daplug_setTimeOTP(DaplugDongle *dpd, int keyVersion, int keyId, char *timeSrcKey, int step, int time);

/**
 * \ingroup Daplug
 * \fn void Daplug_getTimeOTP(DaplugDongle *dpd, char* time)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param time Returned time.
 *
 * Gets the current time of the dongle.
 * The time value is encoded as a big endian unsigned 32 bits integer (string format).
*/
void DAPLUGAPI DAPLUGCALL Daplug_getTimeOTP(DaplugDongle *dpd, char* time);

/**
 * \ingroup Daplug
 * \fn void Daplug_useAsKeyboard(DaplugDongle *dpd)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 *
 * Use the selected file as keyboard file. We must create a keyboard file then select it before using this function. (Refer to Keyborad functions
 * to see how to create a keyboard file).
*/
void DAPLUGAPI DAPLUGCALL Daplug_useAsKeyboard(DaplugDongle *dpd);

/**
 * \ingroup Daplug
 * \fn void Daplug_setKeyboardAtBoot(DaplugDongle *dpd, int activated)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 * \param activated A flag indicating if we want to enable/disable the keyboard emulation
 *
 * Activates or deactivates keyboard emulation when the dongle is plugged.
*/
void DAPLUGAPI DAPLUGCALL Daplug_setKeyboardAtBoot(DaplugDongle *dpd, int activated);

/**
 * \ingroup Daplug
 * \fn void Daplug_triggerKeyboard(DaplugDongle *dpd)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 *
 * Activates the virtual keyboard once, and plays the content associated as keyboard input file.
*/
void DAPLUGAPI DAPLUGCALL Daplug_triggerKeyboard(DaplugDongle *dpd);

/**
 * \ingroup Daplug
 * \fn void Daplug_hidToWinusb(DaplugDongle *dpd)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 *
 * Change the dongle exchange mode from HID to WinUSB. Change will apply the next time the card boots (replugged or reset).
*/
void DAPLUGAPI DAPLUGCALL Daplug_hidToWinusb(DaplugDongle *dpd);

/**
 * \ingroup Daplug
 * \fn void Daplug_winusbToHid(DaplugDongle *dpd)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 *
 * Change the dongle exchange mode from WinUSB to HID. Change will apply the next time the card boots (replugged or reset).
*/
void DAPLUGAPI DAPLUGCALL Daplug_winusbToHid(DaplugDongle *dpd);

/**
 * \ingroup Daplug
 * \fn void Daplug_reset(DaplugDongle *dpd)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 *
 * Performs a warm reset of the dongle.
*/
void DAPLUGAPI DAPLUGCALL Daplug_reset(DaplugDongle *dpd);

/**
 * \ingroup Daplug
 * \fn void Daplug_halt(DaplugDongle *dpd)
 * \param dpd Represents the current session used for exchanging APDUs (selected dongle and secure channel informations).
 *
 * Blocks future commands sent to the dongle with a 6FAA status until the dongle is physically disconnected and reconnected from the USB port.
*/
void DAPLUGAPI DAPLUGCALL Daplug_halt(DaplugDongle *dpd);

#ifdef __cplusplus
}
#endif


#endif // PLUGUP_DONGLE_H_INCLUDED
