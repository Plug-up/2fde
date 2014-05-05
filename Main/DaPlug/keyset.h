#ifndef KEYSET_H_INCLUDED
#define KEYSET_H_INCLUDED

#include "utils.h"
#include "common.h"

#define GP_KEY_SIZE 16

/**
* \ingroup Daplug
* \enum keyset_usage
* \brief Different keysets roles
*
* Defines what the keyset can be used for. Authenticating with a key wich has role USAGE_GP_AUTH does not open a Secure Channel but sets a permission that is valid for all channels.
* It is not recommended to use it when remote administration is involved as the authentication might be kept active. It is mostly provided for convenience to emulate a user PIN entry
* in order to protect the user credentials.
*/
typedef enum {

    USAGE_GP = 0x01, /**< GlobalPlatform key. */
    USAGE_GP_AUTH = 0x02, /**< GlobalPlatform key used for two-ways authentication */
    USAGE_HOTP = 0x03, /**< HOTP/OATH key */
    USAGE_HOTP_VALIDATION = 0x04, /**< HOTP/OATH key for validation. */
    USAGE_TOTP_VALIDATION = 0x04, /**< TOTP/OATH key for validation. */
    USAGE_OTP = 0x05, /**< RFU */
    USAGE_ENC = 0x06, /**< Encryption Key */
    USAGE_DEC = 0x07, /**< Decryption Key */
    USAGE_ENC_DEC = 0x08, /**< Encryption + Decryption key */
    USAGE_SAM_CTX = 0x09, /**< SAM context encryption key  */
    USAGE_SAM_GP = 0x0a, /**< SAM GlobalPlatform usable key  */
    USAGE_SAM_DIV1 = 0x0b, /**< SAM provisionable key with mandated diversification by at least one diversifier  */
    USAGE_SAM_DIV2 = 0x0c, /**< SAM provisionable key with mandated diversification by at least two diversifiers  */
    USAGE_SAM_CLEAR_EXPORT_DIV1 = 0x0d, /**< SAM cleartext exportable key with mandated diversification by at least one diversifier */
    USAGE_SAM_CLEAR_EXPORT_DIV2 = 0x0e, /**< SAM cleartext exportable key with mandated diversification by at least two diversifiers  */
    USAGE_IMPORT_EXPORT_TRANSIENT = 0x0f, /**< Transient keyset import/export key  */
    USAGE_TOTP_TIME_SRC = 0x10, /**< OATH TOTP time source key */
    USAGE_TOTP = 0x11, /**< TOTP/OATH key. */
    USAGE_HMAC_SHA1 = 0x12 ,/**< HMAC-SHA1 key. */
    USAGE_HOTP_LOCK = 0x13, /**< HOTP/OATH key locking the dongle after each use. */
    USAGE_TOTP_LOCK = 0x14, /**< TOTP/OATH key locking the dongle after each use. */

} keyset_usage;

/**
* \ingroup Daplug
 * \struct Keyset
 * \brief A structure wich holds three DES keys.
 *
 * A structure wich holds three DES keys. Each key is identified by its index: 0 (ENC key), 1 (MAC key) or 2 (DEK key).
 * ENC key is used for encryption and confidentiality. MAC key is used for integrity. DEK key is used for command data confidentiality in specific cases such as PUT KEY command.
 * The keyset is associated with a usage and access control policy. The Key usage parameter defines what each key in the keyset can be used for,
 * The first access value codes the time source keyversion in case of TOTP keyset and for all others keyset roles, it codes the necessary access rights to be validated before being
 * able to use a key in the keyset : 0x00 for always, 0x01 to 0xFE for an access protected by a secure channel 0x01 to 0xFE.
 * The second access value codes decryption access in case of an ENC-DEC keyset ; the key length in case of HMAC-SHA1, HOTP and TOTP keysets ; the minimum security level in case of a GP keyset.
 */
typedef struct{

    Byte version; /**< Keyset version */
    keyset_usage usage; /**< Keyset role */
    Byte access[2]; /**< Keyset access conditions */
    Byte key[3][GP_KEY_SIZE]; /**< Array of Keys values */

} Keyset;

/**
 * \ingroup Daplug
 * \fn void keyset_createKeys(Keyset *keys, int version,const char* encKey,const char* macKey,const char* dekKey)
 * \param version Keyset version
 * \param encKey A new ENC key value (string of bytes)
 * \param macKey A new MAC key value (string of bytes ; optional)
 * \param dekKey A new DEK key value (string of bytes ; optional)
 * \param keys A new Keyset object
 *
 * Creates a new Keyset instance with the provided keys values.
 * If the MAC or DEK key is not specified, the same ENC key value is used instead.
*/
void DAPLUGAPI DAPLUGCALL keyset_createKeys(Keyset *keys, int version,const char* encKey,const char* macKey,const char* dekKey);

/**
 * \ingroup Daplug
 * \fn void keyset_setVersion(Keyset *keys, int version)
 * \param keys A Keyset instance
 * \param version Keyset version
 *
 * Sets keyset version
*/
void DAPLUGAPI DAPLUGCALL keyset_setVersion(Keyset* keys, int version);

/**
 * \ingroup Daplug
 * \fn void keyset_setVersion(Keyset *keys, int version)
 * \param keys A Keyset instance
 * \param version Returned keyset version
 *
 * Return keyset version
*/
void DAPLUGAPI DAPLUGCALL keyset_getVersion(Keyset, int *version);

/**
 * \ingroup Daplug
 * \fn void keyset_setKey(Keyset *keys,int id, char *key_value)
 * \param keys A Keyset instance
 * \param id Key index in the keyset
 * \param key_value A new key value (as a string of bytes)
 *
 * Sets a new key value for the keyset
*/
void DAPLUGAPI DAPLUGCALL keyset_setKey(Keyset *keys,int id,char* key_value);

/**
 * \ingroup Daplug
 * \fn void keyset_getKey(Keyset keys,int id, char *key_value)
 * \param keys A Keyset instance
 * \param id Key index in the keyset
 * \param key_value Returned key value (as a string of bytes)
 *
 * Return the key value requested by id
*/
void DAPLUGAPI DAPLUGCALL keyset_getKey(Keyset keys,int id, char* key_value);

/**
 * \ingroup Daplug
 * \fn void keyset_getKeyUsage(Keyset keys, keyset_usage *ku)
 * \param keys A Keyset instance
 * \param ku Returned key usage
 *
 * Return the keyset role
*/
void DAPLUGAPI DAPLUGCALL keyset_getKeyUsage(Keyset keys, keyset_usage *ku);
/**
 * \ingroup Daplug
 * \fn void keyset_setKeyAccess(Keyset *keys,Byte access[2])
 * \param keys A Keyset instance
 * \param access Keyset access conditions
 *
 * Sets the keyset access conditions
*/
void DAPLUGAPI DAPLUGCALL keyset_setKeyAccess(Keyset *keys,Byte access[2]);

/**
 * \ingroup Daplug
 * \fn void keyset_getKeyAccess(Keyset keys,Byte access[2])
 * \param keys A Keyset instance
 * \param access Returned keyset access conditions
 *
 * Returns the keyset access conditions
*/
void DAPLUGAPI DAPLUGCALL keyset_getKeyAccess(Keyset keys,Byte *access);

#endif // KEYSET_H_INCLUDED
