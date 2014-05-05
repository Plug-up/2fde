/*
============================
= saada.benamar@gmail.com  =
=  plug-up international   =
============================
*/

#include <openssl/rand.h>
#include <openssl/des.h>
#include <daplug/utils.h>

/*
generate bytes challenge
*/
void generateChallenge(unsigned char *challenge,int chl_size);

/*
Verify that calculated card cryptogram is the same as that returned from the card
*/
int checkCardCryptogram(char *returnedCardCryptogram, char *computedCardCryptogram);

/*
Calculate card cryptogram
*/
void computeCardCryptogram(char *hostChallenge,char *cardChallenge, char *counter, char *s_encKey, char *cardCryptogram);

/*
Calculate host cryptogram
*/
void computeHostCryptogram(char *hostChallenge,char *cardChallenge,char *counter,char *s_encKey,char *hostCryptogram);

/*
Calculate retail MAC : cmac = 1 (c-mac) ; cmac = 0 (r-mac)
*/
void computeRetailMac(const char *data, char *key, char *previousMac, char *retailMac, int cmac);

/*
Modify CLA & Lc for command that will be MAC-ed
*/
void modifyCdeForMac(char * command, char *mCommand);

/*
Calculate full triple DES MAC used to calculate card & host cryptograms
*/
void computeFull3DesMac(char *data,  char *key, char *full3DesMac);

/*
Calculate a session key
*/
void computeSessionKey(char *counter,char *keyConstant, char *masterKey, char *sessionKey);

/*
Form an initialize update command to be used as echange() function parameter
The length of init_up_apdu array shall be (13*2+1)
*/
void initializeUpdate(char *keysetId, char *hostChallenge, char* init_up_apdu);

/*
Form an external authenticate command to be used as echange() function parameter after it will be Mac-ed
*/
void externalAuthenticate(char *securityLevel, char *hostCryptogram, char *ext_auth_apdu);

/*
Form a diversified initialize update command to be used as echange() function parameter
The length of d_init_up_apdu array shall be (24*2+1)
*/
void diversifiedInitializeUpdate(char *keysetId, char *hostChallenge, char* masterKeyDiversifier, char* d_init_up_apdu);

/*
Form a mac-ed apdu. return current mac also.
*/
void macedCommand(char *cde, char *cmacKey, char *lastMac, char *currentMac, char *macedCde);

/*
Form a put key command
*/
int createPutKeyCommand(char *numKeyset, char *mode, char *sdekKey, char* gp_enc, char *gp_mac, char *gp_dek, char *keyUsage, char *keyAccess, char *putKeyCommand);

/*
Perform a triple des ecb encryption on 8 bytes data. Outputs 8 bytes encrypted data. (used in createPutKeyCommand())
*/
int tripleDES_ECB_encrypt(char *data, char *key, char *encrypted_data);


/*
Compute a Key Check Value
*/
int computeKCV(char *key, char *kcv);

/*
computes a 16-bytes diversified key from the given <16-bytes key> and the <16-bytes diversifier> parameters using 3-des-cbc algorithm.
*/
void computeDiversifiedKey(char *key, char *s_diversifier, char *divKey);

/*

*/
void dataEncryption(const char *old_data, const char *s_encKey, char *new_data, int enc);

/*

*/
void tripleDES_CBC(char *data, char *key, char *encrypted_data, int enc);
