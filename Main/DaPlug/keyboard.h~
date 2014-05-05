#ifndef KEYBOARD_H_INCLUDED
#define KEYBOARD_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <daplug/utils.h>
#include <daplug/common.h>

#define MAX_KB_CONTENT_SIZE 0xFFFF
#define MAX_WINDOWS_TEXT_LEN 0xFF //per one TLV
#define MAX_MAC_TEXT_LEN 0xFC //per one TLV (0xFF-3)


/**
* \defgroup Keyboard Keyborad
* \brief  Helps to create the keyboard file content to be uploaded to a Daplug dongle
*/

/**
 * \ingroup Keyboard
 * \struct Keyboard
 * \brief A structure describing the keyboard file content
 *
 * A structure describing the keyboard file content to be uploaded to a Daplug dongle.
 */
typedef struct {
    int currentContentSize; /**< The current size of the keyboard file content*/
    char content[MAX_KB_CONTENT_SIZE*2+1]; /**< The keyboard file content*/
} Keyboard;

/**
 * \ingroup Keyboard
* \enum keyborad_hotp_flag
* \brief keyboard HOTP options
*
* When using a converted hex output, file 3F00/0001 must be created and readable and contain the mapping betwwen of each HID code sent for nibbles 0 to F.
*/
typedef enum {

    KB_HOTP_USE_DIV = 0x01, /**< Use diversifier */
    KB_HOTP_NUMERIC = 0x02, /**< Use numeric output */
    KB_HOTP_MODHEX = 0x04 /**< Use modified hex output */

} keyborad_hotp_flag;

/**
 * \fn void keyboard_init(Keyboard *k)
 * \param k A new Keyboard object
 *
 * Creates a new empty Keyboard
*/
void DAPLUGAPI DAPLUGCALL keyboard_init(Keyboard *k);

/**
 * \ingroup Keyboard
 * \fn void keyboard_getContent(Keyboard *k, char *content)
 * \param k A Keyboard instance
 * \param content Returned content
 *
 * Return the content of the Keyboard instance.
*/
void DAPLUGAPI DAPLUGCALL keyboard_getContent(Keyboard *k, char *content);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addOSProbe(Keyboard *k, int nb, int delay, int code)
 * \param k A Keyboard instance
 * \param nb Number of Hid reports (optional)
 * \param delay Delay before Hid report (optional)
 * \param code Keycode sent in each report (optional)
 *
 * Adds an OS probe to the keyboard file content. If the value of an optional parameter is not specified (=-1) a default value is used instead.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addOSProbe(Keyboard *k, int nb, int delay, int code);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addOSProbeWinR(Keyboard *k, int nb, int delay, int code)
 * \param k A Keyboard instance
 * \param nb Number of Hid reports (optional)
 * \param delay Delay before Hid report (optional)
 * \param code Keycode sent in each report (optional)
 *
 * Adds an OS probe to the keyboard file content. If a Windows OS is detected, a Win+R is made.
 * If the value of an optional parameter is not specified (=-1) a default value is used instead.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addOSProbeWinR(Keyboard *k, int nb, int delay, int code);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addIfPC(Keyboard *k)
 * \param k A Keyboard instance
 *
 * Adds a condition to execute following code if Windows OS is detected.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addIfPC(Keyboard *k);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addIfMac(Keyboard *k)
 * \param k A Keyboard instance
 *
 * Adds a condition to execute following code if Mac OS is detected.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addIfMac(Keyboard *k);

/**
 * \ingroup Keyboard
* \fn void keyboard_addTextWindows(Keyboard *k, char *text)
 * \param k A Keyboard instance
 * \param text Text to add
 *
 * Adds text to the keyboard file content in Windows format.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addTextWindows(Keyboard *k, char *text);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addTextMac(Keyboard *k, char *text, int azerty, int delay)
 * \param k A Keyboard instance
 * \param text Text to add
 * \param azerty A flag indicating if we use azerty or qwerty format (optional)
 * \param delay Delay before Hid report (optional)
 *
 * Adds text to the keyboard file content in Mac format.
 * If the value of an optional parameter is not specified (=-1) a default value is used instead.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addTextMac(Keyboard *k, char *text, int azerty, int delay);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addKeyCodeRaw(Keyboard *k, char *code)
 * \param k A Keyboard instance
 * \param code Keycode
 *
 * Adds sequence of keycodes (without modifiers) to the keyboard file content.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addKeyCodeRaw(Keyboard *k, char *code);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addKeyCodeRelease(Keyboard *k,char *code)
 * \param k A Keyboard instance
 * \param code Keycode
 *
 * Adds a sequence of Keycode Containers sent with interleaving empty report, and terminated with an empty report to the keyboard file content.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addKeyCodeRelease(Keyboard *k,char *code);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addHotpCode(Keyboard *k, int flag, int digitsNb, int keysetVersion, int counterFileId, char *div)
 * \param k A Keyboard instance
 * \param flag A flag indicating if we use diversifier or not and if the output is a numeric keypad or a converted hex (see keyborad_hotp_flag)
 * \param digitsNB Number of digits (6, 7 or 8)
 * \param keysetVersion An HOTP keyset version
 * \param counterFileId File Id of a counter file in the counter directory
 * \param div Diversifier (optional)
 *
 * Adds HOTP tag and parameters to the keyboard file content.
 * If the diversifier is not provided, div parameter must be equal to an empty string ("")
*/
void DAPLUGAPI DAPLUGCALL keyboard_addHotpCode(Keyboard *k, int flag, int digitsNb, int keysetVersion, int counterFileId, char *div);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addReturn(Keyboard *k)
 * \param k A Keyboard instance
 *
 * Adds a carriage return to the keyboard file content.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addReturn(Keyboard *k);

/**
 * \ingroup Keyboard
 * \fn void keyboard_addSleep(Keyboard *k, int duration)
 * \param k A Keyboard instance
 * \param duration Duration of the sleep (optional)
 *
 * Adds a sleep to the keyboard file content.
 * If the value of duration parameter is not specified (=-1) a default value is used instead.
*/
void DAPLUGAPI DAPLUGCALL keyboard_addSleep(Keyboard *k, int duration);

/**
 * \ingroup Keyboard
 * \fn void keyboard_zeroPad(Keyboard *k, int size)
 * \param k A Keyboard instance
 * \param size Desired total size of the keyboard file
 *
 * Fills the end of keyboard file with zeroes to avoid misinterpretation.
*/
void DAPLUGAPI DAPLUGCALL keyboard_zeroPad(Keyboard *k, int size);

#ifdef __cplusplus
}
#endif

#endif // KEYBOARD_H_INCLUDED
