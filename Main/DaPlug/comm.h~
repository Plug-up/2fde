#ifndef COMM_H_INCLUDED
#define COMM_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <daplug/DaplugDongle.h>
#include <daplug/sc.h>

#define HID_BLOCK_SIZE 64  //Block size (hid report)

FILE *flog_apdu;

/**
 * \defgroup Comm Comm
 * \brief Used by the Daplug API module to Create and exchange APDUs
*/

/**
* \ingroup Comm
* \fn int exchangeApdu(DaplugDongle *dpd, Apdu *a)
* \param dpd A DaplugDongle
* \param a An Apdu
* \return 1 if success ; 0 if failure
*
* Send the APDU command contained in the Apdu object to the dongle represented by the DaplugDongle object and receive the returned response. If the APDU is sent over a secure channel,
* the funcion perform the neccessary wrap/unwrap operations according to the secure channel security level. When the exchange is successfully performed,
* Apdu response data and status word are updated.
*/
int exchangeApdu(DaplugDongle *, Apdu *);

#ifdef __cplusplus
}
#endif

#endif // COMM_H_INCLUDED
