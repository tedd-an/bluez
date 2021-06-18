/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2007-2008  Fabien Chevalier <fabchevalier@free.fr>
 *
 *
 */

#include <dbus/dbus.h>
#include <stdint.h>

#define ERROR_INTERFACE "org.bluez.Error"

/* BR/EDR connection failure reasons
 * BT_ERR_* should be used as one of the parameters to btd_error_*_err().
 */

/* Either the profile is already connected or ACL connection is in
 * place.
 * errno: EALREADY, EISCONN
 */
#define BTD_ERR_BREDR_CONN_ALREADY_CONNECTED	0x0001
/* Failed due to page timeout.
 * errno: EHOSTDOWN
 */
#define BTD_ERR_BREDR_CONN_PAGE_TIMEOUT		0x0002
/* Failed to find connectable services or the target service.
 * errno: ENOPROTOOPT
 */
#define BTD_ERR_BREDR_CONN_PROFILE_UNAVAILABLE	0x0003
/* Failed to complete the SDP search.
 * errno: none
 */
#define BTD_ERR_BREDR_CONN_SDP_SEARCH		0x0004
/* Failed to create or connect to BT IO socket. This can also indicate
 * hardware failure in the controller.
 * errno: EIO
 */
#define BTD_ERR_BREDR_CONN_CREATE_SOCKET	0x0005
/* Failed due to invalid arguments.
 * errno: EINVAL
 */
#define BTD_ERR_BREDR_CONN_INVALID_ARGUMENTS	0x0006
/* Failed due to adapter not powered.
 * errno: EHOSTUNREACH
 */
#define BTD_ERR_BREDR_CONN_ADAPTER_NOT_POWERED	0x0007
/* Failed due to unsupported state transition of L2CAP channel or other
 * features either by the local host or the remote.
 * errno: EOPNOTSUPP, EPROTONOSUPPORT
 */
#define BTD_ERR_BREDR_CONN_NOT_SUPPORTED	0x0008
/* Failed due to the socket is in bad state.
 * errno: EBADFD
 */
#define BTD_ERR_BREDR_CONN_BAD_SOCKET		0x0009
/* Failed to allocate memory in either host stack or controller.
 * errno: ENOMEM
 */
#define BTD_ERR_BREDR_CONN_MEMORY_ALLOC		0x000A
/* Failed due to other ongoing operations, such as pairing, busy L2CAP
 * channel or the operation disallowed by the controller.
 * errno: EBUSY
 */
#define BTD_ERR_BREDR_CONN_BUSY			0x000B
/* Failed due to reaching the synchronous connection limit to a device.
 * errno: EMLINK
 */
#define BTD_ERR_BREDR_CONN_SYNC_CONNECT_LIMIT	0x000C
/* Failed due to connection timeout
 * errno: ETIMEDOUT
 */
#define BTD_ERR_BREDR_CONN_TIMEOUT		0x000D
/* Refused by the remote device due to limited resource, security reason
 * or unacceptable address type.
 * errno: ECONNREFUSED
 */
#define BTD_ERR_BREDR_CONN_REFUSED		0x000E
/* Terminated by the remote device due to limited resource or power
 * off.
 * errno: ECONNRESET
 */
#define BTD_ERR_BREDR_CONN_TERM_BY_REMOTE	0x000F
/* Terminated by the local host.
 * errno: ECONNABORTED
 */
#define BTD_ERR_BREDR_CONN_TERM_BY_LOCAL	0x0010
/* Failed due to LMP protocol error.
 * errno: EPROTO
 */
#define BTD_ERR_BREDR_CONN_PROTO_ERROR		0x0011
/* Failed due to cancellation caused by adapter drop, unexpected device drop,
 * or incoming disconnection request before connection request is completed.
 * errno: none
 */
#define BTD_ERR_BREDR_CONN_CANCELED		0x0012
/* Failed due to unknown reason.
 * errno: ENOSYS
 */
#define BTD_ERR_BREDR_CONN_UNKNOWN		0x0013

/* LE connection failure reasons
 * BT_ERR_* should be used as one of the parameters to btd_error_*_err().
 */

/* Failed due to invalid arguments.
 * errno: EINVAL
 */
#define BTD_ERR_LE_CONN_INVALID_ARGUMENTS	0x0101
/* Failed due to adapter not powered.
 * errno: EHOSTUNREACH
 */
#define BTD_ERR_LE_CONN_ADAPTER_NOT_POWERED	0x0102
/* Failed due to unsupported state transition of L2CAP channel or other
 * features (e.g. LE features) either by the local host or the remote.
 * errno: EOPNOTSUPP, EPROTONOSUPPORT
 */
#define BTD_ERR_LE_CONN_NOT_SUPPORTED		0x0103
/* Either the BT IO is already connected or LE link connection in place.
 * errno: EALREADY, EISCONN
 */
#define BTD_ERR_LE_CONN_ALREADY_CONNECTED	0x0104
/* Failed due to the socket is in bad state.
 * errno: EBADFD
 */
#define BTD_ERR_LE_CONN_BAD_SOCKET		0x0105
/* Failed to allocate memory in either host stack or controller.
 * errno: ENOMEM
 */
#define BTD_ERR_LE_CONN_MEMORY_ALLOC		0x0106
/* Failed due to other ongoing operations, such as pairing, connecting, busy
 * L2CAP channel or the operation disallowed by the controller.
 * errno: EBUSY
 */
#define BTD_ERR_LE_CONN_BUSY			0x0107
/* Failed due to that LE is not enabled or the attempt is refused by the remote
 * device due to limited resource, security reason or unacceptable address type.
 * errno: ECONNREFUSED
 */
#define BTD_ERR_LE_CONN_REFUSED			0x0108
/* Failed to create or connect to BT IO socket. This can also indicate
 * hardware failure in the controller.
 * errno: EIO
 */
#define BTD_ERR_LE_CONN_CREATE_SOCKET		0x0109
/* Failed due to connection timeout
 * errno: ETIMEDOUT
 */
#define BTD_ERR_LE_CONN_TIMEOUT			0x010A
/* Failed due to reaching the synchronous connection limit to a device.
 * errno: EMLINK
 */
#define BTD_ERR_LE_CONN_SYNC_CONNECT_LIMIT	0x010B
/* Terminated by the remote device due to limited resource or power
 * off.
 * errno: ECONNRESET
 */
#define BTD_ERR_LE_CONN_TERM_BY_REMOTE		0x010C
/* Terminated by the local host.
 * errno: ECONNABORTED
 */
#define BTD_ERR_LE_CONN_TERM_BY_LOCAL		0x010D
/* Failed due to LL protocol error.
 * errno: EPROTO
 */
#define BTD_ERR_LE_CONN_PROTO_ERROR		0x010E
/* Failed to complete the GATT browsing.
 * errno: none
 */
#define BTD_ERR_LE_CONN_GATT_BROWSE		0x010F
/* Failed due to unknown reason.
 * errno: ENOSYS
 */
#define BTD_ERR_LE_CONN_UNKNOWN			0x0110

DBusMessage *btd_error_invalid_args(DBusMessage *msg);
DBusMessage *btd_error_invalid_args_str(DBusMessage *msg, const char *str);
DBusMessage *btd_error_invalid_args_err(DBusMessage *msg, uint16_t err);
DBusMessage *btd_error_busy(DBusMessage *msg);
DBusMessage *btd_error_already_exists(DBusMessage *msg);
DBusMessage *btd_error_not_supported(DBusMessage *msg);
DBusMessage *btd_error_not_connected(DBusMessage *msg);
DBusMessage *btd_error_already_connected(DBusMessage *msg);
DBusMessage *btd_error_not_available(DBusMessage *msg);
DBusMessage *btd_error_not_available_err(DBusMessage *msg, uint16_t err);
DBusMessage *btd_error_in_progress(DBusMessage *msg);
DBusMessage *btd_error_in_progress_err(DBusMessage *msg, uint16_t err);
DBusMessage *btd_error_does_not_exist(DBusMessage *msg);
DBusMessage *btd_error_not_authorized(DBusMessage *msg);
DBusMessage *btd_error_not_permitted(DBusMessage *msg, const char *str);
DBusMessage *btd_error_no_such_adapter(DBusMessage *msg);
DBusMessage *btd_error_agent_not_available(DBusMessage *msg);
DBusMessage *btd_error_not_ready(DBusMessage *msg);
DBusMessage *btd_error_not_ready_err(DBusMessage *msg, uint16_t err);
DBusMessage *btd_error_failed(DBusMessage *msg, const char *str);
DBusMessage *btd_error_failed_err(DBusMessage *msg, uint16_t err);

uint16_t btd_error_bredr_conn_from_errno(int errno_code);
uint16_t btd_error_le_conn_from_errno(int errno_code);
