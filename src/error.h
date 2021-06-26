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
#define BTD_ERR_BREDR_CONN_ALREADY_CONNECTED	0x0001
#define BTD_ERR_BREDR_CONN_PAGE_TIMEOUT		0x0002
#define BTD_ERR_BREDR_CONN_PROFILE_UNAVAILABLE	0x0003
#define BTD_ERR_BREDR_CONN_SDP_SEARCH		0x0004
#define BTD_ERR_BREDR_CONN_CREATE_SOCKET	0x0005
#define BTD_ERR_BREDR_CONN_INVALID_ARGUMENTS	0x0006
#define BTD_ERR_BREDR_CONN_ADAPTER_NOT_POWERED	0x0007
#define BTD_ERR_BREDR_CONN_NOT_SUPPORTED	0x0008
#define BTD_ERR_BREDR_CONN_BAD_SOCKET		0x0009
#define BTD_ERR_BREDR_CONN_MEMORY_ALLOC		0x000A
#define BTD_ERR_BREDR_CONN_BUSY			0x000B
#define BTD_ERR_BREDR_CONN_CNCR_CONNECT_LIMIT	0x000C
#define BTD_ERR_BREDR_CONN_TIMEOUT		0x000D
#define BTD_ERR_BREDR_CONN_REFUSED		0x000E
#define BTD_ERR_BREDR_CONN_ABORT_BY_REMOTE	0x000F
#define BTD_ERR_BREDR_CONN_ABORT_BY_LOCAL	0x0010
#define BTD_ERR_BREDR_CONN_PROTO_ERROR		0x0011
#define BTD_ERR_BREDR_CONN_CANCELED		0x0012
#define BTD_ERR_BREDR_CONN_UNKNOWN		0x0013

/* LE connection failure reasons
 * BT_ERR_* should be used as one of the parameters to btd_error_*_err().
 */
#define BTD_ERR_LE_CONN_INVALID_ARGUMENTS	0x0101
#define BTD_ERR_LE_CONN_ADAPTER_NOT_POWERED	0x0102
#define BTD_ERR_LE_CONN_NOT_SUPPORTED		0x0103
#define BTD_ERR_LE_CONN_ALREADY_CONNECTED	0x0104
#define BTD_ERR_LE_CONN_BAD_SOCKET		0x0105
#define BTD_ERR_LE_CONN_MEMORY_ALLOC		0x0106
#define BTD_ERR_LE_CONN_BUSY			0x0107
#define BTD_ERR_LE_CONN_REFUSED			0x0108
#define BTD_ERR_LE_CONN_CREATE_SOCKET		0x0109
#define BTD_ERR_LE_CONN_TIMEOUT			0x010A
#define BTD_ERR_LE_CONN_SYNC_CONNECT_LIMIT	0x010B
#define BTD_ERR_LE_CONN_ABORT_BY_REMOTE		0x010C
#define BTD_ERR_LE_CONN_ABORT_BY_LOCAL		0x010D
#define BTD_ERR_LE_CONN_PROTO_ERROR		0x010E
#define BTD_ERR_LE_CONN_GATT_BROWSE		0x010F
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
