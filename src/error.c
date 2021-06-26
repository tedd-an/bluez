// SPDX-License-Identifier: GPL-2.0-or-later
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include "gdbus/gdbus.h"

#include "error.h"

DBusMessage *btd_error_invalid_args(DBusMessage *msg)
{
	return btd_error_invalid_args_str(msg,
					"Invalid arguments in method call");
}

DBusMessage *btd_error_invalid_args_str(DBusMessage *msg, const char *str)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
					"%s", str);
}

DBusMessage *btd_error_invalid_args_err(DBusMessage *msg, uint16_t err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
					"0x%04X", err);
}

DBusMessage *btd_error_busy(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress",
					"Operation already in progress");
}

DBusMessage *btd_error_already_exists(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".AlreadyExists",
					"Already Exists");
}

DBusMessage *btd_error_not_supported(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotSupported",
					"Operation is not supported");
}

DBusMessage *btd_error_not_connected(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotConnected",
					"Not Connected");
}

DBusMessage *btd_error_already_connected(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".AlreadyConnected",
					"Already Connected");
}

DBusMessage *btd_error_in_progress(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress",
					"In Progress");
}

DBusMessage *btd_error_in_progress_err(DBusMessage *msg, uint16_t err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress", "0x%04X",
					err);
}

DBusMessage *btd_error_not_available(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAvailable",
					"Operation currently not available");
}

DBusMessage *btd_error_not_available_err(DBusMessage *msg, uint16_t err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAvailable",
					"0x%04X", err);
}

DBusMessage *btd_error_does_not_exist(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".DoesNotExist",
					"Does Not Exist");
}

DBusMessage *btd_error_not_authorized(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAuthorized",
						"Operation Not Authorized");
}

DBusMessage *btd_error_not_permitted(DBusMessage *msg, const char *str)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotPermitted",
					"%s", str);
}

DBusMessage *btd_error_no_such_adapter(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NoSuchAdapter",
					"No such adapter");
}

DBusMessage *btd_error_agent_not_available(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".AgentNotAvailable",
					"Agent Not Available");
}

DBusMessage *btd_error_not_ready(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotReady",
					"Resource Not Ready");
}

DBusMessage *btd_error_not_ready_err(DBusMessage *msg, uint16_t err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotReady", "0x%04X",
					err);
}

DBusMessage *btd_error_failed(DBusMessage *msg, const char *str)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE
					".Failed", "%s", str);
}

DBusMessage *btd_error_failed_err(DBusMessage *msg, uint16_t err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed", "0x%04X",
					err);
}

uint16_t btd_error_bredr_conn_from_errno(int errno_code)
{
	switch (-errno_code) {
	case EALREADY:
	case EISCONN: // Fall through
		return BTD_ERR_BREDR_CONN_ALREADY_CONNECTED;
	case EHOSTDOWN:
		return BTD_ERR_BREDR_CONN_PAGE_TIMEOUT;
	case ENOPROTOOPT:
		return BTD_ERR_BREDR_CONN_PROFILE_UNAVAILABLE;
	case EIO:
		return BTD_ERR_BREDR_CONN_CREATE_SOCKET;
	case EINVAL:
		return BTD_ERR_BREDR_CONN_INVALID_ARGUMENTS;
	case EHOSTUNREACH:
		return BTD_ERR_BREDR_CONN_ADAPTER_NOT_POWERED;
	case EOPNOTSUPP:
	case EPROTONOSUPPORT: // Fall through
		return BTD_ERR_BREDR_CONN_NOT_SUPPORTED;
	case EBADFD:
		return BTD_ERR_BREDR_CONN_BAD_SOCKET;
	case ENOMEM:
		return BTD_ERR_BREDR_CONN_MEMORY_ALLOC;
	case EBUSY:
		return BTD_ERR_BREDR_CONN_BUSY;
	case EMLINK:
		return BTD_ERR_BREDR_CONN_CNCR_CONNECT_LIMIT;
	case ETIMEDOUT:
		return BTD_ERR_BREDR_CONN_TIMEOUT;
	case ECONNREFUSED:
		return BTD_ERR_BREDR_CONN_REFUSED;
	case ECONNRESET:
		return BTD_ERR_BREDR_CONN_ABORT_BY_REMOTE;
	case ECONNABORTED:
		return BTD_ERR_BREDR_CONN_ABORT_BY_LOCAL;
	case EPROTO:
		return BTD_ERR_BREDR_CONN_PROTO_ERROR;
	default:
		return BTD_ERR_BREDR_CONN_UNKNOWN;
	}
}

uint16_t btd_error_le_conn_from_errno(int errno_code)
{
	switch (-errno_code) {
	case EINVAL:
		return BTD_ERR_LE_CONN_INVALID_ARGUMENTS;
	case EHOSTUNREACH:
		return BTD_ERR_LE_CONN_ADAPTER_NOT_POWERED;
	case EOPNOTSUPP:
	case EPROTONOSUPPORT: // Fall through
		return BTD_ERR_LE_CONN_NOT_SUPPORTED;
	case EALREADY:
	case EISCONN: // Fall through
		return BTD_ERR_LE_CONN_ALREADY_CONNECTED;
	case EBADFD:
		return BTD_ERR_LE_CONN_BAD_SOCKET;
	case ENOMEM:
		return BTD_ERR_LE_CONN_MEMORY_ALLOC;
	case EBUSY:
		return BTD_ERR_LE_CONN_BUSY;
	case ECONNREFUSED:
		return BTD_ERR_LE_CONN_REFUSED;
	case EIO:
		return BTD_ERR_LE_CONN_CREATE_SOCKET;
	case ETIMEDOUT:
		return BTD_ERR_LE_CONN_TIMEOUT;
	case EMLINK:
		return BTD_ERR_LE_CONN_SYNC_CONNECT_LIMIT;
	case ECONNRESET:
		return BTD_ERR_LE_CONN_ABORT_BY_REMOTE;
	case ECONNABORTED:
		return BTD_ERR_LE_CONN_ABORT_BY_LOCAL;
	case EPROTO:
		return BTD_ERR_LE_CONN_PROTO_ERROR;
	default:
		return BTD_ERR_LE_CONN_UNKNOWN;
	}
}
