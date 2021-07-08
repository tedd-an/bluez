// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021 Google LLC
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "src/log.h"
#include "src/plugin.h"

static int admin_policy_init(void)
{
	DBG("");
}

static void admin_policy_exit(void)
{
	DBG("");
}

BLUETOOTH_PLUGIN_DEFINE(admin_policy, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			admin_policy_init, admin_policy_exit)
