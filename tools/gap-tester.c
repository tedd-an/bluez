// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "emulator/hciemu.h"
#include "src/shared/bttester.h"

static struct l_dbus *dbus_conn;
struct l_dbus_client *dbus_client;
struct l_dbus_proxy *adapter_proxy;

static struct hciemu *hciemu_stack;
static struct l_tester *tester;

static void connect_handler(struct l_dbus *connection, void *user_data)
{
	bttester_print("Connected to daemon");

	hciemu_stack = hciemu_new(HCIEMU_TYPE_BREDRLE);
}

static void destroy_client(void *data)
{
	l_dbus_client_destroy(dbus_client);
	dbus_client = NULL;
}

static void destroy_conn(void *data)
{
	l_dbus_destroy(dbus_conn);
	dbus_conn = NULL;
}

static void service_disconnect_handler(struct l_dbus *connection,
							void *user_data)
{
	bttester_print("Daemon disconnected");
}

static void client_destroy_handler(void *user_data)
{
	bttester_print("Disconnected from daemon");

	if (dbus_conn)
		l_idle_oneshot(destroy_conn, NULL, NULL);

	l_tester_teardown_complete(tester);
}

static bool compare_string_property(struct l_dbus_proxy *proxy,
					const char *name, const char *value)
{
	const char *str;

	if (!l_dbus_proxy_get_property(proxy, name, "s", &str))
		return false;

	return !strcmp(str, value);
}

static void proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface;

	interface = l_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		if (compare_string_property(proxy, "Address",
				hciemu_get_address(hciemu_stack))) {
			adapter_proxy = proxy;
			bttester_print("Found adapter");

			l_tester_setup_complete(tester);
		}
	}
}

static void proxy_removed(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface;

	interface = l_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		if (adapter_proxy == proxy) {
			adapter_proxy = NULL;
			bttester_print("Adapter removed");
			l_idle_oneshot(destroy_client, NULL, NULL);
		}
	}
}

static void test_setup(const void *test_data)
{
	dbus_conn = l_dbus_new_default(L_DBUS_SYSTEM_BUS);

	dbus_client = l_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");
	l_dbus_client_set_connect_handler(dbus_client, connect_handler, NULL,
									NULL);
	l_dbus_client_set_disconnect_handler(dbus_client,
						service_disconnect_handler,
						NULL, client_destroy_handler);

	l_dbus_client_set_proxy_handlers(dbus_client, proxy_added,
					proxy_removed, NULL, NULL, NULL);
}

static void test_run(const void *test_data)
{
	l_tester_test_passed(tester);
}

static void test_teardown(const void *test_data)
{
	hciemu_unref(hciemu_stack);
	hciemu_stack = NULL;
}

int main(int argc, char *argv[])
{
	tester = bttester_init(&argc, &argv);

	l_tester_add(tester, "Adapter setup", NULL, test_setup, test_run,
								test_teardown);

	return bttester_run();
}
