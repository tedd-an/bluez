// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014-2015  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/mgmt.h"

#include "emulator/bthost.h"
#include "emulator/hciemu.h"

#include "src/shared/bttester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hci.h"

struct test_data {
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	const void *test_data;
	unsigned int remove_id;
};

static struct l_tester *tester;

static void mgmt_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	bttester_print("%s%s", prefix, str);
}

static void read_info_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct mgmt_rp_read_info *rp = param;
	char addr[18];
	uint16_t manufacturer;
	uint32_t supported_settings, current_settings;

	bttester_print("Read Info callback");
	bttester_print("  Status: 0x%02x", status);

	if (status || !param) {
		l_tester_pre_setup_failed(tester);
		return;
	}

	ba2str(&rp->bdaddr, addr);
	manufacturer = btohs(rp->manufacturer);
	supported_settings = btohl(rp->supported_settings);
	current_settings = btohl(rp->current_settings);

	bttester_print("  Address: %s", addr);
	bttester_print("  Version: 0x%02x", rp->version);
	bttester_print("  Manufacturer: 0x%04x", manufacturer);
	bttester_print("  Supported settings: 0x%08x", supported_settings);
	bttester_print("  Current settings: 0x%08x", current_settings);
	bttester_print("  Class: 0x%02x%02x%02x",
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);
	bttester_print("  Name: %s", rp->name);
	bttester_print("  Short name: %s", rp->short_name);

	if (strcmp(hciemu_get_address(data->hciemu), addr))
		l_tester_pre_setup_failed(tester);
	else
		l_tester_pre_setup_complete(tester);
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);

	bttester_print("Index Added callback");
	bttester_print("  Index: 0x%04x", index);

	if (data->mgmt_index != MGMT_INDEX_NONE)
		return;

	data->mgmt_index = index;

	mgmt_send(data->mgmt, MGMT_OP_READ_INFO, data->mgmt_index, 0, NULL,
					read_info_callback, NULL, NULL);
}

static void index_removed_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);

	bttester_print("Index Removed callback");
	bttester_print("  Index: 0x%04x", index);

	if (index != data->mgmt_index)
		return;

	if (data->remove_id) {
		mgmt_unregister(data->mgmt, data->remove_id);
		data->remove_id = 0;
		l_tester_test_passed(tester);
		return;
	}

	mgmt_unregister_index(data->mgmt, data->mgmt_index);

	mgmt_unref(data->mgmt);
	data->mgmt = NULL;

	l_tester_post_teardown_complete(tester);
}

static void read_index_list_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);

	bttester_print("Read Index List callback");
	bttester_print("  Status: 0x%02x", status);

	if (status || !param) {
		l_tester_pre_setup_failed(tester);
		return;
	}

	mgmt_register(data->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, NULL, NULL);

	data->hciemu = hciemu_new(data->hciemu_type);
	if (!data->hciemu) {
		bttester_warn("Failed to setup HCI emulation");
		l_tester_pre_setup_failed(tester);
	}

	bttester_print("New hciemu instance created");
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		bttester_warn("Failed to setup management interface");
		l_tester_pre_setup_failed(tester);
		return;
	}

	if (bttester_use_debug())
		mgmt_set_debug(data->mgmt, mgmt_debug, "mgmt: ", NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, data->mgmt_index,
					index_removed_callback,
					NULL, NULL);

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void setup_powered_client_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		l_tester_setup_failed(tester);
		return;
	}

	bttester_print("Controller powered on");

	l_tester_setup_complete(tester);
}

static void setup_powered(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	unsigned char param[] = { 0x01 };

	bttester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, setup_powered_client_callback,
			NULL, NULL);
}

static void toggle_powered(const void *test_data);

static void toggle_powered_client_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	uint32_t power = L_PTR_TO_UINT(user_data);

	if (status != MGMT_STATUS_SUCCESS) {
		l_tester_setup_failed(tester);
		return;
	}

	bttester_print("Controller powered %s", power ? "on" : "off");

	if (power)
		toggle_powered(false);
	else
		l_tester_setup_complete(tester);
}

static void toggle_powered(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	uint32_t power = L_PTR_TO_UINT(test_data);
	unsigned char param[1];

	param[0] = power;

	bttester_print("Powering %s controller", power != 0 ? "on" : "off");

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, toggle_powered_client_callback,
			L_UINT_TO_PTR(power), NULL);
}

static void test_open_success(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	struct bt_hci *hci;

	data->remove_id = mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED,
					data->mgmt_index,
					index_removed_callback,
					NULL, NULL);

	hci = bt_hci_new_user_channel(data->mgmt_index);
	if (hci) {
		bt_hci_unref(hci);
		return;
	}

	mgmt_unregister(data->mgmt, data->remove_id);
	data->remove_id = 0;

	l_tester_test_failed(tester);
}

static void test_open_failed(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	struct bt_hci *hci;

	hci = bt_hci_new_user_channel(data->mgmt_index);
	if (!hci) {
		l_tester_test_passed(tester);
		return;
	}

	bt_hci_unref(hci);
	l_tester_test_failed(tester);
}

#define test_user(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = l_malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDR; \
		user->mgmt_index = MGMT_INDEX_NONE; \
		user->test_data = data; \
		user->remove_id = 0; \
		l_tester_add_full(tester, name, data, test_pre_setup, setup, \
					func, NULL, test_post_teardown, 2,\
					user, l_free); \
	} while (0)

int main(int argc, char *argv[])
{
	tester = bttester_init(&argc, &argv);

	test_user("User channel open - Success", NULL,
					NULL, test_open_success);
	test_user("User channel open - Failed", NULL,
					setup_powered, test_open_failed);
	test_user("User channel open - Power Toggle Success",
			L_UINT_TO_PTR(0x1), toggle_powered, test_open_success);

	return bttester_run();
}
