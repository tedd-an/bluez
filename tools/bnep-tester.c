// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/bnep.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"
#include "emulator/bthost.h"
#include "emulator/hciemu.h"

#include "src/shared/bttester.h"
#include "src/shared/mgmt.h"

struct test_data {
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	const void *test_data;
	uint16_t conn_handle;
};

struct rfcomm_client_data {
	uint8_t server_channel;
	uint8_t client_channel;
	int expected_connect_err;
	const uint8_t *send_data;
	const uint8_t *read_data;
	uint16_t data_len;
};

struct rfcomm_server_data {
	uint8_t server_channel;
	uint8_t client_channel;
	bool expected_status;
	const uint8_t *send_data;
	const uint8_t *read_data;
	uint16_t data_len;
};

static struct l_tester *tester;

static void print_debug(const char *str, void *user_data)
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

	if (strcmp(hciemu_get_address(data->hciemu), addr)) {
		l_tester_pre_setup_failed(tester);
		return;
	}

	l_tester_pre_setup_complete(tester);
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);

	bttester_print("Index Added callback");
	bttester_print("  Index: 0x%04x", index);

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

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	data->hciemu = hciemu_new(data->hciemu_type);
	if (!data->hciemu) {
		bttester_warn("Failed to setup HCI emulation");
		l_tester_pre_setup_failed(tester);
	}

	if (bttester_use_debug())
		hciemu_set_debug(data->hciemu, print_debug, "hciemu: ", NULL);

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
		mgmt_set_debug(data->mgmt, print_debug, "mgmt: ", NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void test_data_free(void *test_data)
{
	struct test_data *data = test_data;

	l_free(data);
}

static void client_connectable_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	switch (opcode) {
	case BT_HCI_CMD_WRITE_SCAN_ENABLE:
		break;
	default:
		return;
	}

	bttester_print("Client set connectable status 0x%02x", status);

	if (status)
		l_tester_setup_failed(tester);
	else
		l_tester_setup_complete(tester);
}

static void setup_powered_client_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	struct bthost *bthost;

	if (status != MGMT_STATUS_SUCCESS) {
		l_tester_setup_failed(tester);
		return;
	}

	bttester_print("Controller powered on");

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_cmd_complete_cb(bthost, client_connectable_complete, data);
	bthost_write_scan_enable(bthost, 0x03);
}

static void setup_powered_client(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	unsigned char param[] = { 0x01 };

	bttester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, setup_powered_client_callback,
			NULL, NULL);
}

static void test_basic(const void *test_data)
{
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_BNEP);
	if (sk < 0) {
		bttester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		l_tester_test_failed(tester);
		return;
	}

	close(sk);

	l_tester_test_passed(tester);
}

#define test_bnep(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = l_new(struct test_data, 1);	\
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDR; \
		user->test_data = data; \
		l_tester_add_full(tester, name, data,		   \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, test_data_free); \
	} while (0)

int main(int argc, char *argv[])
{
	tester = bttester_init(&argc, &argv);

	test_bnep("Basic BNEP Socket - Success", NULL,
					setup_powered_client, test_basic);

	return bttester_run();
}
