// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.

 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/l2cap.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"
#include "emulator/bthost.h"
#include "emulator/hciemu.h"

#include "src/shared/bttester.h"
#include "src/shared/mgmt.h"

struct test_data {
	const void *test_data;
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	struct l_io *io;
	struct l_io *io2;
	enum hciemu_type hciemu_type;
	uint16_t handle;
	uint16_t scid;
	uint16_t dcid;
	int sk;
	int sk2;
	bool host_disconnected;
};

struct l2cap_data {
	uint16_t client_psm;
	uint16_t server_psm;
	uint16_t cid;
	uint8_t mode;
	int expect_err;

	uint8_t send_cmd_code;
	const void *send_cmd;
	uint16_t send_cmd_len;
	uint8_t expect_cmd_code;
	const void *expect_cmd;
	uint16_t expect_cmd_len;

	uint16_t data_len;
	const void *read_data;
	const void *write_data;

	bool enable_ssp;
	uint8_t client_io_cap;
	int sec_level;
	bool reject_ssp;

	bool expect_pin;
	uint8_t pin_len;
	const void *pin;
	uint8_t client_pin_len;
	const void *client_pin;

	bool addr_type_avail;
	uint8_t addr_type;

	uint8_t *client_bdaddr;
	bool server_not_advertising;
	bool direct_advertising;
	bool close_1;

	bool shut_sock_wr;
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

	if (data->io) {
		l_io_destroy(data->io);
		data->io = NULL;
	}

	if (data->io2) {
		l_io_destroy(data->io2);
		data->io2 = NULL;
	}

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

#define test_l2cap_bredr(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = l_new(struct test_data, 1);	\
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDR; \
		user->test_data = data; \
		l_tester_add_full(tester, name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, l_free); \
	} while (0)

#define test_l2cap_le(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = l_new(struct test_data, 1);	\
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_LE; \
		user->test_data = data; \
		l_tester_add_full(tester, name, data,		   \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, l_free); \
	} while (0)

static uint8_t pair_device_pin[] = { 0x30, 0x30, 0x30, 0x30 }; /* "0000" */

static const struct l2cap_data client_connect_success_test = {
	.client_psm = 0x1001,
	.server_psm = 0x1001,
};

static const struct l2cap_data client_connect_ssp_success_test_1 = {
	.client_psm = 0x1001,
	.server_psm = 0x1001,
	.enable_ssp = true,
};

static const struct l2cap_data client_connect_ssp_success_test_2 = {
	.client_psm = 0x1001,
	.server_psm = 0x1001,
	.enable_ssp = true,
	.sec_level  = BT_SECURITY_HIGH,
	.client_io_cap = 0x04,
};

static const struct l2cap_data client_connect_pin_success_test = {
	.client_psm = 0x1001,
	.server_psm = 0x1001,
	.sec_level  = BT_SECURITY_MEDIUM,
	.pin = pair_device_pin,
	.pin_len = sizeof(pair_device_pin),
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
};

static uint8_t l2_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static const struct l2cap_data client_connect_read_success_test = {
	.client_psm = 0x1001,
	.server_psm = 0x1001,
	.read_data = l2_data,
	.data_len = sizeof(l2_data),
};

static const struct l2cap_data client_connect_write_success_test = {
	.client_psm = 0x1001,
	.server_psm = 0x1001,
	.write_data = l2_data,
	.data_len = sizeof(l2_data),
};

static const struct l2cap_data client_connect_shut_wr_success_test = {
	.client_psm = 0x1001,
	.server_psm = 0x1001,
	.shut_sock_wr = true,
};

static const struct l2cap_data client_connect_nval_psm_test_1 = {
	.client_psm = 0x1001,
	.expect_err = ECONNREFUSED,
};

static const struct l2cap_data client_connect_nval_psm_test_2 = {
	.client_psm = 0x0001,
	.expect_err = ECONNREFUSED,
};

static const struct l2cap_data client_connect_nval_psm_test_3 = {
	.client_psm = 0x0001,
	.expect_err = ECONNREFUSED,
	.enable_ssp = true,
};

static const uint8_t l2cap_connect_req[] = { 0x01, 0x10, 0x41, 0x00 };

static const struct l2cap_data l2cap_server_success_test = {
	.server_psm = 0x1001,
	.send_cmd_code = BT_L2CAP_PDU_CONN_REQ,
	.send_cmd = l2cap_connect_req,
	.send_cmd_len = sizeof(l2cap_connect_req),
	.expect_cmd_code = BT_L2CAP_PDU_CONN_RSP,
};

static const struct l2cap_data l2cap_server_read_success_test = {
	.server_psm = 0x1001,
	.send_cmd_code = BT_L2CAP_PDU_CONN_REQ,
	.send_cmd = l2cap_connect_req,
	.send_cmd_len = sizeof(l2cap_connect_req),
	.expect_cmd_code = BT_L2CAP_PDU_CONN_RSP,
	.read_data = l2_data,
	.data_len = sizeof(l2_data),
};

static const struct l2cap_data l2cap_server_write_success_test = {
	.server_psm = 0x1001,
	.send_cmd_code = BT_L2CAP_PDU_CONN_REQ,
	.send_cmd = l2cap_connect_req,
	.send_cmd_len = sizeof(l2cap_connect_req),
	.expect_cmd_code = BT_L2CAP_PDU_CONN_RSP,
	.write_data = l2_data,
	.data_len = sizeof(l2_data),
};

static const uint8_t l2cap_sec_block_rsp[] = {	0x00, 0x00,	/* dcid */
						0x41, 0x00,	/* scid */
						0x03, 0x00,	/* Sec Block */
						0x00, 0x00	/* status */
					};

static const struct l2cap_data l2cap_server_sec_block_test = {
	.server_psm = 0x1001,
	.send_cmd_code = BT_L2CAP_PDU_CONN_REQ,
	.send_cmd = l2cap_connect_req,
	.send_cmd_len = sizeof(l2cap_connect_req),
	.expect_cmd_code = BT_L2CAP_PDU_CONN_RSP,
	.expect_cmd = l2cap_sec_block_rsp,
	.expect_cmd_len = sizeof(l2cap_sec_block_rsp),
	.enable_ssp = true,
};

static const uint8_t l2cap_nval_psm_rsp[] = {	0x00, 0x00,	/* dcid */
						0x41, 0x00,	/* scid */
						0x02, 0x00,	/* nval PSM */
						0x00, 0x00	/* status */
					};

static const struct l2cap_data l2cap_server_nval_psm_test = {
	.send_cmd_code = BT_L2CAP_PDU_CONN_REQ,
	.send_cmd = l2cap_connect_req,
	.send_cmd_len = sizeof(l2cap_connect_req),
	.expect_cmd_code = BT_L2CAP_PDU_CONN_RSP,
	.expect_cmd = l2cap_nval_psm_rsp,
	.expect_cmd_len = sizeof(l2cap_nval_psm_rsp),
};

static const uint8_t l2cap_nval_conn_req[] = { 0x00 };
static const uint8_t l2cap_nval_pdu_rsp[] = { 0x00, 0x00 };

static const struct l2cap_data l2cap_server_nval_pdu_test1 = {
	.send_cmd_code = BT_L2CAP_PDU_CONN_REQ,
	.send_cmd = l2cap_nval_conn_req,
	.send_cmd_len = sizeof(l2cap_nval_conn_req),
	.expect_cmd_code = BT_L2CAP_PDU_CMD_REJECT,
	.expect_cmd = l2cap_nval_pdu_rsp,
	.expect_cmd_len = sizeof(l2cap_nval_pdu_rsp),
};

static const uint8_t l2cap_nval_dc_req[] = { 0x12, 0x34, 0x56, 0x78 };
static const uint8_t l2cap_nval_cid_rsp[] = { 0x02, 0x00,
						0x12, 0x34, 0x56, 0x78 };

static const struct l2cap_data l2cap_server_nval_cid_test1 = {
	.send_cmd_code = BT_L2CAP_PDU_DISCONN_REQ,
	.send_cmd = l2cap_nval_dc_req,
	.send_cmd_len = sizeof(l2cap_nval_dc_req),
	.expect_cmd_code = BT_L2CAP_PDU_CMD_REJECT,
	.expect_cmd = l2cap_nval_cid_rsp,
	.expect_cmd_len = sizeof(l2cap_nval_cid_rsp),
};

static const uint8_t l2cap_nval_cfg_req[] = { 0x12, 0x34, 0x00, 0x00 };
static const uint8_t l2cap_nval_cfg_rsp[] = { 0x02, 0x00,
						0x12, 0x34, 0x00, 0x00 };

static const struct l2cap_data l2cap_server_nval_cid_test2 = {
	.send_cmd_code = BT_L2CAP_PDU_CONFIG_REQ,
	.send_cmd = l2cap_nval_cfg_req,
	.send_cmd_len = sizeof(l2cap_nval_cfg_req),
	.expect_cmd_code = BT_L2CAP_PDU_CMD_REJECT,
	.expect_cmd = l2cap_nval_cfg_rsp,
	.expect_cmd_len = sizeof(l2cap_nval_cfg_rsp),
};

static const struct l2cap_data le_client_connect_success_test_1 = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
};

static const struct l2cap_data le_client_connect_adv_success_test_1 = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
	.direct_advertising = true,
};

static const struct l2cap_data le_client_connect_success_test_2 = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
	.sec_level  = BT_SECURITY_MEDIUM,
};

static const uint8_t cmd_reject_rsp[] = { 0x01, 0x01, 0x02, 0x00, 0x00, 0x00 };

static const struct l2cap_data le_client_connect_reject_test_1 = {
	.client_psm = 0x0080,
	.send_cmd = cmd_reject_rsp,
	.send_cmd_len = sizeof(cmd_reject_rsp),
	.expect_err = ECONNREFUSED,
};

static const struct l2cap_data le_client_connect_reject_test_2 = {
	.client_psm = 0x0080,
	.addr_type_avail = true,
	.addr_type = BDADDR_LE_PUBLIC,
};

static uint8_t nonexisting_bdaddr[] = {0x00, 0xAA, 0x01, 0x02, 0x03, 0x00};
static const struct l2cap_data le_client_close_socket_test_1 = {
	.client_psm = 0x0080,
	.client_bdaddr = nonexisting_bdaddr,
};

static const struct l2cap_data le_client_close_socket_test_2 = {
	.client_psm = 0x0080,
	.server_not_advertising = true,
};

static const struct l2cap_data le_client_2_same_client = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
	.server_not_advertising = true,
};

static const struct l2cap_data le_client_2_close_1 = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
	.server_not_advertising = true,
	.close_1 = true,
};

static const struct l2cap_data le_client_connect_nval_psm_test = {
	.client_psm = 0x0080,
	.expect_err = ECONNREFUSED,
};

static const uint8_t le_connect_req[] = {	0x80, 0x00, /* PSM */
						0x41, 0x00, /* SCID */
						0x20, 0x00, /* MTU */
						0x20, 0x00, /* MPS */
						0x05, 0x00, /* Credits */
};

static const uint8_t le_connect_rsp[] = {	0x40, 0x00, /* DCID */
						0xa0, 0x02, /* MTU */
						0xbc, 0x00, /* MPS */
						0x04, 0x00, /* Credits */
						0x00, 0x00, /* Result */
};

static const struct l2cap_data le_server_success_test = {
	.server_psm = 0x0080,
	.send_cmd_code = BT_L2CAP_PDU_LE_CONN_REQ,
	.send_cmd = le_connect_req,
	.send_cmd_len = sizeof(le_connect_req),
	.expect_cmd_code = BT_L2CAP_PDU_LE_CONN_RSP,
	.expect_cmd = le_connect_rsp,
	.expect_cmd_len = sizeof(le_connect_rsp),
};

static const uint8_t nval_le_connect_req[] = {	0x80, 0x00, /* PSM */
						0x01, 0x00, /* SCID */
						0x20, 0x00, /* MTU */
						0x20, 0x00, /* MPS */
						0x05, 0x00, /* Credits */
};

static const uint8_t nval_le_connect_rsp[] = {	0x00, 0x00, /* DCID */
						0x00, 0x00, /* MTU */
						0x00, 0x00, /* MPS */
						0x00, 0x00, /* Credits */
						0x09, 0x00, /* Result */
};

static const struct l2cap_data le_server_nval_scid_test = {
	.server_psm = 0x0080,
	.send_cmd_code = BT_L2CAP_PDU_LE_CONN_REQ,
	.send_cmd = nval_le_connect_req,
	.send_cmd_len = sizeof(nval_le_connect_req),
	.expect_cmd_code = BT_L2CAP_PDU_LE_CONN_RSP,
	.expect_cmd = nval_le_connect_rsp,
	.expect_cmd_len = sizeof(nval_le_connect_rsp),
};

static const struct l2cap_data le_att_client_connect_success_test_1 = {
	.cid = 0x0004,
	.sec_level = BT_SECURITY_LOW,
};

static const struct l2cap_data le_att_server_success_test_1 = {
	.cid = 0x0004,
};

static const struct l2cap_data ext_flowctl_client_connect_success_test_1 = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
	.mode = BT_MODE_EXT_FLOWCTL,
};

static const struct l2cap_data ext_flowctl_client_connect_adv_success_test_1 = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
	.mode = BT_MODE_EXT_FLOWCTL,
	.direct_advertising = true,
};

static const struct l2cap_data ext_flowctl_client_connect_success_test_2 = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
	.mode = BT_MODE_EXT_FLOWCTL,
	.sec_level  = BT_SECURITY_MEDIUM,
};

static const struct l2cap_data ext_flowctl_client_connect_reject_test_1 = {
	.client_psm = 0x0080,
	.mode = BT_MODE_EXT_FLOWCTL,
	.send_cmd = cmd_reject_rsp,
	.send_cmd_len = sizeof(cmd_reject_rsp),
	.expect_err = ECONNREFUSED,
};

static const struct l2cap_data ext_flowctl_client_2 = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
	.mode = BT_MODE_EXT_FLOWCTL,
	.server_not_advertising = true,
};

static const struct l2cap_data ext_flowctl_client_2_close_1 = {
	.client_psm = 0x0080,
	.server_psm = 0x0080,
	.mode = BT_MODE_EXT_FLOWCTL,
	.server_not_advertising = true,
	.close_1 = true,
};

static void client_cmd_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *test = data->test_data;
	struct bthost *bthost;

	bthost = hciemu_client_get_host(data->hciemu);

	switch (opcode) {
	case BT_HCI_CMD_WRITE_SCAN_ENABLE:
	case BT_HCI_CMD_LE_SET_ADV_ENABLE:
		bttester_print("Client set connectable status 0x%02x", status);
		if (!status && test && test->enable_ssp) {
			bthost_write_ssp_mode(bthost, 0x01);
			return;
		}
		break;
	case BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE:
		bttester_print("Client enable SSP status 0x%02x", status);
		break;
	default:
		return;
	}


	if (status)
		l_tester_setup_failed(tester);
	else
		l_tester_setup_complete(tester);
}

static void server_cmd_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	switch (opcode) {
	case BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE:
		bttester_print("Server enable SSP status 0x%02x", status);
		break;
	default:
		return;
	}

	if (status)
		l_tester_setup_failed(tester);
	else
		l_tester_setup_complete(tester);
}

static void setup_powered_client_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	struct bthost *bthost;

	if (status != MGMT_STATUS_SUCCESS) {
		l_tester_setup_failed(tester);
		return;
	}

	bttester_print("Controller powered on");

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_cmd_complete_cb(bthost, client_cmd_complete, user_data);

	if (data->hciemu_type == HCIEMU_TYPE_LE) {
		if (!l2data || !l2data->server_not_advertising)
			bthost_set_adv_enable(bthost, 0x01);
		else
			l_tester_setup_complete(tester);
	} else {
		bthost_write_scan_enable(bthost, 0x03);
	}
}

static void setup_powered_server_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *test = data->test_data;
	struct bthost *bthost;

	if (status != MGMT_STATUS_SUCCESS) {
		l_tester_setup_failed(tester);
		return;
	}

	bttester_print("Controller powered on");

	if (!test->enable_ssp) {
		l_tester_setup_complete(tester);
		return;
	}

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_cmd_complete_cb(bthost, server_cmd_complete, user_data);
	bthost_write_ssp_mode(bthost, 0x01);
}

static void user_confirm_request_callback(uint16_t index, uint16_t length,
							const void *param,
							void *user_data)
{
	const struct mgmt_ev_user_confirm_request *ev = param;
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *test = data->test_data;
	struct mgmt_cp_user_confirm_reply cp;
	uint16_t opcode;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, &ev->addr, sizeof(cp.addr));

	if (test->reject_ssp)
		opcode = MGMT_OP_USER_CONFIRM_NEG_REPLY;
	else
		opcode = MGMT_OP_USER_CONFIRM_REPLY;

	mgmt_reply(data->mgmt, opcode, data->mgmt_index, sizeof(cp), &cp,
							NULL, NULL, NULL);
}

static void pin_code_request_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_ev_pin_code_request *ev = param;
	struct test_data *data = user_data;
	const struct l2cap_data *test = data->test_data;
	struct mgmt_cp_pin_code_reply cp;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, &ev->addr, sizeof(cp.addr));

	if (!test->pin) {
		mgmt_reply(data->mgmt, MGMT_OP_PIN_CODE_NEG_REPLY,
				data->mgmt_index, sizeof(cp.addr), &cp.addr,
				NULL, NULL, NULL);
		return;
	}

	cp.pin_len = test->pin_len;
	memcpy(cp.pin_code, test->pin, test->pin_len);

	mgmt_reply(data->mgmt, MGMT_OP_PIN_CODE_REPLY, data->mgmt_index,
			sizeof(cp), &cp, NULL, NULL, NULL);
}

static void bthost_send_rsp(const void *buf, uint16_t len, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	struct bthost *bthost;

	if (l2data->expect_cmd_len && len != l2data->expect_cmd_len) {
		l_tester_test_failed(tester);
		return;
	}

	if (l2data->expect_cmd && memcmp(buf, l2data->expect_cmd,
						l2data->expect_cmd_len)) {
		l_tester_test_failed(tester);
		return;
	}

	if (!l2data->send_cmd)
		return;

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_send_cid(bthost, data->handle, data->dcid,
				l2data->send_cmd, l2data->send_cmd_len);
}

static void send_rsp_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;
	struct bthost *bthost;

	bttester_print("New connection with handle 0x%04x", handle);

	data->handle = handle;

	if (data->hciemu_type == HCIEMU_TYPE_LE)
		data->dcid = 0x0005;
	else
		data->dcid = 0x0001;

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_add_cid_hook(bthost, data->handle, data->dcid,
						bthost_send_rsp, NULL);
}

static void setup_powered_common(void)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *test = data->test_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	unsigned char param[] = { 0x01 };

	mgmt_register(data->mgmt, MGMT_EV_USER_CONFIRM_REQUEST,
			data->mgmt_index, user_confirm_request_callback,
			NULL, NULL);

	if (test && (test->pin || test->expect_pin))
		mgmt_register(data->mgmt, MGMT_EV_PIN_CODE_REQUEST,
				data->mgmt_index, pin_code_request_callback,
				data, NULL);

	if (test && test->client_io_cap)
		bthost_set_io_capability(bthost, test->client_io_cap);

	if (test && test->client_pin)
		bthost_set_pin_code(bthost, test->client_pin,
							test->client_pin_len);
	if (test && test->reject_ssp)
		bthost_set_reject_user_confirm(bthost, true);

	if (data->hciemu_type == HCIEMU_TYPE_LE)
		mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	if (test && test->enable_ssp)
		mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_BONDABLE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);
}

static void setup_powered_client(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *test = data->test_data;
	unsigned char param[] = { 0x01 };

	setup_powered_common();

	bttester_print("Powering on controller");

	if (test && (test->expect_cmd || test->send_cmd)) {
		struct bthost *bthost = hciemu_client_get_host(data->hciemu);
		bthost_set_connect_cb(bthost, send_rsp_new_conn, data);
	}

	if (test && test->direct_advertising)
		mgmt_send(data->mgmt, MGMT_OP_SET_ADVERTISING,
				data->mgmt_index, sizeof(param), param,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, setup_powered_client_callback,
			NULL, NULL);
}

static void setup_powered_server(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	unsigned char param[] = { 0x01 };

	setup_powered_common();

	bttester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	if (data->hciemu_type != HCIEMU_TYPE_BREDR)
		mgmt_send(data->mgmt, MGMT_OP_SET_ADVERTISING,
				data->mgmt_index, sizeof(param), param, NULL,
				NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, setup_powered_server_callback,
			NULL, NULL);
}

static void test_basic(const void *test_data)
{
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		bttester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		l_tester_test_failed(tester);
		return;
	}

	close(sk);

	l_tester_test_passed(tester);
}

static bool client_received_data(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	char buf[1024];
	int sk;

	sk = l_io_get_fd(io);
	if (read(sk, buf, l2data->data_len) != l2data->data_len) {
		bttester_warn("Unable to read %u bytes", l2data->data_len);
		l_tester_test_failed(tester);
		return false;
	}

	if (memcmp(buf, l2data->read_data, l2data->data_len))
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);

	return true;
}

static bool server_received_data(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	char buf[1024];
	int sk;

	sk = l_io_get_fd(io);
	if (read(sk, buf, l2data->data_len) != l2data->data_len) {
		bttester_warn("Unable to read %u bytes", l2data->data_len);
		l_tester_test_failed(tester);

		l_io_destroy(io);
		return false;
	}

	if (memcmp(buf, l2data->read_data, l2data->data_len))
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);

	l_io_destroy(io);

	return true;
}

static void bthost_received_data(const void *buf, uint16_t len,
							void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;

	if (len != l2data->data_len) {
		l_tester_test_failed(tester);
		return;
	}

	if (memcmp(buf, l2data->write_data, l2data->data_len))
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);
}

static void server_bthost_received_data(const void *buf, uint16_t len,
							void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;

	if (len != l2data->data_len) {
		l_tester_test_failed(tester);
		return;
	}

	if (memcmp(buf, l2data->write_data, l2data->data_len))
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);
}

static bool check_mtu(struct test_data *data, int sk)
{
	const struct l2cap_data *l2data = data->test_data;
	struct l2cap_options l2o;
	socklen_t len;

	memset(&l2o, 0, sizeof(l2o));

	if (data->hciemu_type == HCIEMU_TYPE_LE &&
				(l2data->client_psm || l2data->server_psm)) {
		/* LE CoC enabled kernels should support BT_RCVMTU and
		 * BT_SNDMTU.
		 */
		len = sizeof(l2o.imtu);
		if (getsockopt(sk, SOL_BLUETOOTH, BT_RCVMTU,
							&l2o.imtu, &len) < 0) {
			bttester_warn("getsockopt(BT_RCVMTU): %s (%d)",
							strerror(errno), errno);
			return false;
		}

		len = sizeof(l2o.omtu);
		if (getsockopt(sk, SOL_BLUETOOTH, BT_SNDMTU,
							&l2o.omtu, &len) < 0) {
			bttester_warn("getsockopt(BT_SNDMTU): %s (%d)",
							strerror(errno), errno);
			return false;
		}
	} else {
		/* For non-LE CoC enabled kernels we need to fall back to
		 * L2CAP_OPTIONS, so test support for it as well */
		len = sizeof(l2o);
		if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &len) < 0) {
			bttester_warn("getsockopt(L2CAP_OPTIONS): %s (%d)",
							strerror(errno), errno);
			return false;
		 }
	}

	return true;
}

static void l2cap_disconnect_cb(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	int err, sk_err, sk;
	socklen_t len = sizeof(sk_err);

	bttester_print("Disconnect callback");
	if (l2data->shut_sock_wr) {
		/* if socket is closed using SHUT_WR, L2CAP disconnection
		 * response must be received first before EPOLLHUP event.
		 */
		if (data->host_disconnected)
			l_tester_test_passed(tester);
		else {
			bttester_warn("HUP received before L2CAP disconnect");
			l_tester_test_failed(tester);
		}

		return;
	}

	sk = l_io_get_fd(io);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	if (l2data->expect_err) {

		if (-err == l2data->expect_err)
			l_tester_test_passed(tester);
		else
			l_tester_test_failed(tester);
	}
}

static bool l2cap_connect_cb(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	int err, sk_err, sk;
	socklen_t len = sizeof(sk_err);

	sk = l_io_get_fd(io);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	if (err < 0) {
		bttester_warn("Connect failed: %s (%d)", strerror(-err), -err);
		goto failed;
	}

	bttester_print("Successfully connected");

	if (!check_mtu(data, sk)) {
		l_tester_test_failed(tester);
		return false;
	}

	if (l2data->read_data) {
		struct bthost *bthost;

		bthost = hciemu_client_get_host(data->hciemu);
		l_io_set_read_handler(io, client_received_data, NULL, NULL);

		bthost_send_cid(bthost, data->handle, data->dcid,
					l2data->read_data, l2data->data_len);

		return false;
	} else if (l2data->write_data) {
		struct bthost *bthost;
		ssize_t ret;

		bthost = hciemu_client_get_host(data->hciemu);
		bthost_add_cid_hook(bthost, data->handle, data->dcid,
					bthost_received_data, NULL);

		ret = write(sk, l2data->write_data, l2data->data_len);
		if (ret != l2data->data_len) {
			bttester_warn("Unable to write all data");
			l_tester_test_failed(tester);
		}

		return false;
	} else if (l2data->shut_sock_wr) {
		shutdown(sk, SHUT_WR);

		return false;
	}

failed:
	if (-err != l2data->expect_err)
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);

	return false;
}

static int create_l2cap_sock(struct test_data *data, uint16_t psm,
				uint16_t cid, int sec_level, uint8_t mode)
{
	const struct l2cap_data *l2data = data->test_data;
	const uint8_t *master_bdaddr;
	struct sockaddr_l2 addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK,
							BTPROTO_L2CAP);
	if (sk < 0) {
		err = -errno;
		bttester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	master_bdaddr = hciemu_get_master_bdaddr(data->hciemu);
	if (!master_bdaddr) {
		bttester_warn("No master bdaddr");
		close(sk);
		return -ENODEV;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	addr.l2_psm = htobs(psm);
	addr.l2_cid = htobs(cid);
	bacpy(&addr.l2_bdaddr, (void *) master_bdaddr);

	if (l2data && l2data->addr_type_avail)
		addr.l2_bdaddr_type = l2data->addr_type;
	else if (data->hciemu_type == HCIEMU_TYPE_LE)
		addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;
	else
		addr.l2_bdaddr_type = BDADDR_BREDR;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		bttester_warn("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		close(sk);
		return err;
	}

	if (sec_level) {
		struct bt_security sec;

		memset(&sec, 0, sizeof(sec));
		sec.level = sec_level;

		if (setsockopt(sk, SOL_BLUETOOTH, BT_SECURITY, &sec,
							sizeof(sec)) < 0) {
			err = -errno;
			bttester_warn("Can't set security level: %s (%d)",
							strerror(errno), errno);
			close(sk);
			return err;
		}
	}

	if (mode) {
		if (setsockopt(sk, SOL_BLUETOOTH, BT_MODE, &mode,
							sizeof(mode)) < 0) {
			err = -errno;
			bttester_warn("Can't set mode: %s (%d)",
							strerror(errno), errno);
			close(sk);
			return err;
		}
	}

	return sk;
}

static int connect_l2cap_impl(int sk, const uint8_t *bdaddr,
				uint8_t bdaddr_type, uint16_t psm, uint16_t cid)
{
	struct sockaddr_l2 addr;
	int err;

	if (!bdaddr) {
		bttester_warn("No client bdaddr");
		return -ENODEV;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, (void *) bdaddr);
	addr.l2_bdaddr_type = bdaddr_type;
	addr.l2_psm = htobs(psm);
	addr.l2_cid = htobs(cid);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS)) {
		err = -errno;
		bttester_warn("Can't connect socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	return 0;
}

static int connect_l2cap_sock(struct test_data *data, int sk, uint16_t psm,
								uint16_t cid)
{
	const struct l2cap_data *l2data = data->test_data;
	const uint8_t *client_bdaddr;
	uint8_t bdaddr_type;

	if (l2data->client_bdaddr != NULL)
		client_bdaddr = l2data->client_bdaddr;
	else
		client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);

	if (!client_bdaddr) {
		bttester_warn("No client bdaddr");
		return -ENODEV;
	}

	if (l2data && l2data->addr_type_avail)
		bdaddr_type = l2data->addr_type;
	else if (data->hciemu_type == HCIEMU_TYPE_LE)
		bdaddr_type = BDADDR_LE_PUBLIC;
	else
		bdaddr_type = BDADDR_BREDR;

	return connect_l2cap_impl(sk, client_bdaddr, bdaddr_type, psm, cid);
}

static void client_l2cap_connect_cb(uint16_t handle, uint16_t cid,
							void *user_data)
{
	struct test_data *data = user_data;

	data->dcid = cid;
	data->handle = handle;
}

static void client_l2cap_disconnect_cb(void *user_data)
{
	struct test_data *data = user_data;

	data->host_disconnected = true;
}

static void direct_adv_cmd_complete(uint16_t opcode, const void *param,
						uint8_t len, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct bt_hci_cmd_le_set_adv_parameters *cp;
	const uint8_t *expect_bdaddr;

	if (opcode != BT_HCI_CMD_LE_SET_ADV_PARAMETERS)
		return;

	bttester_print("Received advertising parameters HCI command");

	cp = param;

	/* Advertising as client should be direct advertising */
	if (cp->type != 0x01) {
		bttester_warn("Invalid advertising type");
		l_tester_test_failed(tester);
		return;
	}

	expect_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	if (memcmp(expect_bdaddr, cp->direct_addr, 6)) {
		bttester_warn("Invalid direct address in adv params");
		l_tester_test_failed(tester);
		return;
	}

	l_tester_test_passed(tester);
}

static void test_connect(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	int sk;

	if (l2data->server_psm) {
		struct bthost *bthost = hciemu_client_get_host(data->hciemu);
		bthost_l2cap_connect_cb host_connect_cb = NULL;
		bthost_l2cap_disconnect_cb host_disconnect_cb = NULL;

		if (l2data->data_len)
			host_connect_cb = client_l2cap_connect_cb;

		if (l2data->shut_sock_wr)
			host_disconnect_cb = client_l2cap_disconnect_cb;

		bthost_add_l2cap_server(bthost, l2data->server_psm,
					host_connect_cb, host_disconnect_cb,
					data);
	}

	if (l2data->direct_advertising)
		hciemu_add_master_post_command_hook(data->hciemu,
						direct_adv_cmd_complete, NULL);

	sk = create_l2cap_sock(data, 0, l2data->cid, l2data->sec_level,
							l2data->mode);
	if (sk < 0) {
		if (sk == -ENOPROTOOPT)
			l_tester_test_abort(tester);
		else
			l_tester_test_failed(tester);
		return;
	}

	if (connect_l2cap_sock(data, sk, l2data->client_psm,
							l2data->cid) < 0) {
		close(sk);
		l_tester_test_failed(tester);
		return;
	}

	data->io = l_io_new(sk);

	l_io_set_close_on_destroy(data->io, true);

	l_io_set_disconnect_handler(data->io, l2cap_disconnect_cb, NULL, NULL);
	l_io_set_write_handler(data->io, l2cap_connect_cb, NULL, NULL);

	bttester_print("Connect in progress");
}

static void test_connect_reject(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	int sk;

	sk = create_l2cap_sock(data, 0, l2data->cid, l2data->sec_level,
							l2data->mode);
	if (sk < 0) {
		l_tester_test_failed(tester);
		return;
	}

	if (connect_l2cap_sock(data, sk, l2data->client_psm,
							l2data->cid) < 0)
		l_tester_test_passed(tester);
	else
		l_tester_test_failed(tester);

	close(sk);
}

static struct l_io *connect_socket(const uint8_t *client_bdaddr,
					l_io_write_cb_t connect_cb, bool defer)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	struct l_io *io;
	int sk;

	sk = create_l2cap_sock(data, 0, l2data->cid, l2data->sec_level,
							l2data->mode);
	if (sk < 0) {
		bttester_print("Error in create_l2cap_sock");
		if (sk == -ENOPROTOOPT)
			l_tester_test_abort(tester);
		else
			l_tester_test_failed(tester);
		return NULL;
	}

	if (defer) {
		int opt = 1;

		if (setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP, &opt,
							sizeof(opt)) < 0) {
			bttester_print("Can't enable deferred setup: %s (%d)",
						strerror(errno), errno);
			l_tester_test_failed(tester);
			return NULL;
		}
	}

	if (connect_l2cap_impl(sk, client_bdaddr, BDADDR_LE_PUBLIC,
			l2data->client_psm, l2data->cid) < 0) {
		bttester_print("Error in connect_l2cap_sock");
		close(sk);
		l_tester_test_failed(tester);
		return NULL;
	}

	io = l_io_new(sk);
	l_io_set_close_on_destroy(io, true);
	l_io_set_write_handler(io, connect_cb, NULL, NULL);

	bttester_print("Connect in progress, sk = %d %s", sk,
						defer ? "(deferred)" : "");

	return io;
}

static void test_close_socket_1_part_3(void *arg)
{
	struct test_data *data = l_tester_get_data(tester);

	bttester_print("Checking whether scan was properly stopped...");

	if (data->sk != -1) {
		bttester_print("Error - scan was not enabled yet");
		l_tester_test_failed(tester);
		return;
	}

	if (hciemu_get_master_le_scan_enable(data->hciemu)) {
		bttester_print("Delayed check whether scann is off failed");
		l_tester_test_failed(tester);
		return;
	}

	l_tester_test_passed(tester);
}

static void test_close_socket_1_part_2(void *args)
{
	struct test_data *data = l_tester_get_data(tester);
	int sk = data->sk;

	bttester_print("Will close socket during scan phase...");

	/* We tried to conect to LE device that is not advertising. It
	 * was added to kernel whitelist, and scan was started. We
	 * should be still scanning.
	 */
	if (!hciemu_get_master_le_scan_enable(data->hciemu)) {
		bttester_print("Error - should be still scanning");
		l_tester_test_failed(tester);
		return;
	}

	/* Calling close() should remove device from  whitelist, and stop
	 * the scan.
	 */
	if (close(sk) < 0) {
		bttester_print("Error when closing socket");
		l_tester_test_failed(tester);
		return;
	}

	data->sk = -1;
	/* tester_test_passed will be called when scan is stopped. */
}

static void test_close_socket_2_part_3(void *arg)
{
	struct test_data *data = l_tester_get_data(tester);
	int sk = data->sk;
	int err;

	/* Scan should be already over, we're trying to create connection */
	if (hciemu_get_master_le_scan_enable(data->hciemu)) {
		bttester_print("Error - should no longer scan");
		l_tester_test_failed(tester);
		return;
	}

	/* Calling close() should eventually cause CMD_LE_CREATE_CONN_CANCEL */
	err = close(sk);
	if (err < 0) {
		bttester_print("Error when closing socket");
		l_tester_test_failed(tester);
		return;
	}

	/* CMD_LE_CREATE_CONN_CANCEL will trigger test pass. */
}

static bool test_close_socket_cc_hook(const void *data, uint16_t len,
							void *user_data)
{
	return false;
}

static void test_close_socket_2_part_2(void *arg)
{
	struct test_data *data = l_tester_get_data(tester);
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	/* Make sure CMD_LE_CREATE_CONN will not immediately result in
	 * BT_HCI_EVT_CONN_COMPLETE.
	 */
	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_EVT,
		BT_HCI_CMD_LE_CREATE_CONN, test_close_socket_cc_hook, NULL);

	/* Advertise once. After that, kernel should stop scanning, and trigger
	 * BT_HCI_CMD_LE_CREATE_CONN_CANCEL.
	 */
	bthost_set_adv_enable(bthost, 0x01);
	bthost_set_adv_enable(bthost, 0x00);
}

static void test_close_socket_scan_enabled(void)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;

	if (l2data == &le_client_close_socket_test_1)
		l_idle_oneshot(test_close_socket_1_part_2, NULL, NULL);
	else if (l2data == &le_client_close_socket_test_2)
		l_idle_oneshot(test_close_socket_2_part_2, NULL, NULL);
}

static void test_close_socket_scan_disabled(void)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;

	if (l2data == &le_client_close_socket_test_1)
		l_idle_oneshot(test_close_socket_1_part_3, NULL, NULL);
	else if (l2data == &le_client_close_socket_test_2)
		l_idle_oneshot(test_close_socket_2_part_3, NULL, NULL);
}

static void test_close_socket_conn_cancel(void)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;

	if (l2data == &le_client_close_socket_test_2)
		l_tester_test_passed(tester);
}

static void test_close_socket_router(uint16_t opcode, const void *param,
					uint8_t length, void *user_data)
{
	/* bttester_print("HCI Command 0x%04x length %u", opcode, length); */
	if (opcode == BT_HCI_CMD_LE_SET_SCAN_ENABLE) {
		const struct bt_hci_cmd_le_set_scan_enable *scan_params = param;

		if (scan_params->enable == true)
			test_close_socket_scan_enabled();
		else
			test_close_socket_scan_disabled();
	} else if (opcode == BT_HCI_CMD_LE_CREATE_CONN_CANCEL) {
		test_close_socket_conn_cancel();
	}
}

static void test_close_socket(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	const uint8_t *client_bdaddr;

	hciemu_add_master_post_command_hook(data->hciemu,
					test_close_socket_router, data);

	if (l2data->client_bdaddr != NULL)
		client_bdaddr = l2data->client_bdaddr;
	else
		client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);

	data->io = connect_socket(client_bdaddr, NULL, false);
	data->sk = l_io_get_fd(data->io);
}

static uint8_t test_2_connect_cb_cnt;
static bool test_2_connect_cb(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	int err, sk_err, sk;
	socklen_t len = sizeof(sk_err);

	sk = l_io_get_fd(io);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	if (err < 0) {
		bttester_warn("Connect failed: %s (%d)", strerror(-err), -err);
		l_tester_test_failed(tester);
		return false;
	}

	bttester_print("Successfully connected");
	test_2_connect_cb_cnt++;

	if (test_2_connect_cb_cnt == 2) {
		close(data->sk);
		close(data->sk2);
		l_tester_test_passed(tester);
	}

	if (l2data->close_1 && test_2_connect_cb_cnt == 1) {
		close(data->sk2);
		l_tester_test_passed(tester);
	}

	return false;
}

static void enable_advertising(void *args)
{
	struct test_data *data = l_tester_get_data(tester);
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	bthost_set_adv_enable(bthost, 0x01);
}

static void test_connect_2_part_2(void)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	const uint8_t *client_bdaddr;

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	data->io2 = connect_socket(client_bdaddr, test_2_connect_cb, false);
	data->sk2 = l_io_get_fd(data->io2);

	if (l2data->close_1) {
		bttester_print("Closing first socket! %d", data->sk);
		close(data->sk);
	}

	l_idle_oneshot(enable_advertising, NULL, NULL);
}

static uint8_t test_scan_enable_counter;
static void test_connect_2_router(uint16_t opcode, const void *param,
					uint8_t length, void *user_data)
{
	const struct bt_hci_cmd_le_set_scan_enable *scan_params = param;

	bttester_print("HCI Command 0x%04x length %u", opcode, length);
	if (opcode == BT_HCI_CMD_LE_SET_SCAN_ENABLE &&
						scan_params->enable == true) {
		test_scan_enable_counter++;
		if (test_scan_enable_counter == 1)
			test_connect_2_part_2();
		else if (test_scan_enable_counter == 2)
			l_idle_oneshot(enable_advertising, NULL, NULL);
	}
}

static void test_connect_2(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	const uint8_t *client_bdaddr;
	bool defer;

	test_2_connect_cb_cnt = 0;
	test_scan_enable_counter = 0;

	hciemu_add_master_post_command_hook(data->hciemu,
				test_connect_2_router, data);

	if (l2data->server_psm) {
		struct bthost *bthost = hciemu_client_get_host(data->hciemu);

		if (!l2data->data_len)
			bthost_add_l2cap_server(bthost, l2data->server_psm,
						NULL, NULL, NULL);
	}

	defer = (l2data->mode == BT_MODE_EXT_FLOWCTL);

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	if (l2data->close_1)
		data->io = connect_socket(client_bdaddr, NULL, defer);
	else
		data->io = connect_socket(client_bdaddr, test_2_connect_cb,
								defer);

	data->sk = l_io_get_fd(data->io);
}

static bool l2cap_listen_cb(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	int sk, new_sk;

	sk = l_io_get_fd(io);

	new_sk = accept(sk, NULL, NULL);
	if (new_sk < 0) {
		bttester_warn("accept failed: %s (%u)", strerror(errno), errno);
		l_tester_test_failed(tester);
		return false;
	}

	if (!check_mtu(data, new_sk)) {
		l_tester_test_failed(tester);
		return false;
	}

	if (l2data->read_data) {
		struct bthost *bthost;
		struct l_io *new_io;

		new_io = l_io_new(new_sk);
		l_io_set_close_on_destroy(new_io, true);

		bthost = hciemu_client_get_host(data->hciemu);
		l_io_set_read_handler(new_io, server_received_data, NULL, NULL);
		bthost_send_cid(bthost, data->handle, data->dcid,
					l2data->read_data, l2data->data_len);

		return false;
	} else if (l2data->write_data) {
		struct bthost *bthost;
		ssize_t ret;

		bthost = hciemu_client_get_host(data->hciemu);
		bthost_add_cid_hook(bthost, data->handle, data->scid,
					server_bthost_received_data, NULL);

		ret = write(new_sk, l2data->write_data, l2data->data_len);
		close(new_sk);

		if (ret != l2data->data_len) {
			bttester_warn("Unable to write all data");
			l_tester_test_failed(tester);
		}

		return false;
	}

	bttester_print("Successfully connected");

	close(new_sk);

	l_tester_test_passed(tester);

	return false;
}

static void client_l2cap_rsp(uint8_t code, const void *data, uint16_t len,
							void *user_data)
{
	struct test_data *test_data = user_data;
	const struct l2cap_data *l2data = test_data->test_data;

	bttester_print("Client received response code 0x%02x", code);

	if (code != l2data->expect_cmd_code) {
		bttester_warn("Unexpected L2CAP response code (expect 0x%02x)",
						l2data->expect_cmd_code);
		return;
	}

	if (code == BT_L2CAP_PDU_CONN_RSP) {

		const struct bt_l2cap_pdu_conn_rsp *rsp = data;
		if (len == sizeof(rsp) && !rsp->result && !rsp->status)
			return;

		test_data->dcid = rsp->dcid;
		test_data->scid = rsp->scid;

		if (l2data->data_len)
			return;
	}

	if (!l2data->expect_cmd) {
		l_tester_test_passed(tester);
		return;
	}

	if (l2data->expect_cmd_len != len) {
		bttester_warn("Unexpected L2CAP response length (%u != %u)",
						len, l2data->expect_cmd_len);
		goto failed;
	}

	if (memcmp(l2data->expect_cmd, data, len) != 0) {
		bttester_warn("Unexpected L2CAP response");
		goto failed;
	}

	l_tester_test_passed(tester);
	return;

failed:
	l_tester_test_failed(tester);
}

static void send_req_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;
	const struct l2cap_data *l2data = data->test_data;
	struct bthost *bthost;

	bttester_print("New client connection with handle 0x%04x", handle);

	data->handle = handle;

	if (l2data->send_cmd) {
		bthost_l2cap_rsp_cb cb;

		if (l2data->expect_cmd_code)
			cb = client_l2cap_rsp;
		else
			cb = NULL;

		bttester_print("Sending L2CAP Request from client");

		bthost = hciemu_client_get_host(data->hciemu);
		bthost_l2cap_req(bthost, handle, l2data->send_cmd_code,
					l2data->send_cmd, l2data->send_cmd_len,
					cb, data);
	}
}

static void test_server(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct l2cap_data *l2data = data->test_data;
	const uint8_t *master_bdaddr;
	uint8_t addr_type;
	struct bthost *bthost;
	int sk;

	if (l2data->server_psm || l2data->cid) {
		sk = create_l2cap_sock(data, l2data->server_psm,
					l2data->cid, l2data->sec_level,
					l2data->mode);
		if (sk < 0) {
			l_tester_test_failed(tester);
			return;
		}

		if (listen(sk, 5) < 0) {
			bttester_warn("listening on socket failed: %s (%u)",
							strerror(errno), errno);
			l_tester_test_failed(tester);
			close(sk);
			return;
		}

		data->io = l_io_new(sk);
		l_io_set_close_on_destroy(data->io, true);
		l_io_set_read_handler(data->io, l2cap_listen_cb, NULL, NULL);

		bttester_print("Listening for connections");
	}

	master_bdaddr = hciemu_get_master_bdaddr(data->hciemu);
	if (!master_bdaddr) {
		bttester_warn("No master bdaddr");
		l_tester_test_failed(tester);
		return;
	}

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_connect_cb(bthost, send_req_new_conn, data);

	if (data->hciemu_type == HCIEMU_TYPE_BREDR)
		addr_type = BDADDR_BREDR;
	else
		addr_type = BDADDR_LE_PUBLIC;

	bthost_hci_connect(bthost, master_bdaddr, addr_type);
}

static void test_getpeername_not_connected(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	struct sockaddr_l2 addr;
	socklen_t len;
	int sk;

	sk = create_l2cap_sock(data, 0, 0, 0, 0);
	if (sk < 0) {
		l_tester_test_failed(tester);
		return;
	}

	len = sizeof(addr);
	if (getpeername(sk, (struct sockaddr *) &addr, &len) == 0) {
		bttester_warn("getpeername succeeded on non-connected socket");
		l_tester_test_failed(tester);
		goto done;
	}

	if (errno != ENOTCONN) {
		bttester_warn("Unexpected getpeername error: %s (%d)",
						strerror(errno), errno);
		l_tester_test_failed(tester);
		goto done;
	}

	l_tester_test_passed(tester);

done:
	close(sk);
}

int main(int argc, char *argv[])
{
	tester = bttester_init(&argc, &argv);

	test_l2cap_bredr("Basic L2CAP Socket - Success", NULL,
					setup_powered_client, test_basic);
	test_l2cap_bredr("Non-connected getpeername - Failure", NULL,
					setup_powered_client,
					test_getpeername_not_connected);

	test_l2cap_bredr("L2CAP BR/EDR Client - Success",
					&client_connect_success_test,
					setup_powered_client, test_connect);

	test_l2cap_bredr("L2CAP BR/EDR Client SSP - Success 1",
					&client_connect_ssp_success_test_1,
					setup_powered_client, test_connect);
	test_l2cap_bredr("L2CAP BR/EDR Client SSP - Success 2",
					&client_connect_ssp_success_test_2,
					setup_powered_client, test_connect);
	test_l2cap_bredr("L2CAP BR/EDR Client PIN Code - Success",
					&client_connect_pin_success_test,
					setup_powered_client, test_connect);

	test_l2cap_bredr("L2CAP BR/EDR Client - Read Success",
					&client_connect_read_success_test,
					setup_powered_client, test_connect);

	test_l2cap_bredr("L2CAP BR/EDR Client - Write Success",
					&client_connect_write_success_test,
					setup_powered_client, test_connect);

	test_l2cap_bredr("L2CAP BR/EDR Client - Invalid PSM 1",
					&client_connect_nval_psm_test_1,
					setup_powered_client, test_connect);

	test_l2cap_bredr("L2CAP BR/EDR Client - Invalid PSM 2",
					&client_connect_nval_psm_test_2,
					setup_powered_client, test_connect);

	test_l2cap_bredr("L2CAP BR/EDR Client - Invalid PSM 3",
					&client_connect_nval_psm_test_3,
					setup_powered_client, test_connect);

	test_l2cap_bredr("L2CAP BR/EDR Client - Socket Shut WR Success",
					&client_connect_shut_wr_success_test,
					setup_powered_client, test_connect);

	test_l2cap_bredr("L2CAP BR/EDR Server - Success",
					&l2cap_server_success_test,
					setup_powered_server, test_server);

	test_l2cap_bredr("L2CAP BR/EDR Server - Read Success",
					&l2cap_server_read_success_test,
					setup_powered_server, test_server);

	test_l2cap_bredr("L2CAP BR/EDR Server - Write Success",
					&l2cap_server_write_success_test,
					setup_powered_server, test_server);

	test_l2cap_bredr("L2CAP BR/EDR Server - Security Block",
					&l2cap_server_sec_block_test,
					setup_powered_server, test_server);

	test_l2cap_bredr("L2CAP BR/EDR Server - Invalid PSM",
					&l2cap_server_nval_psm_test,
					setup_powered_server, test_server);
	test_l2cap_bredr("L2CAP BR/EDR Server - Invalid PDU",
				&l2cap_server_nval_pdu_test1,
				setup_powered_server, test_server);
	test_l2cap_bredr("L2CAP BR/EDR Server - Invalid Disconnect CID",
				&l2cap_server_nval_cid_test1,
				setup_powered_server, test_server);
	test_l2cap_bredr("L2CAP BR/EDR Server - Invalid Config CID",
				&l2cap_server_nval_cid_test2,
				setup_powered_server, test_server);

	test_l2cap_le("L2CAP LE Client - Success",
				&le_client_connect_success_test_1,
				setup_powered_client, test_connect);
	test_l2cap_le("L2CAP LE Client, Direct Advertising - Success",
				&le_client_connect_adv_success_test_1,
				setup_powered_client, test_connect);
	test_l2cap_le("L2CAP LE Client SMP - Success",
				&le_client_connect_success_test_2,
				setup_powered_client, test_connect);
	test_l2cap_le("L2CAP LE Client - Command Reject",
					&le_client_connect_reject_test_1,
					setup_powered_client, test_connect);
	test_l2cap_bredr("L2CAP LE Client - Connection Reject",
				&le_client_connect_reject_test_2,
				setup_powered_client, test_connect_reject);

	test_l2cap_le("L2CAP LE Client - Close socket 1",
				&le_client_close_socket_test_1,
				setup_powered_client,
				test_close_socket);

	test_l2cap_le("L2CAP LE Client - Close socket 2",
				&le_client_close_socket_test_2,
				setup_powered_client,
				test_close_socket);

	test_l2cap_le("L2CAP LE Client - Open two sockets",
				&le_client_2_same_client,
				setup_powered_client,
				test_connect_2);

	test_l2cap_le("L2CAP LE Client - Open two sockets close one",
				&le_client_2_close_1,
				setup_powered_client,
				test_connect_2);

	test_l2cap_le("L2CAP LE Client - Invalid PSM",
					&le_client_connect_nval_psm_test,
					setup_powered_client, test_connect);
	test_l2cap_le("L2CAP LE Server - Success", &le_server_success_test,
					setup_powered_server, test_server);
	test_l2cap_le("L2CAP LE Server - Nval SCID", &le_server_nval_scid_test,
					setup_powered_server, test_server);


	test_l2cap_le("L2CAP Ext-Flowctl Client - Success",
				&ext_flowctl_client_connect_success_test_1,
				setup_powered_client, test_connect);
	test_l2cap_le("L2CAP Ext-Flowctl Client, Direct Advertising - Success",
				&ext_flowctl_client_connect_adv_success_test_1,
				setup_powered_client, test_connect);
	test_l2cap_le("L2CAP Ext-Flowctl Client SMP - Success",
				&ext_flowctl_client_connect_success_test_2,
				setup_powered_client, test_connect);
	test_l2cap_le("L2CAP Ext-Flowctl Client - Command Reject",
				&ext_flowctl_client_connect_reject_test_1,
				setup_powered_client, test_connect);

	test_l2cap_le("L2CAP Ext-Flowctl Client - Open two sockets",
				&ext_flowctl_client_2,
				setup_powered_client,
				test_connect_2);

	test_l2cap_le("L2CAP Ext-Flowctl Client - Open two sockets close one",
				&ext_flowctl_client_2_close_1,
				setup_powered_client,
				test_connect_2);

	test_l2cap_le("L2CAP LE ATT Client - Success",
				&le_att_client_connect_success_test_1,
				setup_powered_client, test_connect);
	test_l2cap_le("L2CAP LE ATT Server - Success",
				&le_att_server_success_test_1,
				setup_powered_server, test_server);

	return bttester_run();
}
