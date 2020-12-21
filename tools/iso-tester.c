// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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

#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/iso.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"
#include "emulator/bthost.h"
#include "emulator/hciemu.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/util.h"

#define QOS_IO(_interval, _latency, _sdu, _phy, _rtn) \
{ \
	.interval = _interval, \
	.latency = _latency, \
	.sdu = _sdu, \
	.phy = _phy, \
	.rtn = _rtn, \
}

#define QOS_FULL(_in, _out) \
{ \
	.cig = BT_ISO_QOS_CIG_UNSET, \
	.cis = BT_ISO_QOS_CIS_UNSET, \
	.sca = 0x07, \
	.packing = 0x00, \
	.framing = 0x00, \
	.in = _in, \
	.out = _out, \
}

#define QOS(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL(QOS_IO(_interval, _latency, _sdu, _phy, _rtn), \
		QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

#define QOS_OUT(_interval, _latency, _sdu, _phy, _rtn) \
	QOS_FULL({}, QOS_IO(_interval, _latency, _sdu, _phy, _rtn))

/* QoS Configuration settings for low latency audio data */
#define QOS_8_1_1 QOS(7500, 8, 26, 0x02, 2)
#define QOS_8_2_1 QOS(10000, 10, 30, 0x02, 2)
#define QOS_16_1_1 QOS(7500, 8, 30, 0x02, 2)
#define QOS_16_2_1 QOS(10000, 10, 40, 0x02, 2)
#define QOS_24_1_1 QOS(7500, 8, 45, 0x02, 2)
#define QOS_24_2_1 QOS(10000, 10, 60, 0x02, 2)
#define QOS_32_1_1 QOS(7500, 8, 60, 0x02, 2)
#define QOS_32_2_1 QOS(10000, 10, 80, 0x02, 2)
#define QOS_44_1_1 QOS_OUT(8163, 24, 98, 0x02, 5)
#define QOS_44_2_1 QOS_OUT(10884, 31, 130, 0x02, 5)
#define QOS_48_1_1 QOS_OUT(7500, 15, 75, 0x02, 5)
#define QOS_48_2_1 QOS_OUT(10000, 20, 100, 0x02, 5)
#define QOS_48_3_1 QOS_OUT(7500, 15, 90, 0x02, 5)
#define QOS_48_4_1 QOS_OUT(10000, 20, 120, 0x02, 5)
#define QOS_48_5_1 QOS_OUT(7500, 15, 117, 0x02, 5)
#define QOS_48_6_1 QOS_OUT(10000, 20, 155, 0x02, 5)
/* QoS Configuration settings for high reliability audio data */
#define QOS_8_1_2 QOS(7500, 45, 26, 0x02, 41)
#define QOS_8_2_2 QOS(10000, 60, 30, 0x02, 53)
#define QOS_16_1_2 QOS(7500, 45, 30, 0x02, 41)
#define QOS_16_2_2 QOS(10000, 60, 40, 0x02, 47)
#define QOS_24_1_2 QOS(7500, 45, 45, 0x02, 35)
#define QOS_24_2_2 QOS(10000, 60, 60, 0x02, 41)
#define QOS_32_1_2 QOS(7500, 45, 60, 0x02, 29)
#define QOS_32_2_2 QOS(10000, 60, 80, 0x02, 35)
#define QOS_44_1_2 QOS_OUT(8163, 54, 98, 0x02, 23)
#define QOS_44_2_2 QOS_OUT(10884, 71, 130, 0x02, 23)
#define QOS_48_1_2 QOS_OUT(7500, 45, 75, 0x02, 23)
#define QOS_48_2_2 QOS_OUT(10000, 60, 100, 0x02, 23)
#define QOS_48_3_2 QOS_OUT(7500, 45, 90, 0x02, 23)
#define QOS_48_4_2 QOS_OUT(10000, 60, 120, 0x02, 23)
#define QOS_48_5_2 QOS_OUT(7500, 45, 117, 0x02, 23)
#define QOS_48_6_2 QOS_OUT(10000, 60, 155, 0x02, 23)

struct test_data {
	const void *test_data;
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	unsigned int io_id[2];
	uint8_t client_num;
	int step;
};

struct iso_client_data {
	struct bt_iso_qos qos;
	int expect_err;
};

static void mgmt_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	tester_print("%s%s", prefix, str);
}

static void read_info_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_info *rp = param;
	char addr[18];
	uint16_t manufacturer;
	uint32_t supported_settings, current_settings;

	tester_print("Read Info callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	ba2str(&rp->bdaddr, addr);
	manufacturer = btohs(rp->manufacturer);
	supported_settings = btohl(rp->supported_settings);
	current_settings = btohl(rp->current_settings);

	tester_print("  Address: %s", addr);
	tester_print("  Version: 0x%02x", rp->version);
	tester_print("  Manufacturer: 0x%04x", manufacturer);
	tester_print("  Supported settings: 0x%08x", supported_settings);
	tester_print("  Current settings: 0x%08x", current_settings);
	tester_print("  Class: 0x%02x%02x%02x",
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);
	tester_print("  Name: %s", rp->name);
	tester_print("  Short name: %s", rp->short_name);

	if (strcmp(hciemu_get_address(data->hciemu), addr)) {
		tester_pre_setup_failed();
		return;
	}

	tester_pre_setup_complete();
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Added callback");
	tester_print("  Index: 0x%04x", index);

	data->mgmt_index = index;

	mgmt_send(data->mgmt, MGMT_OP_READ_INFO, data->mgmt_index, 0, NULL,
					read_info_callback, NULL, NULL);
}

static void index_removed_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Removed callback");
	tester_print("  Index: 0x%04x", index);

	if (index != data->mgmt_index)
		return;

	mgmt_unregister_index(data->mgmt, data->mgmt_index);

	mgmt_unref(data->mgmt);
	data->mgmt = NULL;

	tester_post_teardown_complete();
}

static void hciemu_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	tester_print("%s%s", prefix, str);
}

static void read_index_list_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Read Index List callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	mgmt_register(data->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, NULL, NULL);

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	data->hciemu = hciemu_new_num(HCIEMU_TYPE_BREDRLE52, data->client_num);
	if (!data->hciemu) {
		tester_warn("Failed to setup HCI emulation");
		tester_pre_setup_failed();
		return;
	}

	if (tester_use_debug())
		hciemu_set_debug(data->hciemu, hciemu_debug, "hciemu: ", NULL);

	tester_print("New hciemu instance created");
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	if (tester_use_debug())
		mgmt_set_debug(data->mgmt, mgmt_debug, "mgmt: ", NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void test_data_free(void *test_data)
{
	struct test_data *data = test_data;

	if (data->io_id[0] > 0)
		g_source_remove(data->io_id[0]);

	if (data->io_id[1] > 0)
		g_source_remove(data->io_id[1]);

	free(data);
}

#define test_iso_full(name, data, setup, func, num) \
	do { \
		struct test_data *user; \
		user = new0(struct test_data, 1); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDRLE; \
		user->test_data = data; \
		user->client_num = num; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, test_data_free); \
	} while (0)

#define test_iso(name, data, setup, func) \
	test_iso_full(name, data, setup, func, 1)

#define test_iso2(name, data, setup, func) \
	test_iso_full(name, data, setup, func, 2)

static const struct iso_client_data connect_8_1_1 = {
	.qos = QOS_8_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_8_2_1 = {
	.qos = QOS_8_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_16_1_1 = {
	.qos = QOS_16_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_16_2_1 = {
	.qos = QOS_16_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_24_1_1 = {
	.qos = QOS_24_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_24_2_1 = {
	.qos = QOS_24_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_32_1_1 = {
	.qos = QOS_32_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_32_2_1 = {
	.qos = QOS_32_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_44_1_1 = {
	.qos = QOS_44_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_44_2_1 = {
	.qos = QOS_44_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_1_1 = {
	.qos = QOS_48_1_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_2_1 = {
	.qos = QOS_48_2_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_3_1 = {
	.qos = QOS_48_3_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_4_1 = {
	.qos = QOS_48_4_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_5_1 = {
	.qos = QOS_48_5_1,
	.expect_err = 0
};

static const struct iso_client_data connect_48_6_1 = {
	.qos = QOS_48_6_1,
	.expect_err = 0
};

static const struct iso_client_data connect_8_1_2 = {
	.qos = QOS_8_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_8_2_2 = {
	.qos = QOS_8_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_16_1_2 = {
	.qos = QOS_16_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_16_2_2 = {
	.qos = QOS_16_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_24_1_2 = {
	.qos = QOS_24_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_24_2_2 = {
	.qos = QOS_24_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_32_1_2 = {
	.qos = QOS_32_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_32_2_2 = {
	.qos = QOS_32_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_44_1_2 = {
	.qos = QOS_44_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_44_2_2 = {
	.qos = QOS_44_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_1_2 = {
	.qos = QOS_48_1_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_2_2 = {
	.qos = QOS_48_2_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_3_2 = {
	.qos = QOS_48_3_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_4_2 = {
	.qos = QOS_48_4_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_5_2 = {
	.qos = QOS_48_5_2,
	.expect_err = 0
};

static const struct iso_client_data connect_48_6_2 = {
	.qos = QOS_48_6_2,
	.expect_err = 0
};

static void client_connectable_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	struct test_data *data = user_data;
	static uint8_t client_num;

	if (opcode != BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE)
		return;

	tester_print("Client %u set connectable status 0x%02x", client_num,
								status);

	client_num++;

	if (status)
		tester_setup_failed();
	else if (data->client_num == client_num) {
		tester_setup_complete();
		client_num = 0;
	}
}

static void setup_powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	uint8_t i;

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	for (i = 0; i < data->client_num; i++) {
		struct hciemu_client *client;
		struct bthost *host;

		client = hciemu_get_client(data->hciemu, i);
		host = hciemu_client_host(client);
		bthost_set_cmd_complete_cb(host, client_connectable_complete,
									data);
		bthost_set_ext_adv_enable(host, 0x01);
	}
}

static void setup_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void test_framework(const void *test_data)
{
	tester_test_passed();
}

static void test_socket(const void *test_data)
{
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_abort();
		return;
	}

	close(sk);

	tester_test_passed();
}

static void test_getsockopt(const void *test_data)
{
	int sk, err;
	socklen_t len;
	struct bt_iso_qos qos;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_abort();
		return;
	}

	len = sizeof(qos);
	memset(&qos, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	tester_test_passed();

end:
	close(sk);
}

static void test_setsockopt(const void *test_data)
{
	int sk, err;
	socklen_t len;
	struct bt_iso_qos qos = QOS_16_1_2;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_abort();
		goto end;
	}

	err = setsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, sizeof(qos));
	if (err < 0) {
		tester_warn("Can't set socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	len = sizeof(qos);
	memset(&qos, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	tester_test_passed();

end:
	close(sk);
}

static int create_iso_sock(struct test_data *data)
{
	const uint8_t *master_bdaddr;
	struct sockaddr_iso addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK, BTPROTO_ISO);
	if (sk < 0) {
		err = -errno;
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		return -EPROTONOSUPPORT;
	}

	master_bdaddr = hciemu_get_master_bdaddr(data->hciemu);
	if (!master_bdaddr) {
		tester_warn("No master bdaddr");
		return -ENODEV;
	}

	memset(&addr, 0, sizeof(addr));
	addr.iso_family = AF_BLUETOOTH;
	bacpy(&addr.iso_bdaddr, (void *) master_bdaddr);
	addr.iso_bdaddr_type = BDADDR_LE_PUBLIC;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		tester_warn("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		close(sk);
		return err;
	}

	return sk;
}

static int connect_iso_sock(struct test_data *data, uint8_t num, int sk)
{
	const struct iso_client_data *isodata = data->test_data;
	struct hciemu_client *client;
	const uint8_t *client_bdaddr;
	struct sockaddr_iso addr;
	char str[18];
	int err;

	client = hciemu_get_client(data->hciemu, num);
	if (!client) {
		tester_warn("No client");
		return -ENODEV;
	}

	client_bdaddr = hciemu_client_bdaddr(client);
	if (!client_bdaddr) {
		tester_warn("No client bdaddr");
		return -ENODEV;
	}

	err = setsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &isodata->qos,
						sizeof(isodata->qos));
	if (err < 0) {
		tester_warn("Can't set socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		return -EINVAL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.iso_family = AF_BLUETOOTH;
	bacpy(&addr.iso_bdaddr, (void *) client_bdaddr);
	addr.iso_bdaddr_type = BDADDR_LE_PUBLIC;

	ba2str(&addr.iso_bdaddr, str);

	tester_print("Connecting to %s...", str);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS)) {
		err = -errno;
		tester_warn("Can't connect socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	return 0;
}

static bool check_io_qos(const struct bt_iso_io_qos *io1,
				const struct bt_iso_io_qos *io2)
{
	if (io1->interval != io2->interval) {
		tester_warn("Unexpected IO interval: %u != %u",
				io1->interval, io2->interval);
		return false;
	}

	if (io1->latency != io2->latency) {
		tester_warn("Unexpected IO latency: %u != %u",
				io1->latency, io2->latency);
		return false;
	}

	if (io1->sdu != io2->sdu) {
		tester_warn("Unexpected IO SDU: %u != %u", io1->sdu, io2->sdu);
		return false;
	}

	if (io2->phy && io1->phy != io2->phy) {
		tester_warn("Unexpected IO PHY: 0x%02x != 0x%02x",
				io1->phy, io2->phy);
		return false;
	}

	if (io1->rtn != io2->rtn) {
		tester_warn("Unexpected IO RTN: %u != %u", io1->rtn, io2->rtn);
		return false;
	}

	return true;
}

static bool check_qos(const struct bt_iso_qos *qos1,
				const struct bt_iso_qos *qos2)
{
	if (qos1->packing != qos2->packing) {
		tester_warn("Unexpected QoS packing: 0x%02x != 0x%02x",
				qos1->packing, qos2->packing);
		return false;
	}

	if (qos1->framing != qos2->framing) {
		tester_warn("Unexpected QoS framing: 0x%02x != 0x%02x",
				qos1->framing, qos2->framing);
		return false;
	}

	if (!check_io_qos(&qos1->in, &qos2->in)) {
		tester_warn("Unexpected Input QoS");
		return false;
	}

	if (!check_io_qos(&qos1->out, &qos2->out)) {
		tester_warn("Unexpected Output QoS");
		return false;
	}

	return true;
}

static gboolean iso_connect(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct iso_client_data *isodata = data->test_data;
	int err, sk_err, sk;
	socklen_t len;
	struct bt_iso_qos qos;

	data->io_id[0] = 0;

	sk = g_io_channel_unix_get_fd(io);

	len = sizeof(qos);
	memset(&qos, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		return FALSE;
	}

	if (!check_qos(&qos, &isodata->qos)) {
		tester_warn("Unexpected QoS parameter");
		tester_test_failed();
		return FALSE;
	}

	len = sizeof(sk_err);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	if (err < 0)
		tester_warn("Connect failed: %s (%d)", strerror(-err), -err);
	else
		tester_print("Successfully connected");

	if (-err != isodata->expect_err)
		tester_test_failed();
	else {
		data->step--;
		if (data->step)
			tester_print("Step %u", data->step);
		else
			tester_test_passed();
	}

	return FALSE;
}

static gboolean iso_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();

	data->io_id[0] = 0;

	return iso_connect(io, cond, user_data);
}

static gboolean iso_connect2_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();

	data->io_id[1] = 0;

	return iso_connect(io, cond, user_data);
}

static void setup_connect(struct test_data *data, uint8_t num, GIOFunc func)
{
	GIOChannel *io;
	int sk;

	sk = create_iso_sock(data);
	if (sk < 0) {
		if (sk == -EPROTONOSUPPORT)
			tester_test_abort();
		else
			tester_test_failed();
		return;
	}

	if (connect_iso_sock(data, num, sk) < 0) {
		close(sk);
		tester_test_failed();
		return;
	}

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	data->io_id[num] = g_io_add_watch(io, G_IO_OUT, func, NULL);

	g_io_channel_unref(io);

	tester_print("Connect in progress");

	data->step++;
}

static void test_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup_connect(data, 0, iso_connect_cb);
}

static void test_connect2(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup_connect(data, 0, iso_connect_cb);
	setup_connect(data, 1, iso_connect2_cb);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_iso("Basic Framework - Success", NULL, setup_powered,
							test_framework);

	test_iso("Basic ISO Socket - Success", NULL, setup_powered,
							test_socket);

	test_iso("Basic ISO Get Socket Option - Success", NULL, setup_powered,
							test_getsockopt);

	test_iso("Basic ISO Set Socket Option - Success", NULL, setup_powered,
							test_setsockopt);

	test_iso("ISO QoS 8_1_1 - Success", &connect_8_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 8_2_1 - Success", &connect_8_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_1_1 - Success", &connect_16_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_2_1 - Success", &connect_16_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 24_1_1 - Success", &connect_24_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 24_2_1 - Success", &connect_24_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_1_1 - Success", &connect_32_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_2_1 - Success", &connect_32_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 44_1_1 - Success", &connect_44_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 44_2_1 - Success", &connect_44_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_1_1 - Success", &connect_48_1_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_2_1 - Success", &connect_48_2_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_3_1 - Success", &connect_48_3_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_4_1 - Success", &connect_48_4_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_5_1 - Success", &connect_48_5_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_6_1 - Success", &connect_48_6_1, setup_powered,
							test_connect);

	test_iso("ISO QoS 8_1_2 - Success", &connect_8_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 8_2_2 - Success", &connect_8_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_1_2 - Success", &connect_16_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 16_2_2 - Success", &connect_16_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 24_1_2 - Success", &connect_24_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 24_2_2 - Success", &connect_24_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_1_2 - Success", &connect_32_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 32_2_2 - Success", &connect_32_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 44_1_2 - Success", &connect_44_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 44_2_2 - Success", &connect_44_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_1_2 - Success", &connect_48_1_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_2_2 - Success", &connect_48_2_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_3_2 - Success", &connect_48_3_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_4_2 - Success", &connect_48_4_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_5_2 - Success", &connect_48_5_2, setup_powered,
							test_connect);

	test_iso("ISO QoS 48_6_2 - Success", &connect_48_6_2, setup_powered,
							test_connect);

	test_iso2("ISO Connect2 - Success", &connect_16_2_1, setup_powered,
							test_connect2);

	return tester_run();
}
