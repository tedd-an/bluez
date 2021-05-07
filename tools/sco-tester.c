// spdx-License-Identifier: GPL-2.0-or-later
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
#include "lib/sco.h"
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
	enum hciemu_type hciemu_type;
	struct l_io *io;
	bool disable_esco;
};

struct sco_client_data {
	int expect_err;
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

	data->hciemu = hciemu_new(HCIEMU_TYPE_BREDRLE);
	if (!data->hciemu) {
		bttester_warn("Failed to setup HCI emulation");
		l_tester_pre_setup_failed(tester);
		return;
	}

	if (bttester_use_debug())
		hciemu_set_debug(data->hciemu, print_debug, "hciemu: ", NULL);

	bttester_print("New hciemu instance created");

	if (data->disable_esco) {
		uint8_t *features;

		bttester_print("Disabling eSCO packet type support");

		features = hciemu_get_features(data->hciemu);
		if (features)
			features[3] &= ~0x80;
	}
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

	if (data->io) {
		l_io_destroy(data->io);
		data->io = NULL;
	}

	l_free(data);
}

#define test_sco_full(name, data, setup, func, _disable_esco) \
	do { \
		struct test_data *user; \
		user = l_new(struct test_data, 1); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDRLE; \
		user->test_data = data; \
		user->disable_esco = _disable_esco; \
		l_tester_add_full(tester, name, data, test_pre_setup, setup, \
					func, NULL, test_post_teardown, 2, \
					user, test_data_free); \
	} while (0)

#define test_sco(name, data, setup, func) \
	test_sco_full(name, data, setup, func, false)

#define test_sco_11(name, data, setup, func) \
	test_sco_full(name, data, setup, func, true)

static const struct sco_client_data connect_success = {
	.expect_err = 0
};

static const struct sco_client_data connect_failure = {
	.expect_err = EOPNOTSUPP
};

static void client_connectable_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	if (opcode != BT_HCI_CMD_WRITE_SCAN_ENABLE)
		return;

	bttester_print("Client set connectable status 0x%02x", status);

	if (status)
		l_tester_setup_failed(tester);
	else
		l_tester_setup_complete(tester);
}

static void setup_powered_callback(uint8_t status, uint16_t length,
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

static void setup_powered(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	unsigned char param[] = { 0x01 };

	bttester_print("Powering on controller");

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
	l_tester_test_passed(tester);
}

static void test_socket(const void *test_data)
{
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		bttester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		l_tester_test_failed(tester);
		return;
	}

	close(sk);

	l_tester_test_passed(tester);
}

static void test_getsockopt(const void *test_data)
{
	int sk, err;
	socklen_t len;
	struct bt_voice voice;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		bttester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		l_tester_test_failed(tester);
		return;
	}

	len = sizeof(voice);
	memset(&voice, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, &len);
	if (err < 0) {
		bttester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		l_tester_test_failed(tester);
		goto end;
	}

	if (voice.setting != BT_VOICE_CVSD_16BIT) {
		bttester_warn("Invalid voice setting");
		l_tester_test_failed(tester);
		goto end;
	}

	l_tester_test_passed(tester);

end:
	close(sk);
}

static void test_setsockopt(const void *test_data)
{
	int sk, err;
	socklen_t len;
	struct bt_voice voice;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		bttester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		l_tester_test_failed(tester);
		goto end;
	}


	len = sizeof(voice);
	memset(&voice, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, &len);
	if (err < 0) {
		bttester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		l_tester_test_failed(tester);
		goto end;
	}

	if (voice.setting != BT_VOICE_CVSD_16BIT) {
		bttester_warn("Invalid voice setting");
		l_tester_test_failed(tester);
		goto end;
	}

	memset(&voice, 0, sizeof(voice));
	voice.setting = BT_VOICE_TRANSPARENT;

	err = setsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, sizeof(voice));
	if (err < 0) {
		bttester_warn("Can't set socket option : %s (%d)",
							strerror(errno), errno);
		l_tester_test_failed(tester);
		goto end;
	}

	len = sizeof(voice);
	memset(&voice, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, &len);
	if (err < 0) {
		bttester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		l_tester_test_failed(tester);
		goto end;
	}

	if (voice.setting != BT_VOICE_TRANSPARENT) {
		bttester_warn("Invalid voice setting");
		l_tester_test_failed(tester);
		goto end;
	}

	l_tester_test_passed(tester);

end:
	close(sk);
}

static int create_sco_sock(struct test_data *data)
{
	const uint8_t *master_bdaddr;
	struct sockaddr_sco addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK,
								BTPROTO_SCO);
	if (sk < 0) {
		err = -errno;
		bttester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	master_bdaddr = hciemu_get_master_bdaddr(data->hciemu);
	if (!master_bdaddr) {
		bttester_warn("No master bdaddr");
		return -ENODEV;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, (void *) master_bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		bttester_warn("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		close(sk);
		return err;
	}

	return sk;
}

static int connect_sco_sock(struct test_data *data, int sk)
{
	const uint8_t *client_bdaddr;
	struct sockaddr_sco addr;
	int err;

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	if (!client_bdaddr) {
		bttester_warn("No client bdaddr");
		return -ENODEV;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, (void *) client_bdaddr);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS)) {
		err = -errno;
		bttester_warn("Can't connect socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	return 0;
}

static bool sco_connect_cb(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct sco_client_data *scodata = data->test_data;
	int err, sk_err, sk;
	socklen_t len = sizeof(sk_err);

	sk = l_io_get_fd(io);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	if (err < 0)
		bttester_warn("Connect failed: %s (%d)", strerror(-err), -err);
	else
		bttester_print("Successfully connected");

	if (-err != scodata->expect_err)
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);

	return false;
}

static void test_connect(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	int sk;

	sk = create_sco_sock(data);
	if (sk < 0) {
		l_tester_test_failed(tester);
		return;
	}

	if (connect_sco_sock(data, sk) < 0) {
		close(sk);
		l_tester_test_failed(tester);
		return;
	}

	data->io = l_io_new(sk);
	l_io_set_close_on_destroy(data->io, true);

	l_io_set_write_handler(data->io, sco_connect_cb, NULL, NULL);

	bttester_print("Connect in progress");
}

static void test_connect_transp(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct sco_client_data *scodata = data->test_data;
	int sk, err;
	struct bt_voice voice;

	sk = create_sco_sock(data);
	if (sk < 0) {
		l_tester_test_failed(tester);
		return;
	}

	memset(&voice, 0, sizeof(voice));
	voice.setting = BT_VOICE_TRANSPARENT;

	err = setsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, sizeof(voice));
	if (err < 0) {
		bttester_warn("Can't set socket option : %s (%d)",
							strerror(errno), errno);
		l_tester_test_failed(tester);
		goto end;
	}

	err = connect_sco_sock(data, sk);

	bttester_warn("Connect returned %s (%d), expected %s (%d)",
								strerror(-err),
		-err, strerror(scodata->expect_err), scodata->expect_err);

	if (-err != scodata->expect_err)
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);

end:
	close(sk);
}

int main(int argc, char *argv[])
{
	tester = bttester_init(&argc, &argv);

	test_sco("Basic Framework - Success", NULL, setup_powered,
							test_framework);

	test_sco("Basic SCO Socket - Success", NULL, setup_powered,
							test_socket);

	test_sco("Basic SCO Get Socket Option - Success", NULL, setup_powered,
							test_getsockopt);

	test_sco("Basic SCO Set Socket Option - Success", NULL, setup_powered,
							test_setsockopt);

	test_sco("eSCO CVSD - Success", &connect_success, setup_powered,
							test_connect);

	test_sco("eSCO mSBC - Success", &connect_success, setup_powered,
							test_connect_transp);

	test_sco_11("SCO CVSD 1.1 - Success", &connect_success, setup_powered,
							test_connect);

	test_sco_11("SCO mSBC 1.1 - Failure", &connect_failure, setup_powered,
							test_connect_transp);

	return bttester_run();
}
