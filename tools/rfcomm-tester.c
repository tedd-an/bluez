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
#include "lib/rfcomm.h"
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
	struct l_io *io;
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

	if (data->io) {
		l_io_destroy(data->io);
		data->io = NULL;
	}

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

static void setup_powered_server_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		l_tester_setup_failed(tester);
		return;
	}

	bttester_print("Controller powered on");

	l_tester_setup_complete(tester);
}

static void setup_powered_server(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	unsigned char param[] = { 0x01 };

	bttester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
				sizeof(param), param,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, setup_powered_server_callback,
			NULL, NULL);
}

const struct rfcomm_client_data connect_success = {
	.server_channel = 0x0c,
	.client_channel = 0x0c
};

const uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};

const struct rfcomm_client_data connect_send_success = {
	.server_channel = 0x0c,
	.client_channel = 0x0c,
	.data_len = sizeof(data),
	.send_data = data
};

const struct rfcomm_client_data connect_read_success = {
	.server_channel = 0x0c,
	.client_channel = 0x0c,
	.data_len = sizeof(data),
	.read_data = data
};

const struct rfcomm_client_data connect_nval = {
	.server_channel = 0x0c,
	.client_channel = 0x0e,
	.expected_connect_err = -ECONNREFUSED
};

const struct rfcomm_server_data listen_success = {
	.server_channel = 0x0c,
	.client_channel = 0x0c,
	.expected_status = true
};

const struct rfcomm_server_data listen_send_success = {
	.server_channel = 0x0c,
	.client_channel = 0x0c,
	.expected_status = true,
	.data_len = sizeof(data),
	.send_data = data
};

const struct rfcomm_server_data listen_read_success = {
	.server_channel = 0x0c,
	.client_channel = 0x0c,
	.expected_status = true,
	.data_len = sizeof(data),
	.read_data = data
};

const struct rfcomm_server_data listen_nval = {
	.server_channel = 0x0c,
	.client_channel = 0x0e,
	.expected_status = false
};

static void test_basic(const void *test_data)
{
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		bttester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		l_tester_test_failed(tester);
		return;
	}

	close(sk);

	l_tester_test_passed(tester);
}

static int create_rfcomm_sock(bdaddr_t *address, uint8_t channel)
{
	int sk;
	struct sockaddr_rc addr;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM | SOCK_NONBLOCK, BTPROTO_RFCOMM);

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	addr.rc_channel = channel;
	bacpy(&addr.rc_bdaddr, address);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	return sk;
}

static int connect_rfcomm_sock(int sk, const bdaddr_t *bdaddr, uint8_t channel)
{
	struct sockaddr_rc addr;
	int err;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, bdaddr);
	addr.rc_channel = htobs(channel);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS))
		return err;

	return 0;
}

static bool client_received_data(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct rfcomm_client_data *cli = data->test_data;
	int sk;
	ssize_t ret;
	char buf[248];

	sk = l_io_get_fd(io);

	ret = read(sk, buf, cli->data_len);
	if (cli->data_len != ret) {
		l_tester_test_failed(tester);
		return false;
	}

	if (memcmp(cli->read_data, buf, cli->data_len))
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);

	return false;
}

static void rc_disconnect_cb(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct rfcomm_client_data *cli = data->test_data;
	socklen_t len = sizeof(int);
	int sk, err, sk_err;

	bttester_print("Disconnected");

	sk = l_io_get_fd(io);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	if (cli->expected_connect_err && err == cli->expected_connect_err)
		l_tester_test_passed(tester);
	else
		l_tester_test_failed(tester);
}

static bool rc_connect_cb(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct rfcomm_client_data *cli = data->test_data;
	socklen_t len = sizeof(int);
	int sk, err, sk_err;

	bttester_print("Connected");

	sk = l_io_get_fd(io);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	if (cli->expected_connect_err && err == cli->expected_connect_err) {
		l_tester_test_passed(tester);
		return false;
	}

	if (cli->send_data) {
		ssize_t ret;

		bttester_print("Writing %u bytes of data", cli->data_len);

		ret = write(sk, cli->send_data, cli->data_len);
		if (cli->data_len != ret) {
			bttester_warn("Failed to write %u bytes: %s (%d)",
					cli->data_len, strerror(errno), errno);
			l_tester_test_failed(tester);
		}

		return false;
	} else if (cli->read_data) {
		l_io_set_read_handler(io, client_received_data, NULL, NULL);
		bthost_send_rfcomm_data(hciemu_client_get_host(data->hciemu),
						data->conn_handle,
						cli->client_channel,
						cli->read_data, cli->data_len);
		return false;
	}

	if (err < 0)
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);

	return false;
}

static void client_hook_func(const void *data, uint16_t len,
							void *user_data)
{
	struct test_data *test_data = l_tester_get_data(tester);
	const struct rfcomm_client_data *cli = test_data->test_data;
	ssize_t ret;

	bttester_print("bthost received %u bytes of data", len);

	if (cli->data_len != len) {
		l_tester_test_failed(tester);
		return;
	}

	ret = memcmp(cli->send_data, data, len);
	if (ret)
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);
}

static void server_hook_func(const void *data, uint16_t len,
							void *user_data)
{
	struct test_data *test_data = l_tester_get_data(tester);
	const struct rfcomm_server_data *srv = test_data->test_data;
	ssize_t ret;

	if (srv->data_len != len) {
		l_tester_test_failed(tester);
		return;
	}

	ret = memcmp(srv->send_data, data, len);
	if (ret)
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);
}

static void rfcomm_connect_cb(uint16_t handle, uint16_t cid,
						void *user_data, bool status)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct rfcomm_client_data *cli = data->test_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	if (cli->send_data)
		bthost_add_rfcomm_chan_hook(bthost, handle,
						cli->client_channel,
						client_hook_func, NULL);
	else if (cli->read_data)
		data->conn_handle = handle;
}

static void test_connect(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	const struct rfcomm_client_data *cli = data->test_data;
	const uint8_t *client_addr, *master_addr;
	int sk;

	bthost_add_l2cap_server(bthost, 0x0003, NULL, NULL, NULL);
	bthost_add_rfcomm_server(bthost, cli->server_channel,
						rfcomm_connect_cb, NULL);

	master_addr = hciemu_get_master_bdaddr(data->hciemu);
	client_addr = hciemu_get_client_bdaddr(data->hciemu);

	sk = create_rfcomm_sock((bdaddr_t *) master_addr, 0);

	if (connect_rfcomm_sock(sk, (const bdaddr_t *) client_addr,
					cli->client_channel) < 0) {
		close(sk);
		l_tester_test_failed(tester);
		return;
	}

	data->io = l_io_new(sk);
	l_io_set_close_on_destroy(data->io, true);
	l_io_set_disconnect_handler(data->io, rc_disconnect_cb, NULL, NULL);

	if (!l_io_set_write_handler(data->io, rc_connect_cb, NULL, NULL)) {
		l_tester_test_failed(tester);
		return;
	}

	bttester_print("Connect in progress %d", sk);
}

static bool server_received_data(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct rfcomm_server_data *srv = data->test_data;
	char buf[1024];
	ssize_t ret;
	int sk;

	sk = l_io_get_fd(io);

	ret = read(sk, buf, srv->data_len);
	if (ret != srv->data_len) {
		l_tester_test_failed(tester);
		return false;
	}

	if (memcmp(buf, srv->read_data, srv->data_len))
		l_tester_test_failed(tester);
	else
		l_tester_test_passed(tester);

	return false;
}

static bool rfcomm_listen_cb(struct l_io *io, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct rfcomm_server_data *srv = data->test_data;
	int sk, new_sk;


	sk = l_io_get_fd(io);

	new_sk = accept(sk, NULL, NULL);
	if (new_sk < 0) {
		l_tester_test_failed(tester);
		return false;
	}

	if (srv->send_data) {
		ssize_t ret;

		ret = write(new_sk, srv->send_data, srv->data_len);
		if (ret != srv->data_len)
			l_tester_test_failed(tester);

		close(new_sk);
		return false;
	} else if (srv->read_data) {
		struct l_io *new_io;

		new_io = l_io_new(new_sk);
		l_io_set_close_on_destroy(new_io, true);
		l_io_set_read_handler(new_io, server_received_data, NULL, NULL);

		return false;
	}

	close(new_sk);

	l_tester_test_passed(tester);

	return false;
}

static void connection_cb(uint16_t handle, uint16_t cid, void *user_data,
								bool status)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct rfcomm_server_data *srv = data->test_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	if (srv->read_data) {
		data->conn_handle = handle;
		bthost_send_rfcomm_data(bthost, data->conn_handle,
						srv->client_channel,
						srv->read_data, srv->data_len);
		return;
	} else if (srv->data_len) {
		return;
	}

	if (srv->expected_status == status)
		l_tester_test_passed(tester);
	else
		l_tester_test_failed(tester);
}

static void client_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct rfcomm_server_data *srv = data->test_data;
	struct bthost *bthost;

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_add_rfcomm_chan_hook(bthost, handle, srv->client_channel,
						server_hook_func, NULL);
	bthost_connect_rfcomm(bthost, handle, srv->client_channel,
						connection_cb, NULL);
}

static void test_server(const void *test_data)
{
	struct test_data *data = l_tester_get_data(tester);
	const struct rfcomm_server_data *srv = data->test_data;
	const uint8_t *master_addr;
	struct bthost *bthost;
	int sk;

	master_addr = hciemu_get_master_bdaddr(data->hciemu);

	sk = create_rfcomm_sock((bdaddr_t *) master_addr, srv->server_channel);
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

	l_io_set_read_handler(data->io, rfcomm_listen_cb, NULL, NULL);

	bttester_print("Listening for connections");

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_connect_cb(bthost, client_new_conn, data);

	bthost_hci_connect(bthost, master_addr, BDADDR_BREDR);
}

#define test_rfcomm(name, data, setup, func) \
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

	test_rfcomm("Basic RFCOMM Socket - Success", NULL,
					setup_powered_client, test_basic);
	test_rfcomm("Basic RFCOMM Socket Client - Success", &connect_success,
					setup_powered_client, test_connect);
	test_rfcomm("Basic RFCOMM Socket Client - Write Success",
				&connect_send_success, setup_powered_client,
				test_connect);
	test_rfcomm("Basic RFCOMM Socket Client - Read Success",
				&connect_read_success, setup_powered_client,
				test_connect);
	test_rfcomm("Basic RFCOMM Socket Client - Conn Refused",
			&connect_nval, setup_powered_client, test_connect);
	test_rfcomm("Basic RFCOMM Socket Server - Success", &listen_success,
					setup_powered_server, test_server);
	test_rfcomm("Basic RFCOMM Socket Server - Write Success",
				&listen_send_success, setup_powered_server,
				test_server);
	test_rfcomm("Basic RFCOMM Socket Server - Read Success",
				&listen_read_success, setup_powered_server,
				test_server);
	test_rfcomm("Basic RFCOMM Socket Server - Conn Refused", &listen_nval,
					setup_powered_server, test_server);

	return bttester_run();
}
