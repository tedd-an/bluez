// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014, 2021  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>

#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"

#include "monitor/bt.h"
#include "emulator/btdev.h"
#include "emulator/bthost.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "emulator/hciemu.h"

struct hciemu_client {
	struct bthost *host;
	struct btdev *dev;
	struct l_idle *start_idle;
	struct l_io *host_io;
	struct l_io *io;
};

struct hciemu {
	int ref_count;
	enum btdev_type btdev_type;
	struct btdev *dev;
	struct l_queue *clients;
	struct l_io *io;
	struct l_queue *post_command_hooks;
	char bdaddr_str[18];

	hciemu_debug_func_t debug_callback;
	hciemu_destroy_func_t debug_destroy;
	void *debug_data;
};

struct hciemu_command_hook {
	hciemu_command_func_t function;
	void *user_data;
};

static void destroy_command_hook(void *data)
{
	struct hciemu_command_hook *hook = data;

	l_free(hook);
}

struct run_data {
	uint16_t opcode;
	const void *data;
	uint8_t len;
};

static void run_command_hook(void *data, void *user_data)
{
	struct hciemu_command_hook *hook = data;
	struct run_data *run_data = user_data;

	if (hook->function)
		hook->function(run_data->opcode, run_data->data,
					run_data->len, hook->user_data);
}

static void master_command_callback(uint16_t opcode,
				const void *data, uint8_t len,
				btdev_callback callback, void *user_data)
{
	struct hciemu *hciemu = user_data;
	struct run_data run_data = { .opcode = opcode,
						.data = data, .len = len };

	btdev_command_default(callback);

	l_queue_foreach(hciemu->post_command_hooks, run_command_hook,
								&run_data);
}

static void client_command_callback(uint16_t opcode,
				const void *data, uint8_t len,
				btdev_callback callback, void *user_data)
{
	btdev_command_default(callback);
}

static void writev_callback(const struct iovec *iov, int iovlen,
								void *user_data)
{
	struct l_io *io = user_data;
	ssize_t written;
	int fd;

	fd = l_io_get_fd(io);

	written = writev(fd, iov, iovlen);
	if (written < 0)
		return;
}

static bool receive_bthost(struct l_io *io, void *user_data)
{
	struct bthost *bthost = user_data;
	unsigned char buf[4096];
	ssize_t len;
	int fd;

	fd = l_io_get_fd(io);

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return false;

	bthost_receive_h4(bthost, buf, len);

	return true;
}

static struct l_io *create_io_bthost(int fd, struct bthost *bthost)
{
	struct l_io *io;

	io = l_io_new(fd);

	l_io_set_close_on_destroy(io, true);

	bthost_set_send_handler(bthost, writev_callback, io);

	l_io_set_read_handler(io, receive_bthost, bthost, NULL);

	return io;
}

static bool receive_btdev(struct l_io *io, void *user_data)
{
	struct btdev *btdev = user_data;
	unsigned char buf[4096];
	ssize_t len;
	int fd;

	fd = l_io_get_fd(io);

	len = read(fd, buf, sizeof(buf));
	if (len < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return true;

		return false;
	}

	if (len < 1)
		return false;

	switch (buf[0]) {
	case BT_H4_CMD_PKT:
	case BT_H4_ACL_PKT:
	case BT_H4_SCO_PKT:
		btdev_receive_h4(btdev, buf, len);
		break;
	}

	return true;
}

static struct l_io *create_io_btdev(int fd, struct btdev *btdev)
{
	struct l_io *io;

	io = l_io_new(fd);

	l_io_set_close_on_destroy(io, true);

	btdev_set_send_handler(btdev, writev_callback, io);

	l_io_set_read_handler(io, receive_btdev, btdev, NULL);

	return io;
}

static bool create_vhci(struct hciemu *hciemu)
{
	struct btdev *btdev;
	uint8_t create_req[2];
	ssize_t written;
	int fd;

	btdev = btdev_create(hciemu->btdev_type, 0x00);
	if (!btdev)
		return false;

	btdev_set_command_handler(btdev, master_command_callback, hciemu);

	fd = open("/dev/vhci", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("Opening /dev/vhci failed");
		btdev_destroy(btdev);
		return false;
	}

	create_req[0] = HCI_VENDOR_PKT;
	create_req[1] = HCI_PRIMARY;

	written = write(fd, create_req, sizeof(create_req));
	if (written < 0) {
		close(fd);
		btdev_destroy(btdev);
		return false;
	}

	hciemu->dev = btdev;

	hciemu->io = create_io_btdev(fd, btdev);

	return true;
}

struct hciemu_client *hciemu_get_client(struct hciemu *hciemu, int num)
{
	const struct l_queue_entry *entry;

	if (!hciemu)
		return NULL;

	for (entry = l_queue_get_entries(hciemu->clients); entry;
					entry = entry->next, num--) {
		if (!num)
			return entry->data;
	}

	return NULL;
}

struct bthost *hciemu_client_host(struct hciemu_client *client)
{
	if (!client)
		return NULL;

	return client->host;
}

struct bthost *hciemu_client_get_host(struct hciemu *hciemu)
{
	struct hciemu_client *client;

	if (!hciemu)
		return NULL;

	client = hciemu_get_client(hciemu, 0);

	return hciemu_client_host(client);
}

static void start_host(struct l_idle *idle, void *user_data)
{
	struct hciemu_client *client = user_data;

	l_idle_remove(client->start_idle);

	client->start_idle = NULL;

	bthost_start(client->host);
}

static void hciemu_client_destroy(void *data)
{
	struct hciemu_client *client = data;

	if (client->start_idle)
		l_idle_remove(client->start_idle);

	l_io_destroy(client->host_io);
	l_io_destroy(client->io);

	bthost_destroy(client->host);
	btdev_destroy(client->dev);

	l_free(client);
}

static struct hciemu_client *hciemu_client_new(struct hciemu *hciemu,
							uint8_t id)
{
	struct hciemu_client *client;
	int sv[2];

	client = l_new(struct hciemu_client, 1);

	client->dev = btdev_create(hciemu->btdev_type, id++);
	if (!client->dev) {
		l_free(client);
		return NULL;
	}

	client->host = bthost_create();
	if (!client->host) {
		btdev_destroy(client->dev);
		l_free(client);
		return NULL;
	}

	btdev_set_command_handler(client->dev, client_command_callback, client);

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
								0, sv) < 0) {
		bthost_destroy(client->host);
		btdev_destroy(client->dev);
		return NULL;
	}

	client->io = create_io_btdev(sv[0], client->dev);
	client->host_io = create_io_bthost(sv[1], client->host);
	client->start_idle = l_idle_create(start_host, client, NULL);

	return client;
}

struct hciemu *hciemu_new_num(enum hciemu_type type, uint8_t num)
{

	struct hciemu *hciemu;
	int i;

	if (!num)
		return NULL;

	hciemu = l_new(struct hciemu, 1);

	switch (type) {
	case HCIEMU_TYPE_BREDRLE:
		hciemu->btdev_type = BTDEV_TYPE_BREDRLE;
		break;
	case HCIEMU_TYPE_BREDR:
		hciemu->btdev_type = BTDEV_TYPE_BREDR;
		break;
	case HCIEMU_TYPE_LE:
		hciemu->btdev_type = BTDEV_TYPE_LE;
		break;
	case HCIEMU_TYPE_LEGACY:
		hciemu->btdev_type = BTDEV_TYPE_BREDR20;
		break;
	case HCIEMU_TYPE_BREDRLE50:
		hciemu->btdev_type = BTDEV_TYPE_BREDRLE50;
		break;
	case HCIEMU_TYPE_BREDRLE52:
		hciemu->btdev_type = BTDEV_TYPE_BREDRLE52;
		break;
	default:
		return NULL;
	}

	hciemu->post_command_hooks = l_queue_new();

	if (!create_vhci(hciemu)) {
		l_queue_destroy(hciemu->post_command_hooks, NULL);
		l_free(hciemu);
		return NULL;
	}

	hciemu->clients = l_queue_new();

	for (i = 0; i < num; i++) {
		struct hciemu_client *client = hciemu_client_new(hciemu, i);

		if (!client) {
			l_queue_destroy(hciemu->clients, hciemu_client_destroy);
			break;
		}

		l_queue_push_tail(hciemu->clients, client);
	}

	return hciemu_ref(hciemu);
}

struct hciemu *hciemu_new(enum hciemu_type type)
{
	return hciemu_new_num(type, 1);
}

struct hciemu *hciemu_ref(struct hciemu *hciemu)
{
	if (!hciemu)
		return NULL;

	__sync_fetch_and_add(&hciemu->ref_count, 1);

	return hciemu;
}

void hciemu_unref(struct hciemu *hciemu)
{
	if (!hciemu)
		return;

	if (__sync_sub_and_fetch(&hciemu->ref_count, 1))
		return;

	l_queue_destroy(hciemu->post_command_hooks, destroy_command_hook);
	l_queue_destroy(hciemu->clients, hciemu_client_destroy);

	l_io_destroy(hciemu->io);
	btdev_destroy(hciemu->dev);

	l_free(hciemu);
}

static void bthost_debug(const char *str, void *user_data)
{
	struct hciemu *hciemu = user_data;

	util_debug(hciemu->debug_callback, hciemu->debug_data,
					"bthost: %s", str);
}

static void btdev_master_debug(const char *str, void *user_data)
{
	struct hciemu *hciemu = user_data;

	util_debug(hciemu->debug_callback, hciemu->debug_data,
					"btdev: %s", str);
}

static void btdev_client_debug(const char *str, void *user_data)
{
	struct hciemu *hciemu = user_data;

	util_debug(hciemu->debug_callback, hciemu->debug_data,
					"btdev[bthost]: %s", str);
}

static void hciemu_client_set_debug(void *data, void *user_data)
{
	struct hciemu_client *client = data;
	struct hciemu *hciemu = user_data;

	btdev_set_debug(client->dev, btdev_client_debug, hciemu, NULL);
	bthost_set_debug(client->host, bthost_debug, hciemu, NULL);
}

bool hciemu_set_debug(struct hciemu *hciemu, hciemu_debug_func_t callback,
			void *user_data, hciemu_destroy_func_t destroy)
{
	if (!hciemu)
		return false;

	if (hciemu->debug_destroy)
		hciemu->debug_destroy(hciemu->debug_data);

	hciemu->debug_callback = callback;
	hciemu->debug_destroy = destroy;
	hciemu->debug_data = user_data;

	btdev_set_debug(hciemu->dev, btdev_master_debug, hciemu, NULL);

	l_queue_foreach(hciemu->clients, hciemu_client_set_debug, hciemu);

	return true;
}

const char *hciemu_get_address(struct hciemu *hciemu)
{
	const uint8_t *addr;

	if (!hciemu || !hciemu->dev)
		return NULL;

	addr = btdev_get_bdaddr(hciemu->dev);
	sprintf(hciemu->bdaddr_str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
			addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
	return hciemu->bdaddr_str;
}

uint8_t *hciemu_get_features(struct hciemu *hciemu)
{
	if (!hciemu || !hciemu->dev)
		return NULL;

	return btdev_get_features(hciemu->dev);
}

const uint8_t *hciemu_get_master_bdaddr(struct hciemu *hciemu)
{
	if (!hciemu || !hciemu->dev)
		return NULL;

	return btdev_get_bdaddr(hciemu->dev);
}

const uint8_t *hciemu_client_bdaddr(struct hciemu_client *client)
{
	if (!client)
		return NULL;

	return btdev_get_bdaddr(client->dev);
}

const uint8_t *hciemu_get_client_bdaddr(struct hciemu *hciemu)
{
	struct hciemu_client *client;

	if (!hciemu)
		return NULL;

	client = hciemu_get_client(hciemu, 0);

	return hciemu_client_bdaddr(client);
}

uint8_t hciemu_get_master_scan_enable(struct hciemu *hciemu)
{
	if (!hciemu || !hciemu->dev)
		return 0;

	return btdev_get_scan_enable(hciemu->dev);
}

uint8_t hciemu_get_master_le_scan_enable(struct hciemu *hciemu)
{
	if (!hciemu || !hciemu->dev)
		return 0;

	return btdev_get_le_scan_enable(hciemu->dev);
}

void hciemu_set_master_le_states(struct hciemu *hciemu,
						const uint8_t *le_states)
{
	if (!hciemu || !hciemu->dev)
		return;

	btdev_set_le_states(hciemu->dev, le_states);
}

bool hciemu_add_master_post_command_hook(struct hciemu *hciemu,
			hciemu_command_func_t function, void *user_data)
{
	struct hciemu_command_hook *hook;

	if (!hciemu)
		return false;

	hook = l_new(struct hciemu_command_hook, 1);

	hook->function = function;
	hook->user_data = user_data;

	if (!l_queue_push_tail(hciemu->post_command_hooks, hook)) {
		l_free(hook);
		return false;
	}

	return true;
}

bool hciemu_clear_master_post_command_hooks(struct hciemu *hciemu)
{
	if (!hciemu)
		return false;

	l_queue_clear(hciemu->post_command_hooks, destroy_command_hook);
	return true;
}

int hciemu_add_hook(struct hciemu *hciemu, enum hciemu_hook_type type,
				uint16_t opcode, hciemu_hook_func_t function,
				void *user_data)
{
	enum btdev_hook_type hook_type;

	if (!hciemu)
		return -1;

	switch (type) {
	case HCIEMU_HOOK_PRE_CMD:
		hook_type = BTDEV_HOOK_PRE_CMD;
		break;
	case HCIEMU_HOOK_POST_CMD:
		hook_type = BTDEV_HOOK_POST_CMD;
		break;
	case HCIEMU_HOOK_PRE_EVT:
		hook_type = BTDEV_HOOK_PRE_EVT;
		break;
	case HCIEMU_HOOK_POST_EVT:
		hook_type = BTDEV_HOOK_POST_EVT;
		break;
	default:
		return -1;
	}

	return btdev_add_hook(hciemu->dev, hook_type, opcode, function,
								user_data);
}

bool hciemu_del_hook(struct hciemu *hciemu, enum hciemu_hook_type type,
								uint16_t opcode)
{
	enum btdev_hook_type hook_type;

	if (!hciemu)
		return false;

	switch (type) {
	case HCIEMU_HOOK_PRE_CMD:
		hook_type = BTDEV_HOOK_PRE_CMD;
		break;
	case HCIEMU_HOOK_POST_CMD:
		hook_type = BTDEV_HOOK_POST_CMD;
		break;
	case HCIEMU_HOOK_PRE_EVT:
		hook_type = BTDEV_HOOK_PRE_EVT;
		break;
	case HCIEMU_HOOK_POST_EVT:
		hook_type = BTDEV_HOOK_POST_EVT;
		break;
	default:
		return false;
	}

	return btdev_del_hook(hciemu->dev, hook_type, opcode);
}
