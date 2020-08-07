/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <getopt.h>
#include <stdbool.h>
#include <wordexp.h>
#include <ctype.h>

#include <glib.h>

#include "lib/bluetooth.h"

#include "src/shared/mainloop.h"
#include "src/shared/io.h"
#include "src/shared/util.h"
#include "src/shared/shell.h"
#include "src/shared/btp.h"

#define DEFAULT_SOCKET_PATH	"/tmp/bt-stack-tester"

#define PROMPT_ON	COLOR_BLUE "[btpclient]" COLOR_OFF "# "

#define EVT_OPCODE_BASE	0x80

#define DEFAULT_INDEX	0x00

static char *socket_path;
static bool enable_dump;

struct client_data {
	int fd;

	/* Incoming buffer for response and event */
	uint8_t buf[512];
};

struct btpclientctl {
	int server_fd;
	struct client_data *client_data;
	bool debug_enabled;

	/* Outgoing buffer for command */
	uint8_t buf[560];
	uint16_t buf_len;
};

struct ad_data {
	uint8_t type;
	uint8_t len;
	uint8_t data[25];
};

struct advertise_data {
	int duration;
	int ad_data_len;
	uint8_t ad_data[256];
	int scan_data_len;
	uint8_t scan_data[256];
};

struct indexstr_data {
	int index;
	const char *str;
};

struct bitfield_data {
	uint32_t bit;
	const char *str;
};

struct opcode_data {
	uint8_t opcode;
	int bit;
	const char *str;

	void (*cmd_func)(const void *data, uint16_t size);
	uint16_t cmd_size;
	bool cmd_fixed;

	void (*rsp_func)(const void *data, uint16_t size);
	uint16_t rsp_size;
	bool rsp_fixed;

	void (*evt_func)(const void *data, uint16_t size);
	uint16_t evt_size;
	bool evt_fixed;
};

struct service_data {
	uint8_t id;
	int bit;
	const char *str;
	const struct opcode_data *opcode_table;
};

static struct advertise_data *advertise_data;
static struct btpclientctl *btpclientctl;
static bool client_active;
static uint8_t bt_index = DEFAULT_INDEX;

static void hexdump_print(const char *str, void *user_data)
{
	bt_shell_printf("%s%s\n", (char *) user_data, str);
}

static bool parse_argument_on_off(int argc, char *argv[], uint8_t *val)
{
	if (!strcasecmp(argv[1], "on") || !strcasecmp(argv[1], "yes"))
		*val = 1;
	else if (!strcasecmp(argv[1], "off") || !strcasecmp(argv[1], "no"))
		*val = 0;
	else
		*val = atoi(argv[1]);
	return true;
}

static bool parse_argument_list(int argc, char *argv[], uint8_t *val,
					const struct indexstr_data *table)
{
	int i;

	for (i = 0; table[i].str; i++) {
		if (strcasecmp(argv[1], table[i].str) == 0) {
			*val = table[i].index;
			return true;
		}
	}

	bt_shell_printf("Invalid arguement %s\n", argv[1]);

	return false;
}

static bool parse_argument_bitfield_list(int argc, char *argv[], uint32_t *val,
					const struct bitfield_data *table)
{
	int i;

	for (i = 0; table[i].str; i++) {
		if (strcasecmp(argv[0], table[i].str) == 0) {
			*val = table[i].bit;
			return true;
		}
	}

	bt_shell_printf("Invalid argument %s\n", argv[0]);

	return false;
}

static bool parse_argument_addr(int argc, char *argv[], uint8_t *addr_type,
							bdaddr_t *bdaddr)
{
	if (argc < 3) {
		bt_shell_printf("Invalid parameter\n");
		return false;
	}

	*addr_type = atoi(argv[1]);
	str2ba(argv[2], bdaddr);

	return true;
}

static char *argument_gen(const char *text, int state,
					const struct indexstr_data *list)
{
	static int index, len;
	const char *arg;

	if (!state) {
		index = 0;
		len = strlen(text);
	}

	while ((arg = list[index].str)) {
		index++;

		if (!strncasecmp(arg, text, len))
			return strdup(arg);
	}

	return NULL;
}

static char *argument_gen_bitfield(const char *text, int state,
					const struct bitfield_data *list)
{
	static int index, len;
	const char *arg;

	if (!state) {
		index = 0;
		len = strlen(text);
	}

	while ((arg = list[index].str)) {
		index++;

		if (!strncasecmp(arg, text, len))
			return strdup(arg);
	}

	return NULL;
}

static const struct service_data service_table[];

static const struct service_data *find_service_data(uint8_t service_id)
{
	int i;

	for (i = 0; service_table[i].str; i++) {
		if (service_table[i].id == service_id)
			return &service_table[i];
	}

	return NULL;
}

static const struct opcode_data *find_opcode_data(uint8_t opcode,
						const struct opcode_data *table)
{
	int i;

	for (i = 0; table[i].str; i++) {
		if (table[i].opcode == opcode)
			return &table[i];
	}

	return NULL;
}

static const char *get_indexstr(int val, const struct indexstr_data *table)
{
	int i;

	for (i = 0; table[i].str; i++) {
		if (val == table[i].index)
			return table[i].str;
	}

	return "Unknown";
}

static uint32_t print_bitfield(uint32_t val, const struct bitfield_data *table,
							const char *prefix)
{
	uint32_t mask = val;
	int i;

	for (i = 0; table[i].str; i++) {
		if (val & (((uint32_t) 1) << table[i].bit)) {
			bt_shell_printf("%s%s (0x%4.4x)\n", prefix,
						table[i].str, table[i].bit);
			mask &= ~(((uint32_t) 1) << table[i].bit);
		}
	}

	return mask;
}

static void print_bdaddr(const bdaddr_t *address, uint8_t address_type)
{
	char addr[18];

	ba2str(address, addr);
	if (address_type == BTP_GAP_ADDR_PUBLIC)
		bt_shell_printf("\t%s (public)\n", addr);
	else if (address_type == BTP_GAP_ADDR_RANDOM)
		bt_shell_printf("\t%s (random)\n", addr);
	else
		bt_shell_printf("\t%s (unknown)\n", addr);
}

static void null_cmd(const void *data, uint16_t size)
{
	/* Empty */
}

static void null_rsp(const void *data, uint16_t size)
{
	/* Empty */
}

static void null_evt(const void *data, uint16_t size)
{
	/* Empty */
}

static const struct indexstr_data error_table[] = {
	{ 0x01, "Faile" },
	{ 0x02, "Unknown Command" },
	{ 0x03, "Not Ready" },
	{ 0x04, "Invalid Index" },
	{ }
};

static void print_error_rsp(const void *data, uint16_t size)
{
	uint8_t reason = ((uint8_t *)data)[0];

	bt_shell_printf(COLOR_RED "\tReason: %s (%d)\n" COLOR_OFF,
				get_indexstr(reason, error_table), reason);
}

static const char *service_to_str(uint8_t service_id)
{
	int i;

	for (i = 0; service_table[i].str; i++) {
		if (service_table[i].id == service_id)
			return service_table[i].str;
	}

	return "Unknown Service ID";
}

static const char *get_supported_service(int bit)
{
	int i;

	for (i = 0; service_table[i].str; i++) {
		if (service_table[i].bit == bit)
			return service_table[i].str;
	}

	return NULL;
}

static const char *get_supported_command(const struct opcode_data *table,
									int bit)
{
	int i;

	for (i = 0; table[i].str; i++) {
		if (table[i].bit == bit)
			return table[i].str;
	}
	return NULL;
}

static void print_btp_hdr(struct btp_hdr *btp_hdr, const char *type_str,
							const char *opcode_str)
{
	bt_shell_printf("%s: %s(%d) %s(0x%02x) INDEX(0x%02x)\n", type_str,
			service_to_str(btp_hdr->service), btp_hdr->service,
			opcode_str, btp_hdr->opcode, btp_hdr->index);
}

static const struct opcode_data opcode_table_core[];

static void print_core_read_supported_commands_rsp(const void *data,
								uint16_t size)
{
	uint8_t cmds;
	const char *str;
	int i, bit;

	cmds = ((uint8_t *)data)[0];

	for (i = 1; i < (int)(sizeof(cmds) * 8); i++) {
		bit = 0;
		bit = 1 << i;
		if (cmds & bit) {
			str = get_supported_command(opcode_table_core, i);
			if (str)
				bt_shell_printf("\t%s (Bit %d)\n", str, i);
			else
				bt_shell_printf("\tUNKNOWN (Bit %d)\n", i);
		}
	}
}

static void print_core_read_supported_services_rsp(const void *data,
								uint16_t size)
{
	uint8_t services;
	const char *str;
	int i, bit;

	services = ((uint8_t *)data)[0];

	for (i = 0; i < (int)(sizeof(services) * 8); i++) {
		bit = 1 << i;
		if (services & bit) {
			str = get_supported_service(i);
			if (str)
				bt_shell_printf("\t%s (Bit %d)\n", str, i);
			else
				bt_shell_printf("\tUNKNOWN (Bit %d)\n", i);
		}
	}
}

static void print_core_register_service_cmd(const void *data, uint16_t size)
{
	const struct btp_core_register_cp *cp = data;

	bt_shell_printf("\tService ID: %s(0x%02x)\n",
			service_to_str(cp->service_id), cp->service_id);
}

static void print_core_unregister_service_cmd(const void *data, uint16_t size)
{
	const struct btp_core_unregister_cp *cp = data;

	bt_shell_printf("\tService ID: %s(0x%02x)\n",
			service_to_str(cp->service_id), cp->service_id);
}

static const struct opcode_data opcode_table_core[] = {
	{ 0x00, 0, "Error",
			null_cmd, 0, true,
			print_error_rsp, 1, true },
	{ 0x01, 1, "Read Supported Commands",
			null_cmd, 0, true,
			print_core_read_supported_commands_rsp, 1, true },
	{ 0x02, 2, "Read Supported Services",
			null_cmd, 0, true,
			print_core_read_supported_services_rsp, 1, true },
	{ 0x03, 3, "Register Service",
			print_core_register_service_cmd, 1, true,
			null_rsp, 0, true },
	{ 0x04, 4, "Unregister Service",
			print_core_unregister_service_cmd, 1, true,
			null_rsp, 0, true },
	{ 0x80, -1, "IUT Ready",
			null_cmd, 0, true,
			null_rsp, 0, true,
			null_evt, 0, true },
	{ }
};

static const struct opcode_data opcode_table_gap[];

static void print_gap_read_supported_commands_rsp(const void *data,
								uint16_t size)
{
	uint16_t cmds;
	const char *str;
	int i;

	cmds = le16_to_cpu(((uint16_t *)data)[0]);

	for (i = 1; i < (int)(sizeof(cmds) * 8); i++) {
		if (cmds & (1 << i)) {
			str = get_supported_command(opcode_table_gap, i);
			if (str)
				bt_shell_printf("\t%s (Bit %d)\n", str, i);
			else
				bt_shell_printf("\tUNKNOWN (Bit %d)\n", i);
		}
	}
}

static void print_gap_read_controller_index_list_rsp(const void *data,
								uint16_t size)
{
	const struct btp_gap_read_index_rp *list = data;
	int i;

	for (i = 0; i < list->num; i++)
		bt_shell_printf("\tIndex: %d\n", list->indexes[i]);
}

static const struct bitfield_data gap_setting_table[] = {
	{ 0, "Powered" },
	{ 1, "Connectable" },
	{ 2, "Fast Connectable" },
	{ 3, "Discoverable" },
	{ 4, "Bondable" },
	{ 5, "Link Layer Security" },
	{ 6, "Secure Simple Pairing" },
	{ 7, "BR/EDR" },
	{ 8, "High Speed" },
	{ 9, "Low Energy" },
	{ 10, "Advertising" },
	{ 11, "Secure Connection" },
	{ 12, "Debug Keys" },
	{ 13, "Privacy" },
	{ 14, "Controller Configuration" },
	{ 15, "Static Address" },
	{ }
};

static void print_gap_settings(uint32_t val, const struct bitfield_data *table,
							const char *prefix)
{
	uint32_t mask;

	mask = print_bitfield(val, table, prefix);
	if (mask)
		bt_shell_printf("%sUnknown settings (0x%4.4x)\n", prefix, mask);
}

static void print_gap_read_controller_information_rsp(const void *data,
								uint16_t size)
{
	const struct btp_gap_read_info_rp *info = data;
	char addr[18];

	ba2str(&info->address, addr);
	bt_shell_printf("\tAddress: %s\n", addr);
	bt_shell_printf("\tSupported Settings\n");
	print_gap_settings(le32_to_cpu(info->supported_settings),
						gap_setting_table, "\t\t");
	bt_shell_printf("\tCurrent Settings\n");
	print_gap_settings(le32_to_cpu(info->current_settings),
						gap_setting_table, "\t\t");
	bt_shell_printf("\tClass: 0x%02x%02x%02x\n",
				info->cod[2], info->cod[1], info->cod[0]);
	bt_shell_printf("\tShort: %s\n", info->short_name);
	bt_shell_printf("\tName: %s\n", info->name);
}

static void print_gap_reset_rsp(const void *data, uint16_t size)
{
	const struct btp_gap_reset_rp *rp = data;

	print_gap_settings(le32_to_cpu(rp->current_settings),
						gap_setting_table, "\t");
}

static const struct indexstr_data on_off_table[] = {
	{ 0x00, "Off" },
	{ 0x01, "On" },
	{ }
};

static void print_gap_set_powered_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_set_powered_cp *cp = data;

	bt_shell_printf("\tSet Power: %s (%d)\n",
				get_indexstr(cp->powered, on_off_table),
				cp->powered);
}

static void print_gap_set_powered_rsp(const void *data, uint16_t size)
{
	const struct btp_gap_set_powered_rp *rp = data;

	print_gap_settings(le32_to_cpu(rp->current_settings),
						gap_setting_table, "\t");
}

static void print_gap_set_connectable_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_set_connectable_cp *cp = data;

	bt_shell_printf("\t Set Connectable: %s (%d)\n",
				get_indexstr(cp->connectable, on_off_table),
				cp->connectable);
}

static void print_gap_set_connectable_rsp(const void *data, uint16_t size)
{
	const struct btp_gap_set_connectable_rp *rp = data;

	print_gap_settings(le32_to_cpu(rp->current_settings),
						gap_setting_table, "\t");
}

static void print_gap_set_fast_connectable_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_set_fast_connectable_cp *cp = data;

	bt_shell_printf("\t Set Fast Connectable: %s (%d)\n",
			get_indexstr(cp->fast_connectable, on_off_table),
			cp->fast_connectable);
}

static void print_gap_set_fast_connectable_rsp(const void *data, uint16_t size)
{
	const struct btp_gap_set_fast_connectable_rp *rp = data;

	print_gap_settings(le32_to_cpu(rp->current_settings),
						gap_setting_table, "\t");
}

static const struct indexstr_data gap_discoverable_table[] = {
	{ 0x00, "Off" },
	{ 0x01, "On" },
	{ 0x02, "Limited" },
	{ }
};

static void print_gap_set_discoverable_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_set_discoverable_cp *cp = data;

	bt_shell_printf("\t Set Discoverable: %s (%d)\n",
			get_indexstr(cp->discoverable, gap_discoverable_table),
				cp->discoverable);
}

static void print_gap_set_discoverable_rsp(const void *data, uint16_t size)
{
	const struct btp_gap_set_discoverable_rp *rp = data;

	print_gap_settings(le32_to_cpu(rp->current_settings),
						gap_setting_table, "\t");
}

static void print_gap_set_bondable_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_set_bondable_cp *cp = data;

	bt_shell_printf("\t Set Bondable: %s (%d)\n",
				get_indexstr(cp->bondable, on_off_table),
				cp->bondable);
}

static void print_gap_set_bondable_rsp(const void *data, uint16_t size)
{
	const struct btp_gap_set_bondable_rp *rp = data;

	print_gap_settings(le32_to_cpu(rp->current_settings),
						gap_setting_table, "\t");
}

static void print_adv_data(const uint8_t *data, uint8_t len, const char *prefix)
{
	struct ad_data *ad;
	const uint8_t *ptr = data;
	int count = len;
	char str[96];
	int i, j;

	while (count > 0) {
		ad = (struct ad_data *)ptr;

		bt_shell_printf("%sData:\n", prefix);
		bt_shell_printf("%s\tType: 0x%02x (%d)\n", prefix, ad->type,
								ad->len);
		count -= 2;

		for (i = 0, j = 0; i < ad->len; i++) {
			j += sprintf(str + j, "%02x ", ad->data[i]);
			if ((i % 16) == 15) {
				str[j] = '\0';
				bt_shell_printf("%s\t%s\n", prefix, str);
				j = 0;
			}
		}
		str[j] = '\0';
		bt_shell_printf("%s\t%s\n", prefix, str);

		count -= ad->len;
	}
}

static void print_gap_start_advertising_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_start_adv_cp *cp = data;

	if (cp->adv_data_len) {
		bt_shell_printf("\tAdvertising Data:\n");
		print_adv_data(cp->data, cp->adv_data_len, "\t\t");
	}

	if (cp->scan_rsp_len) {
		bt_shell_printf("\tScan Response Data:\n");
		print_adv_data(cp->data + cp->adv_data_len, cp->scan_rsp_len,
								"\t\t");
	}
}

static void print_gap_start_advertising_rsp(const void *data, uint16_t size)
{
	const struct btp_gap_start_adv_rp *rp = data;

	print_gap_settings(le32_to_cpu(rp->current_settings),
						gap_setting_table, "\t");
}

static void print_gap_stop_advertising_rsp(const void *data, uint16_t size)
{
	const struct btp_gap_start_adv_rp *rp = data;

	print_gap_settings(le32_to_cpu(rp->current_settings),
						gap_setting_table, "\t");
}

static const struct bitfield_data gap_discovery_flags_table[] = {
	{ 0, "LE" },
	{ 1, "BREDE" },
	{ 2, "Limited" },
	{ 3, "Active" },
	{ 4, "Observation" },
	{ }
};

static void print_gap_start_discovery_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_start_discovery_cp *cp = data;
	uint32_t mask;

	mask = print_bitfield(le32_to_cpu(cp->flags),
					gap_discovery_flags_table, "\t\t");
	if (mask)
		bt_shell_printf("\t\tUnknown flags (0x%4.4x)\n", mask);
}

static void print_gap_connect_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_connect_cp *cp = data;

	print_bdaddr(&cp->address, cp->address_type);
}

static void print_gap_disconnect_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_disconnect_cp *cp = data;

	print_bdaddr(&cp->address, cp->address_type);
}

static const struct indexstr_data gap_io_capa_table[] = {
	{ 0x00, "DisplayOnly" },
	{ 0x01, "DisplayYesNo" },
	{ 0x02, "KeyboardOnly" },
	{ 0x03, "NoInputOutput" },
	{ 0x04, "KeyboardDisplay" },
	{ }
};

static void print_gap_set_io_capa_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_set_io_capa_cp *cp = data;

	bt_shell_printf("\tIO Capa: %s (%d)\n",
			get_indexstr(cp->capa, gap_io_capa_table), cp->capa);
}

static void print_gap_pair_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_pair_cp *cp = data;

	print_bdaddr(&cp->address, cp->address_type);
}

static void print_gap_unpair_cmd(const void *data, uint16_t size)
{
	const struct btp_gap_unpair_cp *cp = data;

	print_bdaddr(&cp->address, cp->address_type);
}

static void print_gap_passkey_entry_response_cmd(const void *data,
								uint16_t size)
{
	const struct btp_gap_passkey_entry_rsp_cp *cp = data;

	print_bdaddr(&cp->address, cp->address_type);
	bt_shell_printf("\tPasskey: %d\n", le32_to_cpu(cp->passkey));
}

static void print_gap_passkey_confirmation_response_cmd(const void *data,
								uint16_t size)
{
	const struct btp_gap_passkey_confirm_rsp_cp *cp = data;

	print_bdaddr(&cp->address, cp->address_type);
	bt_shell_printf("\tMatch: %d\n", cp->match);
}

static void print_gap_new_settings_evt(const void *data, uint16_t size)
{
	const struct btp_new_settings_ev *ev = data;

	print_gap_settings(le32_to_cpu(ev->current_settings),
						gap_setting_table, "\t");
}

static void print_gap_eir(const uint8_t *eir, uint16_t eir_len,
							const char *prefix)
{
	char str[64];
	int i, n;

	if (eir_len == 0) {
		bt_shell_printf("%sEIR Data: Empty\n", prefix);
		return;
	}

	bt_shell_printf("%sEIR Data:\n", prefix);
	for (i = 0, n = 0; i < eir_len; i++) {
		n += sprintf(str + n, "%02x ", eir[i]);
		if ((i % 16) == 15) {
			str[n] = '\0';
			bt_shell_printf("\t%s%s\n", prefix, str);
			n = 0;
		}
	}
}

static const struct bitfield_data gap_device_found_flags_table[] = {
	{ 0, "RSSI Valid" },
	{ 1, "Adv_Data Included" },
	{ 2, "Scan_Rsp Included" },
	{ }
};

static void print_gap_device_found_evt(const void *data, uint16_t size)
{
	const struct btp_device_found_ev *ev = data;

	print_bdaddr(&ev->address, ev->address_type);
	bt_shell_printf("\tRSSI: %d\n", ev->rssi);
	bt_shell_printf("\tFlags:\n");
	print_bitfield(ev->flags, gap_device_found_flags_table, "\t\t");
	print_gap_eir(ev->eir, ev->eir_len, "\t");
}

static void print_gap_device_connected_evt(const void *data, uint16_t size)
{
	const struct btp_gap_device_connected_ev *ev = data;

	print_bdaddr(&ev->address, ev->address_type);
}

static void print_gap_device_disconnected_evt(const void *data, uint16_t size)
{
	const struct btp_gap_device_disconnected_ev *ev = data;

	print_bdaddr(&ev->address, ev->address_type);
}

static void print_gap_passkey_display_evt(const void *data, uint16_t size)
{
	const struct btp_gap_passkey_display_ev *ev = data;

	print_bdaddr(&ev->address, ev->address_type);
	bt_shell_printf("\tPasskey: %d\n", le32_to_cpu(ev->passkey));
}

static void print_gap_passkey_enter_request_evt(const void *data, uint16_t size)
{
	const struct btp_gap_passkey_req_ev *ev = data;

	print_bdaddr(&ev->address, ev->address_type);
}

static void print_gap_passkey_confirm_request_evt(const void *data,
								uint16_t size)
{
	const struct btp_gap_passkey_confirm_ev *ev = data;

	print_bdaddr(&ev->address, ev->address_type);
	bt_shell_printf("\tPasskey: %d\n", le32_to_cpu(ev->passkey));
}

static void print_gap_identity_resolved_evt(const void *data, uint16_t size)
{
	const struct btp_gap_identity_resolved_ev *ev = data;

	print_bdaddr(&ev->address, ev->address_type);
	bt_shell_printf("\tIdentity: ");
	print_bdaddr(&ev->identity_address, ev->identity_address_type);
}


static const struct opcode_data opcode_table_gap[] = {
	{ 0x00, 0, "Error",
			null_cmd, 0, true,
			print_error_rsp, 1, true },
	{ 0x01, 1, "Read Supported Commands",
			null_cmd, 0, true,
			print_gap_read_supported_commands_rsp, 2, true },
	{ 0x02, 2, "Read Controller Index List",
			null_cmd, 0, true,
			print_gap_read_controller_index_list_rsp, 2, false },
	{ 0x03, 3, "Read Controller Information",
			null_cmd, 0, true,
			print_gap_read_controller_information_rsp, 277, true },
	{ 0x04, 4, "Reset",
			null_cmd, 0, true,
			print_gap_reset_rsp, 4, true },
	{ 0x05, 5, "Set Powered",
			print_gap_set_powered_cmd, 1, true,
			print_gap_set_powered_rsp, 4, true },
	{ 0x06, 6, "Set Connectable",
			print_gap_set_connectable_cmd, 1, true,
			print_gap_set_connectable_rsp, 4, true },
	{ 0x07, 7, "Set Fast Connectable",
			print_gap_set_fast_connectable_cmd, 1, true,
			print_gap_set_fast_connectable_rsp, 4, true },
	{ 0x08, 8, "Set Discoverable",
			print_gap_set_discoverable_cmd, 1, true,
			print_gap_set_discoverable_rsp, 4, true },
	{ 0x09, 9, "Set Bondable",
			print_gap_set_bondable_cmd, 1, true,
			print_gap_set_bondable_rsp, 4, true },
	{ 0x0a, 10, "Starting Advertising",
			print_gap_start_advertising_cmd, 2, false,
			print_gap_start_advertising_rsp, 4, true },
	{ 0x0b, 11, "Stop Advertising",
			null_cmd, 0, true,
			print_gap_stop_advertising_rsp, 4, true },
	{ 0x0c, 12, "Start Discovery",
			print_gap_start_discovery_cmd, 1, true,
			null_rsp, 0, true },
	{ 0x0d, 13, "Stop Discovery",
			null_cmd, 0, true,
			null_rsp, 0, true },
	{ 0x0e, 14, "Connect",
			print_gap_connect_cmd, 7, true,
			null_rsp, 0, true },
	{ 0x0f, 15, "Disconnect",
			print_gap_disconnect_cmd, 7, true,
			null_rsp, 0, true },
	{ 0x10, 16, "Set I/O Capability",
			print_gap_set_io_capa_cmd, 1, true,
			null_rsp, 0, true },
	{ 0x11, 17, "Pair",
			print_gap_pair_cmd, 7, true,
			null_rsp, 0, true },
	{ 0x12, 18, "Unpair",
			print_gap_unpair_cmd, 7, true,
			null_rsp, 0, true },
	{ 0x13, 19, "Passkey Entry Response",
			print_gap_passkey_entry_response_cmd, 11, true,
			null_rsp, 0, true },
	{ 0x14, 20, "Passkey Confirmation Response",
			print_gap_passkey_confirmation_response_cmd, 8, true,
			null_rsp, 0, true },
	{ 0x80, -1, "New Settings",
			null_cmd, 0, true,
			null_rsp, 0, true,
			print_gap_new_settings_evt, 4, true },
	{ 0x81, -1, "Device Found",
			null_cmd, 0, true,
			null_rsp, 0, true,
			print_gap_device_found_evt, 11, false },
	{ 0x82, -1, "Device Connected",
			null_cmd, 0, true,
			null_rsp, 0, true,
			print_gap_device_connected_evt, 7, true },
	{ 0x83, -1, "Device Disconnected",
			null_cmd, 0, true,
			null_rsp, 0, true,
			print_gap_device_disconnected_evt, 7, true },
	{ 0x84, -1, "Passkey Display",
			null_cmd, 0, true,
			null_rsp, 0, true,
			print_gap_passkey_display_evt, 11, true },
	{ 0x85, -1, "Passkey Entry Request",
			null_cmd, 0, true,
			null_rsp, 0, true,
			print_gap_passkey_enter_request_evt, 7, true },
	{ 0x86, -1, "Passkey Confirm Request",
			null_cmd, 0, true,
			null_rsp, 0, true,
			print_gap_passkey_confirm_request_evt, 11, true },
	{ 0x87, -1, "Identity Resolved",
			null_cmd, 0, true,
			null_rsp, 0, true,
			print_gap_identity_resolved_evt, 14, true },
	{ }
};

static const struct service_data service_table[] = {
	{ 0x00, 0, "Core", opcode_table_core},
	{ 0x01, 1, "GAP", opcode_table_gap},
	{ }
};

static bool write_packet(int fd, const void *data, size_t size)
{
	while (size > 0) {
		ssize_t written;

		written = write(fd, data, size);
		if (written < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return false;
		}

		if (enable_dump)
			util_hexdump('<', data, written, hexdump_print,
								"OUT: ");

		data += written;
		size -= written;
	}

	return true;
}

static void btp_print_cmd(struct btp_hdr *btp_hdr, void *data)
{
	const struct service_data *table;
	const struct opcode_data *opcode_data;

	table = find_service_data(btp_hdr->service);
	if (!table) {
		bt_shell_printf("Unknown Service: 0x%02x\n", btp_hdr->service);
		return;
	}

	opcode_data = find_opcode_data(btp_hdr->opcode, table->opcode_table);
	if (!opcode_data) {
		bt_shell_printf("Unknown Opcode: 0x%02x\n", btp_hdr->opcode);
		return;
	}

	print_btp_hdr(btp_hdr, "CMD", opcode_data->str);

	if (opcode_data->cmd_fixed) {
		if (btp_hdr->data_len != opcode_data->cmd_size) {
			bt_shell_printf("Invalid Parameter length %d\n",
							btp_hdr->data_len);
			return;
		}
	} else {
		if (btp_hdr->data_len < opcode_data->cmd_size) {
			bt_shell_printf("Invalid Parameter length %d\n",
							btp_hdr->data_len);
			return;
		}
	}

	opcode_data->cmd_func(data, btp_hdr->data_len);
}

static void btp_print_rsp(struct btp_hdr *btp_hdr, void *data)
{
	const struct service_data *table;
	const struct opcode_data *opcode_data;

	table = find_service_data(btp_hdr->service);
	if (!table) {
		bt_shell_printf("Unknown Service: 0x%02x\n", btp_hdr->service);
		return;
	}

	opcode_data = find_opcode_data(btp_hdr->opcode, table->opcode_table);
	if (!opcode_data) {
		bt_shell_printf("Unknown Opcode: 0x%02x\n", btp_hdr->opcode);
		return;
	}

	print_btp_hdr(btp_hdr, "RSP", opcode_data->str);

	if (opcode_data->rsp_fixed) {
		if (btp_hdr->data_len != opcode_data->rsp_size) {
			bt_shell_printf("Invalid Parameter length %d\n",
							btp_hdr->data_len);
			return;
		}
	} else {
		if (btp_hdr->data_len < opcode_data->rsp_size) {
			bt_shell_printf("Invalid Parameter length %d\n",
							btp_hdr->data_len);
			return;
		}
	}

	opcode_data->rsp_func(data, btp_hdr->data_len);
}

static void btp_print_evt(struct btp_hdr *btp_hdr, void *data)
{
	const struct service_data *table;
	const struct opcode_data *opcode_data;

	table = find_service_data(btp_hdr->service);
	if (!table) {
		bt_shell_printf("Unknown Service: 0x%02x\n", btp_hdr->service);
		return;
	}

	opcode_data = find_opcode_data(btp_hdr->opcode, table->opcode_table);
	if (!opcode_data) {
		bt_shell_printf("Unknown Opcode: 0x%02x\n", btp_hdr->opcode);
		return;
	}

	print_btp_hdr(btp_hdr, "EVT", opcode_data->str);

	if (opcode_data->evt_fixed) {
		if (btp_hdr->data_len != opcode_data->evt_size) {
			bt_shell_printf("Invalid Parameter length %d\n",
							btp_hdr->data_len);
			return;
		}
	} else {
		if (btp_hdr->data_len < opcode_data->evt_size) {
			bt_shell_printf("Invalid Parameter length %d\n",
							btp_hdr->data_len);
			return;
		}
	}

	opcode_data->evt_func(data, btp_hdr->data_len);
}

static bool send_cmd(uint8_t service_id, uint8_t opcode, uint8_t index,
					uint16_t data_len, void *data)
{
	struct btp_hdr *hdr;
	int client_fd;

	if (!client_active) {
		bt_shell_printf("ERROR: Client is not active\n");
		return false;
	}

	hdr = (struct btp_hdr *)(btpclientctl->buf);

	hdr->service = service_id;
	hdr->opcode = opcode;
	hdr->index = index;
	hdr->data_len = cpu_to_le16(data_len);
	if (data)
		memcpy(hdr->data, data, data_len);

	btpclientctl->buf_len = sizeof(*hdr) + data_len;

	client_fd = btpclientctl->client_data->fd;

	btp_print_cmd(hdr, data_len ? hdr->data : NULL);

	if (!write_packet(client_fd, btpclientctl->buf,
						btpclientctl->buf_len)) {
		fprintf(stderr, "Failed to send command to client\n");
		mainloop_remove_fd(client_fd);
		return false;
	}

	return true;
}

static void client_read_destroy(void *user_data)
{
	struct client_data *client_data = user_data;

	close(client_data->fd);
	free(client_data);

	client_active = false;

	bt_shell_printf("Client is disconnected\n");
}

static void client_read_callback(int fd, uint32_t events, void *user_data)
{
	struct client_data *client_data = user_data;
	struct btp_hdr *btp_hdr;
	uint8_t *data, *ptr;
	ssize_t len, pkt_len;

	if (events & (EPOLLERR | EPOLLHUP)) {
		fprintf(stderr, "Error from client connection\n");
		mainloop_remove_fd(client_data->fd);
		return;
	}

	if (events & EPOLLRDHUP) {
		fprintf(stderr, "Remote hangeup of cliient connection\n");
		mainloop_remove_fd(client_data->fd);
		return;
	}

	/* Read incoming packet */
	len = read(client_data->fd, client_data->buf, sizeof(client_data->buf));
	if (len < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return;

		fprintf(stderr, "Read from client descriptor failed\n");
		mainloop_remove_fd(client_data->fd);
		return;
	}

	if (len < (ssize_t)sizeof(struct btp_hdr) - 1)
		return;

	ptr = client_data->buf;

	while (len) {
		btp_hdr = (struct btp_hdr *)ptr;

		pkt_len = sizeof(*btp_hdr) + btp_hdr->data_len;

		if (enable_dump)
			util_hexdump('>', ptr, pkt_len, hexdump_print, "IN : ");

		if (btp_hdr->data_len)
			data = btp_hdr->data;
		else
			data = NULL;

		if (btp_hdr->opcode < EVT_OPCODE_BASE)
			btp_print_rsp(btp_hdr, data);
		else
			btp_print_evt(btp_hdr, data);

		ptr += pkt_len;
		len -= pkt_len;
	}
}

static struct client_data *setup_client(int client_fd)
{
	struct client_data *client_data;

	client_data = new0(struct client_data, 1);
	if (!client_data)
		return NULL;

	client_data->fd = client_fd;

	mainloop_add_fd(client_data->fd, EPOLLIN | EPOLLRDHUP,
			client_read_callback, client_data, client_read_destroy);

	return client_data;
}

static void server_callback(int fd, uint32_t events, void *user_data)
{
	union {
		struct sockaddr common;
		struct sockaddr_un sun;
		struct sockaddr_in sin;
	} addr;
	socklen_t len;
	int client_fd;
	struct client_data *client_data;
	struct btpclientctl *btpclientctl = user_data;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_quit();
		return;
	}

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);

	if (getsockname(fd, &addr.common, &len) < 0) {
		perror("Failed to get socket name");
		return;
	}

	client_fd = accept(fd, &addr.common, &len);
	if (client_fd < 0) {
		perror("Failed to accept client socket");
		return;
	}

	bt_shell_printf("Client is connected\n");

	/* Setup Client */
	client_data = setup_client(client_fd);
	if (!client_data)  {
		fprintf(stderr, "Failed to setup client\n");
		close(client_fd);
		return;
	}

	btpclientctl->client_data = client_data;
	client_active = true;
}

static int open_socket(const char *path)
{
	struct sockaddr_un addr;
	size_t len;
	int fd;

	len = strlen(path);
	if (len > sizeof(addr.sun_path) - 1) {
		fprintf(stderr, "Socket path is too long\n");
		return -1;
	}

	unlink(path);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Failed to open Unix server socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Failed to bind Unix server socket");
		goto error_close;
	}

	if (listen(fd, 1) < 0) {
		perror("Failed to listen Unix server socket");
		goto error_close;
	}

	bt_shell_printf("Waiting for client connection...\n");

	if (chmod(path, 0666) < 0) {
		perror("Failed to change Unix socket file mode");
		goto error_close;
	}

	return fd;

error_close:
	close(fd);
	return -1;
}

static void cmd_ad_show(int argc, char **argv)
{
	bt_shell_printf("AD: Saved Advertise/Scan data\n");

	if (!advertise_data) {
		bt_shell_printf("\tError: Not initialized\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (advertise_data->ad_data_len) {
		bt_shell_printf("\tAD Data:\n");
		print_adv_data(advertise_data->ad_data,
					advertise_data->ad_data_len, "\t\t");
	}

	if (advertise_data->scan_data_len) {
		bt_shell_printf("\tScan Data:\n");
		print_adv_data(advertise_data->scan_data,
					advertise_data->scan_data_len, "\t\t");
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static bool ad_add_data(struct ad_data *ad_data, int argc, char *argv[])
{
	char *endptr = NULL;
	int i;
	long val;

	/* Type */
	val = strtol(argv[0], &endptr, 0);
	if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
		bt_shell_printf("Error: Invalid Type\n");
		return false;
	}
	ad_data->type = val;

	for (i = 1; i < argc; i++) {
		endptr = NULL;

		val = strtol(argv[i], &endptr, 0);
		if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
			bt_shell_printf("Error: Invalid data at %d\n", i);
			return false;
		}

		ad_data->data[ad_data->len] = val;
		ad_data->len++;
	}

	return true;
}

static void cmd_ad_add_ad(int argc, char **argv)
{
	struct ad_data ad_data;
	uint8_t *ptr;

	bt_shell_printf("AD: Save Advertise data\n");

	if (!advertise_data) {
		bt_shell_printf("\tError: Not initialized\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (argc < 2) {
		bt_shell_printf("\tInvalid Parameter Number\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	memset(&ad_data, 0, sizeof(ad_data));

	if (!ad_add_data(&ad_data, argc - 1, argv + 1))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	ptr = advertise_data->ad_data + advertise_data->ad_data_len;
	memcpy(ptr, &ad_data, ad_data.len + 2);
	advertise_data->ad_data_len += ad_data.len + 2;

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_ad_add_scan(int argc, char **argv)
{
	struct ad_data ad_data;
	uint8_t *ptr;

	bt_shell_printf("AD: Save Scan data\n");

	if (!advertise_data) {
		bt_shell_printf("\tError: Not initialized\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (argc < 2) {
		bt_shell_printf("\tInvalid Parameter Number\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!ad_add_data(&ad_data, argc - 1, argv + 1))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	ptr = advertise_data->scan_data + advertise_data->scan_data_len;
	memcpy(ptr, &ad_data, ad_data.len + 2);
	advertise_data->scan_data_len += ad_data.len + 2;

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_ad_duration(int argc, char **argv)
{
	uint32_t val;

	bt_shell_printf("AD: Set Advertising Duration\n");

	if (!advertise_data) {
		bt_shell_printf("\tError: Not initialized\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (argc > 2) {
		bt_shell_printf("\tInvalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	/* No parameter */
	if (argc == 1) {
		bt_shell_printf("\tDuration: %d\n", advertise_data->duration);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	val = (uint32_t)atoi(argv[1]);

	if (val == 0)
		val = UINT32_MAX;

	advertise_data->duration = val;

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_ad_clear(int argc, char **argv)
{
	bt_shell_printf("AD: Clear Advertise/Scan data\n");

	if (!advertise_data) {
		bt_shell_printf("\tError: Not initialized\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	advertise_data->ad_data_len = 0;
	advertise_data->scan_data_len = 0;

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_core_read_cmds(int argc, char **argv)
{
	bt_shell_printf("Core: Read Supported Commands\n");

	if (!send_cmd(BTP_CORE_SERVICE, BTP_OP_CORE_READ_SUPPORTED_COMMANDS,
					BTP_INDEX_NON_CONTROLLER, 0, NULL))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_core_read_services(int argc, char **argv)
{
	bt_shell_printf("Core: Read Supported Services\n");

	if (!send_cmd(BTP_CORE_SERVICE, BTP_OP_CORE_READ_SUPPORTED_SERVICES,
					BTP_INDEX_NON_CONTROLLER, 0, NULL))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_core_register_service(int argc, char **argv)
{
	uint8_t service_id;

	bt_shell_printf("Core: Register Service\n");

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");

		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	service_id = atoi(argv[1]);
	if (service_id == 0) {
		bt_shell_printf("CORE service is already registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!send_cmd(BTP_CORE_SERVICE, BTP_OP_CORE_REGISTER,
				BTP_INDEX_NON_CONTROLLER, 1, &service_id))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_core_unregister_service(int argc, char **argv)
{
	uint8_t service_id;

	bt_shell_printf("Core: Unregister Service\n");

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	service_id = atoi(argv[1]);
	if (service_id == 0) {
		bt_shell_printf("Cannot unregister CORE service\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!send_cmd(BTP_CORE_SERVICE, BTP_OP_CORE_UNREGISTER,
				BTP_INDEX_NON_CONTROLLER, 1, &service_id))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_set_index(int argc, char **argv)
{
	uint8_t index;

	bt_shell_printf("Set Default Controller Index\n");

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	index = atoi(argv[1]);
	if (index == bt_index) {
		bt_shell_printf("Controller index is already set\n");
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	bt_index = index;
	bt_shell_printf("Controller index is updated to 0x%02x\n", bt_index);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_read_cmds(int argc, char **argv)
{
	bt_shell_printf("GAP: Read Supported Commands\n");

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_READ_SUPPORTED_COMMANDS,
					BTP_INDEX_NON_CONTROLLER, 0, NULL))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_read_index(int argc, char **argv)
{
	bt_shell_printf("GAP: Read Controller Index List\n");

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_READ_CONTROLLER_INDEX_LIST,
					BTP_INDEX_NON_CONTROLLER, 0, NULL))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_read_info(int argc, char **argv)
{
	uint8_t index;

	bt_shell_printf("GAP: Read Controller Information\n");

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	index = atoi(argv[1]);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_READ_COTROLLER_INFO,
					index, 0, NULL))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_reset(int argc, char **argv)
{
	bt_shell_printf("GAP: Reset\n");

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_RESET, bt_index, 0, NULL))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static char *gap_on_off_gen(const char *text, int state)
{
	return argument_gen(text, state, on_off_table);
}

static void cmd_gap_power(int argc, char **argv)
{
	struct btp_gap_set_powered_cp cp;

	bt_shell_printf("GAP: Set Power\n");

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!parse_argument_on_off(argc, argv, &cp.powered))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_SET_POWERED, bt_index,
							sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_connectable(int argc, char **argv)
{
	struct btp_gap_set_connectable_cp cp;

	bt_shell_printf("GAP: Set Connectable\n");

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!parse_argument_on_off(argc, argv, &cp.connectable))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_SET_CONNECTABLE, bt_index,
							sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_fast_connectable(int argc, char **argv)
{
	struct btp_gap_set_fast_connectable_cp cp;

	bt_shell_printf("GAP: Set Fast Connectable\n");

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!parse_argument_on_off(argc, argv, &cp.fast_connectable))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_SET_FAST_CONNECTABLE,
						bt_index, sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static char *gap_discoverable_gen(const char *text, int state)
{
	return argument_gen(text, state, gap_discoverable_table);
}

static void cmd_gap_discoverable(int argc, char **argv)
{
	struct btp_gap_set_discoverable_cp cp;

	bt_shell_printf("GAP: Set Discoverable\n");

	memset(&cp, 0, sizeof(cp));

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!parse_argument_list(argc, argv, &cp.discoverable,
						gap_discoverable_table))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_SET_DISCOVERABLE,
						bt_index, sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_bondable(int argc, char **argv)
{
	struct btp_gap_set_bondable_cp cp;

	bt_shell_printf("GAP: Set Bondable\n");

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!parse_argument_on_off(argc, argv, &cp.bondable))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_SET_BONDABLE,
						bt_index, sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_start_adv(int argc, char **argv)
{
	struct btp_gap_start_adv_cp *cp;
	int total;

	bt_shell_printf("GAP: Start Advertising\n");

	/* Check if AD data is availabel */
	if (advertise_data->ad_data_len == 0 &&
					advertise_data->scan_data_len == 0) {
		bt_shell_printf("ERROR: No Advertise or Scan data available\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	/* Allocate the maximum size */
	cp = (struct btp_gap_start_adv_cp *)malloc(520);

	memset(cp, 0, 520);
	total = 2;

	if (advertise_data->ad_data_len) {
		memcpy(cp->data, advertise_data->ad_data,
						advertise_data->ad_data_len);
		cp->adv_data_len = advertise_data->ad_data_len;
	} else
		cp->adv_data_len = 0;

	total += cp->adv_data_len;

	if (advertise_data->scan_data_len) {
		memcpy(cp->data + cp->adv_data_len, advertise_data->scan_data,
						advertise_data->scan_data_len);
		cp->scan_rsp_len = advertise_data->scan_data_len;
	} else
		cp->scan_rsp_len = 0;

	total += cp->scan_rsp_len;

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_START_ADVERTISING,
							bt_index, total, cp)) {
		free(cp);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	free(cp);
	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_stop_adv(int argc, char **argv)
{
	bt_shell_printf("GAP: Stop Advertising\n");

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_STOP_ADVERTISING,
						bt_index, 0, NULL))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static char *gap_start_disc_gen(const char *text, int state)
{
	return argument_gen_bitfield(text, state, gap_discovery_flags_table);
}

static void cmd_gap_start_disc(int argc, char **argv)
{
	struct btp_gap_start_discovery_cp cp;
	int i;
	uint32_t f;

	bt_shell_printf("GAP: Start Discovery\n");

	if (argc < 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	memset(&cp, 0, sizeof(cp));

	for (i = 1; i < argc; i++) {
		if (!parse_argument_bitfield_list(argc - i, &argv[i], &f,
						gap_discovery_flags_table))
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		cp.flags |= (1 << f);
	}

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_START_DISCOVERY,
						bt_index, sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_stop_disc(int argc, char **argv)
{
	bt_shell_printf("GAP: Stop Discovery\n");

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_STOP_DISCOVERY, bt_index,
								0, NULL))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_connect(int argc, char **argv)
{
	struct btp_gap_connect_cp cp;

	bt_shell_printf("GAP: Connect\n");

	memset(&cp, 0, sizeof(cp));

	if (!parse_argument_addr(argc, argv, &cp.address_type, &cp.address))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_CONNECT,
						bt_index, sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_disconnect(int argc, char **argv)
{
	struct btp_gap_disconnect_cp cp;

	bt_shell_printf("GAP: Disconnect\n");

	memset(&cp, 0, sizeof(cp));

	if (!parse_argument_addr(argc, argv, &cp.address_type, &cp.address))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_DISCONNECT,
						bt_index, sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static char *gap_io_capa_gen(const char *text, int state)
{
	return argument_gen(text, state, gap_io_capa_table);
}

static void cmd_gap_set_io_capa(int argc, char **argv)
{
	struct btp_gap_set_io_capa_cp cp;

	bt_shell_printf("GAP: Get IO Capability\n");

	memset(&cp, 0, sizeof(cp));

	if (argc != 2) {
		bt_shell_printf("Invalid parameter\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!parse_argument_list(argc, argv, &cp.capa, gap_io_capa_table))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_SET_IO_CAPA,
						bt_index, sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_pair(int argc, char **argv)
{
	struct btp_gap_pair_cp cp;

	bt_shell_printf("GAP: Pair\n");

	memset(&cp, 0, sizeof(cp));

	if (!parse_argument_addr(argc, argv, &cp.address_type, &cp.address))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_PAIR,
						bt_index, sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_gap_unpair(int argc, char **argv)
{
	struct btp_gap_unpair_cp cp;

	bt_shell_printf("GAP: Unpair\n");

	memset(&cp, 0, sizeof(cp));

	if (!parse_argument_addr(argc, argv, &cp.address_type, &cp.address))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!send_cmd(BTP_GAP_SERVICE, BTP_OP_GAP_UNPAIR,
						bt_index, sizeof(cp), &cp))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static const struct bt_shell_menu ad_menu = {
	.name = "ad",
	.desc = "Manage Advertise DataSubmenu",
	.entries = {
	{ "show",		NULL,
		cmd_ad_show,		"Show current saved AD/Scan data" },
	{ "add-ad",		"<type> <data=xx xx ...>",
		cmd_ad_add_ad,		"Save AD data" },
	{ "add-scan",		"<type> <data=xx xx ...>",
		cmd_ad_add_scan,	"Save Scan data" },
	{ "duration",		"<duration>",
		cmd_ad_duration,	"Set duration" },
	{ "clear",		"<all/ad/scan/duration>",
		cmd_ad_clear,		"Clear saved AD/Scan/duration data" },
	{ } },
};

static const struct bt_shell_menu gap_menu = {
	.name = "gap",
	.desc = "GAP API Submenu",
	.entries = {
	{ "read-cmds",		NULL,
		cmd_gap_read_cmds,	"Show supported commands" },
	{ "list",		NULL,
		cmd_gap_read_index,	"Show index of controllers" },
	{ "read-info",		"<index>",
		cmd_gap_read_info,	"Read controller information" },
	{ "reset",		NULL,
		cmd_gap_reset,		"Reset controller and stack" },
	{ "power",		"<on/off>",
		cmd_gap_power,		"Set controller power",
					gap_on_off_gen },
	{ "connectable",	"<on/off>",
		cmd_gap_connectable,	"Set controller connectable",
					gap_on_off_gen },
	{ "fast-connectable",	"<on/off>",
		cmd_gap_fast_connectable, "Set controller fast connectable",
					gap_on_off_gen },
	{ "discoverable",	"<on/off/limited>",
		cmd_gap_discoverable,	"Set controller discoverable",
					gap_discoverable_gen },
	{ "bondable",		"<on/off>",
		cmd_gap_bondable,	"Set controller bondable",
					gap_on_off_gen },
	{ "start-adv",		NULL,
		cmd_gap_start_adv,	"Start Advertising" },
	{ "stop-adv",		NULL,
		cmd_gap_stop_adv,	"Stop Advertising" },
	{ "start-disc",		"<flags...>",
		cmd_gap_start_disc,	"Start discovery",
					gap_start_disc_gen },
	{ "stop-disc",		NULL,
		cmd_gap_stop_disc,	"Stop discovery" },
	{ "connect",		"<type> <bdaddr>",
		cmd_gap_connect,	"Connect" },
	{ "disconnect",		"<type> <bdaddr>",
		cmd_gap_disconnect,	"Disconnect" },
	{ "set-capa",		"<io capability>",
		cmd_gap_set_io_capa,	"Set IO capability",
					gap_io_capa_gen },
	{ "pair",		"<type> <bdaddr>",
		cmd_gap_pair,		"Pair" },
	{ "unpair",		"<type> <bdaddr>",
		cmd_gap_unpair,		"Unpair" },
	{ } },
};

static const struct bt_shell_menu main_menu = {
	.name = "main",
	.entries =  {
	{ "read-cmds",		NULL,
		cmd_core_read_cmds,		"Read supported commands" },
	{ "read-services",	NULL,
		cmd_core_read_services,		"Read supported services" },
	{ "register",		"<service id>",
		cmd_core_register_service,	"Register service" },
	{ "unregister",		"<service id>",
		cmd_core_unregister_service,	"Unregister service" },
	{ "index",		"<index>",
		cmd_set_index,		"Set controller index. Default is 0" },
	{ } },
};

static const struct option main_options[] = {
	{ "socket",	required_argument, 0, 's' },
	{ "dump  ",	required_argument, 0, 'd' },
	{ 0, 0, 0, 0 }
};

static const char *socket_path_option;
static const char *dump_option;

static const char **optargs[] = {
	&socket_path_option,
	&dump_option,
};

static const char *help[] = {
	"Socket path to listen for BTP client\n",
	"Use \"on\" to enable hex dump\n",
};

static const struct bt_shell_opt opt = {
	.options = main_options,
	.optno = sizeof(main_options) / sizeof(struct option),
	.optstr = "s:d:",
	.optarg = optargs,
	.help = help,
};

int main(int argc, char *argv[])
{
	int status;
	int server_fd;

	bt_shell_init(argc, argv, &opt);
	bt_shell_set_menu(&main_menu);
	bt_shell_add_submenu(&ad_menu);
	bt_shell_add_submenu(&gap_menu);

	if (socket_path_option)
		socket_path = g_strdup(socket_path_option);
	else
		socket_path = g_strdup(DEFAULT_SOCKET_PATH);

	if (dump_option && !strcasecmp(dump_option, "on"))
		enable_dump = true;
	else
		enable_dump = false;


	btpclientctl = new0(struct btpclientctl, 1);
	if (!btpclientctl) {
		status = EXIT_FAILURE;
		goto error_exit;
	}

	advertise_data = new0(struct advertise_data, 1);
	if (!advertise_data) {
		status = EXIT_FAILURE;
		goto error_free_client;
	}

	advertise_data->ad_data_len = 0;
	advertise_data->scan_data_len = 0;

	bt_shell_attach(fileno(stdin));

	server_fd = open_socket(socket_path);
	if (server_fd < 0) {
		status = EXIT_FAILURE;
		goto error_free_ad;
	}

	btpclientctl->server_fd = server_fd;

	mainloop_add_fd(btpclientctl->server_fd, EPOLLIN, server_callback,
			btpclientctl, NULL);

	bt_shell_set_prompt(PROMPT_ON);

	status = bt_shell_run();

	close(btpclientctl->server_fd);

error_free_ad:
	free(advertise_data);
error_free_client:
	free(btpclientctl);
error_exit:
	g_free(socket_path);
	return status;
}
