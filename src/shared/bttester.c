// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>

#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"

#include "src/shared/util.h"
#include "src/shared/bttester.h"
#include "src/shared/log.h"

#define COLOR_WHITE    "\x1B[0;37m"
#define COLOR_OFF      "\x1B[0m"

static char *tester_name;

static bool option_quiet;
static bool option_debug;
static bool option_monitor;
static bool option_list;
static const char *option_prefix;
static const char *option_string;

struct l_tester *tester;

struct monitor_hdr {
	uint16_t opcode;
	uint16_t index;
	uint16_t len;
	uint8_t  priority;
	uint8_t  ident_len;
} __attribute__((packed));

struct monitor_l2cap_hdr {
	uint16_t cid;
	uint16_t psm;
} __attribute__((packed));

static void tester_vprintf(const char *format, va_list ap)
{
	if (bttester_use_quiet())
		return;

	printf("  %s", COLOR_WHITE);
	vprintf(format, ap);
	printf("%s\n", COLOR_OFF);
}

void bttester_print(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	tester_vprintf(format, ap);
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_INFO, format, ap);
	va_end(ap);
}

void bttester_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	tester_vprintf(format, ap);
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_DEBUG, format, ap);
	va_end(ap);
}

void bttester_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	tester_vprintf(format, ap);
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_WARNING, format, ap);
	va_end(ap);
}

static void monitor_debug(const char *str, void *user_data)
{
	const char *label = user_data;

	bttester_debug("%s: %s", label, str);
}

static void monitor_log(char dir, uint16_t cid, uint16_t psm, const void *data,
								size_t len)
{
	struct iovec iov[3];
	struct monitor_l2cap_hdr hdr;
	uint8_t term = 0x00;
	char label[16];

	if (snprintf(label, sizeof(label), "%c %s", dir, tester_name) < 0)
		return;

	hdr.cid = cpu_to_le16(cid);
	hdr.psm = cpu_to_le16(psm);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);

	iov[1].iov_base = (void *) data;
	iov[1].iov_len = len;

	/* Kernel won't forward if data is no NULL terminated */
	iov[2].iov_base = &term;
	iov[2].iov_len = sizeof(term);

	bt_log_sendmsg(HCI_DEV_NONE, label, LOG_INFO, iov, 3);
}

void bttester_monitor(char dir, uint16_t cid, uint16_t psm, const void *data,
								size_t len)
{
	monitor_log(dir, cid, psm, data, len);

	if (!bttester_use_debug())
		return;

	util_hexdump(dir, data, len, monitor_debug, (void *) tester_name);
}

bool bttester_use_quiet(void)
{
	return option_quiet;
}

bool bttester_use_debug(void)
{
	return option_debug;
}

static const struct option options[] = {
	{ "version",	no_argument,		NULL, 'v' },
	{ "quiet",	no_argument,		NULL, 'q' },
	{ "monitor",	no_argument,		NULL, 'm' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "list",	no_argument,		NULL, 'l' },
	{ "prefix",	required_argument,	NULL, 'p' },
	{ "string",	required_argument,	NULL, 's' },
	{ }
};

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"\%s [options]\n", tester_name);
	fprintf(stderr,
		"Options:\n"
		"\t-v, --version Show version information and exit\n"
		"\t-q, --quiet   Run tests without logging\n"
		"\t-d, --debug   Run tests with debug output\n"
		"\t-d, --monitor Enable monitor output\n"
		"\t-l, --list	 Only list the tests to be run\n"
		"\t-p, --prefix	 Run tests matching the provided prefix\n"
		"\t-s, --string	 Run tests matching the provided string\n");
}

static void parse_options(int *argc, char ***argv)
{
	tester_name = strrchr(*argv[0], '/');

	for (;;) {
		int opt;

		opt = getopt_long(*argc, *argv, "s:p:dvlm", options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'v':
			printf("%s\n", VERSION);
			exit(EXIT_SUCCESS);
		case 'd':
			option_debug = true;
			break;
		case 'l':
			option_list = true;
			break;
		case 'm':
			option_monitor = true;
			break;
		case 'p':
			option_prefix = optarg;
			break;
		case 's':
			option_string = optarg;
			break;
		default:
			usage();
			exit(0);
		}
	}
}

static bool terminated;

static void signal_callback(unsigned int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		if (!terminated)
			l_main_quit();

		terminated = true;
		break;
	}
}

static void done_callback(struct l_tester *tester)
{
	if (terminated)
		return;

	l_main_quit();
	terminated = true;
}

struct l_tester *bttester_init(int *argc, char ***argv)
{
	l_log_set_stderr();

	l_main_init();

	tester_name = strrchr(*argv[0], '/');
	parse_options(argc, argv);

	tester = l_tester_new(option_prefix, option_string, option_list);

	return tester;
}

int bttester_run(void)
{
	int status = EXIT_SUCCESS;

	l_tester_start(tester, done_callback);

	if (!option_list && !terminated)
		l_main_run_with_signal(signal_callback, NULL);

	if (!option_list && !l_tester_summarize(tester))
		status = EXIT_FAILURE;

	l_tester_destroy(tester);

	return status;
}
