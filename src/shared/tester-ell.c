// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014, 2020  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "src/shared/log.h"

#define COLOR_OFF	"\x1B[0m"
#define COLOR_BLACK	"\x1B[0;30m"
#define COLOR_RED	"\x1B[0;31m"
#define COLOR_GREEN	"\x1B[0;32m"
#define COLOR_YELLOW	"\x1B[0;33m"
#define COLOR_BLUE	"\x1B[0;34m"
#define COLOR_MAGENTA	"\x1B[0;35m"
#define COLOR_CYAN	"\x1B[0;36m"
#define COLOR_WHITE	"\x1B[0;37m"
#define COLOR_HIGHLIGHT	"\x1B[1;39m"

#define print_text(color, fmt, args...) \
		tester_log(color fmt COLOR_OFF, ## args)

#define print_summary(label, color, value, fmt, args...) \
		tester_log("%-52s " color "%-10s" COLOR_OFF fmt, \
							label, value, ## args)

#define print_progress(name, color, fmt, args...) \
		tester_log(COLOR_HIGHLIGHT "%s" COLOR_OFF " - " \
				color fmt COLOR_OFF, name, ## args)

enum test_result {
	TEST_RESULT_NOT_RUN,
	TEST_RESULT_PASSED,
	TEST_RESULT_FAILED,
	TEST_RESULT_TIMED_OUT,
};

enum test_stage {
	TEST_STAGE_INVALID,
	TEST_STAGE_PRE_SETUP,
	TEST_STAGE_SETUP,
	TEST_STAGE_RUN,
	TEST_STAGE_TEARDOWN,
	TEST_STAGE_POST_TEARDOWN,
};

struct test_case {
	char *name;
	enum test_result result;
	enum test_stage stage;
	const void *test_data;
	tester_data_func_t pre_setup_func;
	tester_data_func_t setup_func;
	tester_data_func_t test_func;
	tester_data_func_t teardown_func;
	tester_data_func_t post_teardown_func;
	double start_time;
	double end_time;
	unsigned int timeout;
	struct l_timeout *run_timer;
	tester_destroy_func_t destroy;
	void *user_data;
	bool teardown;
};

static char *tester_name;

static struct l_queue *test_list;
static const struct l_queue_entry *test_entry;
static struct timeval tester_start;

static bool option_quiet;
static bool option_debug;
static bool option_monitor;
static bool option_list;
static const char *option_prefix;

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

static void test_destroy(void *data)
{
	struct test_case *test = data;

	l_timeout_remove(test->run_timer);

	if (test->destroy)
		test->destroy(test->user_data);

	l_free(test->name);
	l_free(test);
}

static void tester_vprintf(const char *format, va_list ap)
{
	if (tester_use_quiet())
		return;

	printf("  %s", COLOR_WHITE);
	vprintf(format, ap);
	printf("%s\n", COLOR_OFF);
}

static void tester_log(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	printf("\n");
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_INFO, format, ap);
	va_end(ap);
}

void tester_print(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	tester_vprintf(format, ap);
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_INFO, format, ap);
	va_end(ap);
}

void tester_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	tester_vprintf(format, ap);
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_DEBUG, format, ap);
	va_end(ap);
}

void tester_warn(const char *format, ...)
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

	tester_debug("%s: %s", label, str);
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

void tester_monitor(char dir, uint16_t cid, uint16_t psm, const void *data,
								size_t len)
{
	monitor_log(dir, cid, psm, data, len);

	if (!tester_use_debug())
		return;

	util_hexdump(dir, data, len, monitor_debug, (void *) tester_name);
}

static void default_pre_setup(const void *test_data)
{
	tester_pre_setup_complete();
}

static void default_setup(const void *test_data)
{
	tester_setup_complete();
}

static void default_teardown(const void *test_data)
{
	tester_teardown_complete();
}

static void default_post_teardown(const void *test_data)
{
	tester_post_teardown_complete();
}

void tester_add_full(const char *name, const void *test_data,
				tester_data_func_t pre_setup_func,
				tester_data_func_t setup_func,
				tester_data_func_t test_func,
				tester_data_func_t teardown_func,
				tester_data_func_t post_teardown_func,
				unsigned int timeout,
				void *user_data, tester_destroy_func_t destroy)
{
	struct test_case *test;

	if (!test_func)
		return;

	if (option_prefix && !l_str_has_prefix(name, option_prefix)) {
		if (destroy)
			destroy(user_data);
		return;
	}

	if (option_list) {
		tester_log("%s", name);
		if (destroy)
			destroy(user_data);
		return;
	}

	test = l_new(struct test_case, 1);
	test->name = l_strdup(name);
	test->result = TEST_RESULT_NOT_RUN;
	test->stage = TEST_STAGE_INVALID;

	test->test_data = test_data;

	if (pre_setup_func)
		test->pre_setup_func = pre_setup_func;
	else
		test->pre_setup_func = default_pre_setup;

	if (setup_func)
		test->setup_func = setup_func;
	else
		test->setup_func = default_setup;

	test->test_func = test_func;

	if (teardown_func)
		test->teardown_func = teardown_func;
	else
		test->teardown_func = default_teardown;

	if (post_teardown_func)
		test->post_teardown_func = post_teardown_func;
	else
		test->post_teardown_func = default_post_teardown;

	test->timeout = timeout;

	test->destroy = destroy;
	test->user_data = user_data;

	l_queue_push_tail(test_list, test);
}

void tester_add(const char *name, const void *test_data,
					tester_data_func_t setup_func,
					tester_data_func_t test_func,
					tester_data_func_t teardown_func)
{
	tester_add_full(name, test_data, NULL, setup_func, test_func,
					teardown_func, NULL, 0, NULL, NULL);
}

void *tester_get_data(void)
{
	struct test_case *test;

	if (!test_entry)
		return NULL;

	test = test_entry->data;

	return test->user_data;
}

static double get_elapsed_time(struct timeval *base)
{
	static struct timeval now, elapsed;

	gettimeofday(&now, NULL);
	timersub(&now, base, &elapsed);

	return elapsed.tv_sec + ((double) elapsed.tv_usec) / 1000000;
}

static int tester_summarize(void)
{
	unsigned int not_run = 0, passed = 0, failed = 0;
	double execution_time;
	const struct l_queue_entry *entry;

	tester_log("");
	print_text(COLOR_HIGHLIGHT, "");
	print_text(COLOR_HIGHLIGHT, "Test Summary");
	print_text(COLOR_HIGHLIGHT, "------------");

	entry = l_queue_get_entries(test_list);

	for (; entry; entry = entry->next) {
		struct test_case *test = entry->data;
		double exec_time;

		exec_time = test->end_time - test->start_time;

		switch (test->result) {
		case TEST_RESULT_NOT_RUN:
			print_summary(test->name, COLOR_YELLOW, "Not Run", "");
			not_run++;
			break;
		case TEST_RESULT_PASSED:
			print_summary(test->name, COLOR_GREEN, "Passed",
						"%8.3f seconds", exec_time);
			passed++;
			break;
		case TEST_RESULT_FAILED:
			print_summary(test->name, COLOR_RED, "Failed",
						"%8.3f seconds", exec_time);
			failed++;
			break;
		case TEST_RESULT_TIMED_OUT:
			print_summary(test->name, COLOR_RED, "Timed out",
						"%8.3f seconds", exec_time);
			failed++;
			break;
		}
	}

	tester_log("Total: %d, "
		COLOR_GREEN "Passed: %d (%.1f%%)" COLOR_OFF ", "
		COLOR_RED "Failed: %d" COLOR_OFF ", "
		COLOR_YELLOW "Not Run: %d" COLOR_OFF,
			not_run + passed + failed, passed,
			(not_run + passed + failed) ?
			(float) passed * 100 / (not_run + passed + failed) : 0,
			failed, not_run);

	execution_time = get_elapsed_time(&tester_start);
	tester_log("Overall execution time: %.3g seconds", execution_time);

	return failed;
}

static void teardown_callback(void *user_data)
{
	struct test_case *test = user_data;

	test->stage = TEST_STAGE_TEARDOWN;
	test->teardown = false;

	print_progress(test->name, COLOR_MAGENTA, "teardown");
	test->teardown_func(test->test_data);

#ifdef HAVE_VALGRIND_MEMCHECK_H
	VALGRIND_DO_ADDED_LEAK_CHECK;
#endif
}

static void test_timeout(struct l_timeout *timer, void *user_data)
{
	struct test_case *test = user_data;

	l_timeout_remove(timer);
	test->run_timer = NULL;

	test->result = TEST_RESULT_TIMED_OUT;
	print_progress(test->name, COLOR_RED, "test timed out");

	l_idle_oneshot(teardown_callback, test, NULL);
}

static void next_test_case(void)
{
	struct test_case *test;

	if (test_entry)
		test_entry = test_entry->next;
	else
		test_entry = l_queue_get_entries(test_list);

	if (!test_entry) {
		mainloop_quit();
		return;
	}

	test = test_entry->data;

	tester_log("");
	print_progress(test->name, COLOR_BLACK, "init");

	test->start_time = get_elapsed_time(&tester_start);

	if (test->timeout > 0)
		test->run_timer = l_timeout_create(test->timeout, test_timeout,
								test, NULL);

	test->stage = TEST_STAGE_PRE_SETUP;

	test->pre_setup_func(test->test_data);
}

static void setup_callback(void *user_data)
{
	struct test_case *test = user_data;

	test->stage = TEST_STAGE_SETUP;

	print_progress(test->name, COLOR_BLUE, "setup");
	test->setup_func(test->test_data);
}

static void run_callback(void *user_data)
{
	struct test_case *test = user_data;

	test->stage = TEST_STAGE_RUN;

	print_progress(test->name, COLOR_BLACK, "run");
	test->test_func(test->test_data);
}

static void done_callback(void *user_data)
{
	struct test_case *test = user_data;

	test->end_time = get_elapsed_time(&tester_start);

	print_progress(test->name, COLOR_BLACK, "done");
	next_test_case();
}

void tester_pre_setup_complete(void)
{
	struct test_case *test;

	if (!test_entry)
		return;

	test = test_entry->data;

	if (test->stage != TEST_STAGE_PRE_SETUP)
		return;

	l_idle_oneshot(setup_callback, test, NULL);
}

void tester_pre_setup_failed(void)
{
	struct test_case *test;

	if (!test_entry)
		return;

	test = test_entry->data;

	if (test->stage != TEST_STAGE_PRE_SETUP)
		return;

	print_progress(test->name, COLOR_RED, "pre setup failed");

	l_idle_oneshot(done_callback, test, NULL);
}

void tester_setup_complete(void)
{
	struct test_case *test;

	if (!test_entry)
		return;

	test = test_entry->data;

	if (test->stage != TEST_STAGE_SETUP)
		return;

	print_progress(test->name, COLOR_BLUE, "setup complete");

	l_idle_oneshot(run_callback, test, NULL);
}

void tester_setup_failed(void)
{
	struct test_case *test;

	if (!test_entry)
		return;

	test = test_entry->data;

	if (test->stage != TEST_STAGE_SETUP)
		return;

	test->stage = TEST_STAGE_POST_TEARDOWN;

	l_timeout_remove(test->run_timer);
	test->run_timer = NULL;

	print_progress(test->name, COLOR_RED, "setup failed");
	print_progress(test->name, COLOR_MAGENTA, "teardown");

	test->post_teardown_func(test->test_data);
}

static void test_result(enum test_result result)
{
	struct test_case *test;

	if (!test_entry)
		return;

	test = test_entry->data;

	if (test->stage != TEST_STAGE_RUN)
		return;

	l_timeout_remove(test->run_timer);
	test->run_timer = NULL;

	test->result = result;
	switch (result) {
	case TEST_RESULT_PASSED:
		print_progress(test->name, COLOR_GREEN, "test passed");
		break;
	case TEST_RESULT_FAILED:
		print_progress(test->name, COLOR_RED, "test failed");
		break;
	case TEST_RESULT_NOT_RUN:
		print_progress(test->name, COLOR_YELLOW, "test not run");
		break;
	case TEST_RESULT_TIMED_OUT:
		print_progress(test->name, COLOR_RED, "test timed out");
		break;
	}

	if (test->teardown)
		return;

	test->teardown = true;

	l_idle_oneshot(teardown_callback, test, NULL);
}

void tester_test_passed(void)
{
	test_result(TEST_RESULT_PASSED);
}

void tester_test_failed(void)
{
	test_result(TEST_RESULT_FAILED);
}

void tester_test_abort(void)
{
	test_result(TEST_RESULT_NOT_RUN);
}

void tester_teardown_complete(void)
{
	struct test_case *test;

	if (!test_entry)
		return;

	test = test_entry->data;

	if (test->stage != TEST_STAGE_TEARDOWN)
		return;

	test->stage = TEST_STAGE_POST_TEARDOWN;

	test->post_teardown_func(test->test_data);
}

void tester_teardown_failed(void)
{
	struct test_case *test;

	if (!test_entry)
		return;

	test = test_entry->data;

	if (test->stage != TEST_STAGE_TEARDOWN)
		return;

	test->stage = TEST_STAGE_POST_TEARDOWN;

	tester_post_teardown_failed();
}

void tester_post_teardown_complete(void)
{
	struct test_case *test;

	if (!test_entry)
		return;

	test = test_entry->data;

	if (test->stage != TEST_STAGE_POST_TEARDOWN)
		return;

	print_progress(test->name, COLOR_MAGENTA, "teardown complete");

	l_idle_oneshot(done_callback, test, NULL);
}

void tester_post_teardown_failed(void)
{
	struct test_case *test;

	if (!test_entry)
		return;

	test = test_entry->data;

	if (test->stage != TEST_STAGE_POST_TEARDOWN)
		return;

	print_progress(test->name, COLOR_RED, "teardown failed");

	l_idle_oneshot(done_callback, test, NULL);
}

static void start_tester(void *user_data)
{
	gettimeofday(&tester_start, NULL);
	next_test_case();
}

struct wait_data {
	unsigned int seconds;
	struct test_case *test;
	tester_wait_func_t func;
	void *user_data;
};

static void wait_callback(struct l_timeout *timer, void *user_data)
{
	struct wait_data *wait = user_data;
	struct test_case *test = wait->test;

	wait->seconds--;

	if (wait->seconds > 0) {
		print_progress(test->name, COLOR_BLACK, "%u seconds left",
								wait->seconds);
		return;
	}

	print_progress(test->name, COLOR_BLACK, "waiting done");

	wait->func(wait->user_data);

	free(wait);

	l_timeout_remove(timer);
}

void tester_wait(unsigned int seconds, tester_wait_func_t func,
							void *user_data)
{
	struct test_case *test;
	struct wait_data *wait;

	if (!func || seconds < 1)
		return;

	if (!test_entry)
		return;

	test = test_entry->data;

	wait = new0(struct wait_data, 1);
	wait->seconds = seconds;
	wait->test = test;
	wait->func = func;
	wait->user_data = user_data;

	l_timeout_create(1000, wait_callback, wait, NULL);

	print_progress(test->name, COLOR_BLACK, "waiting %u seconds", seconds);
}

static void signal_callback(int signum, void *user_data)
{
	static bool terminated = false;

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		if (!terminated)
			mainloop_quit();

		terminated = true;
		break;
	}
}

bool tester_use_quiet(void)
{
	return option_quiet;
}

bool tester_use_debug(void)
{
	return option_debug;
}

static const struct option options[] = {
	{ "version",	no_argument,		NULL, 'v' },
	{ "quiet",	no_argument,		NULL, 'q' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "monitor",	no_argument,		NULL, 'm' },
	{ "list",	no_argument,		NULL, 'l' },
	{ "prefix",	required_argument,	NULL, 'p' },
	{ }
};

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"\%s [options]\n", tester_name);
	fprintf(stderr,
		"Options:\n"
		"\t--version	Show version information and exit\n"
		"\t--quiet	Run tests without logging\n"
		"\t--debug	Run tests with debug output\n"
		"\t--monitor	Enable monitor output\n"
		"\t--list	Only list the tests to be run\n"
		"\t--prefix	Run tests matching provided prefix\n");
}

void tester_init(int *argc, char ***argv)
{
	tester_name = strrchr(*argv[0], '/');
	if (!tester_name)
		tester_name = strdup(*argv[0]);
	else
		tester_name = strdup(++tester_name);

	for (;;) {
		int opt;

		opt = getopt_long(*argc, *argv, "p:vqdml", options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'v':
			printf("%s\n", VERSION);
			exit(EXIT_SUCCESS);
		case 'q':
			option_quiet = true;
			break;
		case 'd':
			option_debug = true;
			break;
		case 'm':
			option_monitor = true;
			break;
		case 'l':
			option_list = true;
			break;
		case 'p':
			option_prefix = optarg;
			break;
		default:
			usage();
			exit(EXIT_SUCCESS);
		}
	}

	mainloop_init();

	test_list = l_queue_new();
}

int tester_run(void)
{
	int ret;

	if (option_list) {
		mainloop_quit();
		return EXIT_SUCCESS;
	}

	l_idle_oneshot(start_tester, NULL, NULL);

	mainloop_run_with_signal(signal_callback, NULL);

	ret = tester_summarize();

	l_queue_destroy(test_list, test_destroy);

	if (option_monitor)
		bt_log_close();

	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
