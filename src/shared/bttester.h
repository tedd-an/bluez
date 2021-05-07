/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014, 2021  Intel Corporation. All rights reserved.
 *
 *
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct l_tester *bttester_init(int *argc, char ***argv);
int bttester_run(void);

bool bttester_use_quiet(void);
bool bttester_use_debug(void);

void bttester_print(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
void bttester_warn(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
void bttester_debug(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
void bttester_monitor(char dir, uint16_t cid,
				uint16_t psm, const void *data, size_t len);
