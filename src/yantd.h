/*
 * Author: Joe Roback <openwrt@roback.cc>
 * Homepage: http://roback.cc/
 * Github: http://github.com/joeroback/
 *
 * Simple Network Traffic Monitor for OpenWrt
 *
 * yantd is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * yantd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef __YANTD_H__
#define __YANTD_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifndef NDEBUG
# define dprintf(fmt, ...) do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
# define dprintf(fmt, ...) ((void) 0)
#endif

#define fatalsys(msg) do { \
	fprintf(stderr, "%s (line %d): %s\n", msg, __LINE__, strerror(errno)); \
	exit(EXIT_FAILURE); \
} while (0)

#define fatalusr(cause, msg) do { \
	fprintf(stderr, "%s (line %d): %s\n", cause, __LINE__, msg); \
	exit(EXIT_FAILURE); \
} while (0)

struct yantdhdr {
	uint16_t year;
	uint8_t month;
} __attribute__((__packed__));

struct yantddatum {
	uint64_t rx;
	uint64_t tx;
} __attribute__((__packed__));

#endif
