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
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include <sys/file.h>

#if defined(__linux__)
# include <byteswap.h>
# include <endian.h>

# ifndef htobe64
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define htobe64(x) bswap_64(x)
#  else
#   define htobe64(x) (x)
#  endif
# endif

# ifndef be64toh
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define be64toh(x) bswap_64(x)
#  else
#   define be64toh(x) (x)
#  endif
# endif
#elif defined(__APPLE__)
# include <libkern/OSByteOrder.h>
# define htobe64(u) OSSwapHostToBigInt64(u)
# define be64toh(u) OSSwapBigToHostInt64(u)
#endif

#ifndef NDEBUG
# define dbgf(fmt, ...) do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
# define dbgf(fmt, ...) ((void) 0)
#endif

# define yantdlog(prio, fmt, ...) do { \
	syslog(prio, fmt, ## __VA_ARGS__); \
} while (0)

#define fatalsys(msg) do { \
	syslog(LOG_ERR, "error=%s", strerror(errno)); \
	exit(EXIT_FAILURE); \
} while (0)

#define fatalusr(cause, msg) do { \
	syslog(LOG_ERR, "cause=%s, error=%s", cause, msg); \
	exit(EXIT_FAILURE); \
} while (0)

#define fatalcli(fmt, ...) do { \
	fprintf(stderr, fmt, ## __VA_ARGS__); \
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
