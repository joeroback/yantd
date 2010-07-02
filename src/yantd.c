/*
 * Author: Joe Roback <openwrt@roback.cc>
 * Homepage: http://roback.cc/
 * Github: http://github.com/joeroback/
 *
 * Simple Network Traffic Monitor for OpenWrt
 *
 * Idea from and loosely based off ttraff implementation from DD-WRT
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
 * Traffic data is stored with the following format by year/month:
 *
 *   File is named `CFG_DATA_DIR/yantd/<hostname>-<iface>-<year><month>.otf'
 *
 *   File header contains year (uint16_t) / month (uint8_t)
 *   Data is stored as uint64_t types. One for rx bytes, one for tx bytes,
 *   for each day in the month, therefore file size varies month-to-month.
 *
 */

#include <yantd.h>

#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#define PROGRAM "yantd"
#define VERSION "1.0"

static uint8_t DAYSINMONTH[12] = {
	31, /* Jan */
	29, /* Feb */
	31, /* Mar */
	30, /* Apr */
	31, /* May */
	30, /* Jun */
	31, /* Jul */
	31, /* Aug */
	30, /* Sept */
	31, /* Oct */
	30, /* Nov */
	31  /* Dec */
};

static char CFG_DATA_DIR[PATH_MAX] = { "/tmp/"PROGRAM };
static char CFG_IFACE[32] = { "eth1" };
static unsigned int CFG_INTERVAL = 5U;
static char HOSTNAME[256] = { "" };
static char FILENAME[FILENAME_MAX] = { "" };

// foreground flag
static unsigned char stayinfg = 0U;

// termination flag
static unsigned char termint = 0U;

static void usage(int status) __attribute__((noreturn));
static void catch_sigintquitterm(int signo);
void read_dev_bytes(struct yantddatum *bytes);
void write_dev_bytes(uint64_t rx_bytes, uint64_t tx_bytes);

int main(int argc, char **argv)
{
	struct yantddatum od, odp;
	int opt;
	
	// parse cmd line options
	while ((opt = getopt(argc, argv, "d:fi:t:v")) != -1)
	{
		switch (opt)
		{
			case 'd':
			{
				snprintf(CFG_DATA_DIR, sizeof(CFG_DATA_DIR),
					"%s/%s", optarg, PROGRAM);
				break;
			}
			case 'f':
			{
				stayinfg = 1;
				break;
			}
			case 'i':
			{
				snprintf(CFG_IFACE, sizeof(CFG_IFACE), "%s", optarg);
				break;
			}
			case 't':
			{
				CFG_INTERVAL = (unsigned int) strtoul(optarg, NULL, 10);
				break;
			}
			case 'v':
			{
				fprintf(stderr, PROGRAM" v"VERSION"\n");
				exit(EXIT_SUCCESS);
			}
			default:
			{
				usage(EXIT_FAILURE);
			}
		}
	}
	
	if (optind != argc)
	{
		usage(EXIT_FAILURE);
	}
	
	// get current hostname
	if (gethostname(HOSTNAME, sizeof(HOSTNAME)) != 0)
	{
		fatalsys("gethostname");
	}
	
	// if not flagged for foreground operation, detach process
	if (!stayinfg)
	{
		pid_t p;
		
		if ((p = fork()) < 0)
		{
			fatalsys("fork");
		}
		
		// let the parent exit
		if (p > 0)
		{
			exit(EXIT_SUCCESS);
		}
		
		// set child to process group leader
		setsid();
	}
	
	dprintf("datadir=%s, interface=%s, timeinterval=%u, hostname=%s\n",
		CFG_DATA_DIR, CFG_IFACE, CFG_INTERVAL, HOSTNAME);
	
	// install signal handlers
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, catch_sigintquitterm);
	signal(SIGQUIT, catch_sigintquitterm);
	signal(SIGTERM, catch_sigintquitterm);
	
	// do initial reading of dev bytes
	read_dev_bytes(&odp);
	
	do
	{
		// sleep between reads
		sleep(CFG_INTERVAL);
		
		// read proc net file
		read_dev_bytes(&od);
		
		// write the difference out
		write_dev_bytes(od.rx - odp.rx, od.tx - odp.tx);
		
		// swap previous datum
		odp = od;
	} while (termint == 0U);
	
	dprintf("main loop terminated, termint=%u\n", termint);
	
	// return status of 1 on SIGINT...
	if (termint == 2U)
	{
		exit(EXIT_FAILURE);
	}
	
	return 0;
}

static void usage(int status)
{
	fprintf(stderr,
		"Usage: %s [-d datadir] [-f] [-i interface] [-t seconds]\n\n", PROGRAM);
	fprintf(stderr,
		"\t-d\tSet parent directory to store statistic files\n");
	fprintf(stderr,
		"\t-f\tSet foreground operation (debugging)\n");
	fprintf(stderr,
		"\t-i\tInterface to collect statistics from (default eth1)\n");
	fprintf(stderr,
		"\t-t\tInterval to probe interface for statistics (seconds)\n\n");
	exit(status);
}

static void catch_sigintquitterm(int signo)
{
	dprintf("signal handler, signo=%d\n", signo);
	
	switch (signo)
	{
		case SIGINT:
		{
			termint = 2U;
			break;
		}
		case SIGQUIT:
		case SIGTERM:
		{
			termint = 1U;
			break;
		}
		default:
		{
			fatalusr("catch_sigintquitterm", "unknown signal");
		}
	}
}

void read_dev_bytes(struct yantddatum *bytes)
{
	static char line[384];
	FILE *fp;
	
	if ((fp = fopen("/proc/net/dev", "r")) == NULL)
	{
		fatalsys("fopen");
	}
	
	while (fgets(line, sizeof(line), fp) != NULL)
	{
		if (strstr(line, CFG_IFACE) != NULL)
		{
			dprintf("\t> %s", line);
			
			sscanf(strchr(line, ':') + 1,
				"%"PRIu64" %*u %*u %*u %*u %*u %*u %*u %"PRIu64" %*u %*u %*u %*u %*u %*u %*u",
				&bytes->rx, &bytes->tx);
			break;
		}
	}
	
	if (fclose(fp) != 0)
	{
		fatalsys("fclose");
	}
}

void write_dev_bytes(uint64_t rx_bytes, uint64_t tx_bytes)
{
	FILE *fp;
	struct tm *tm;
	time_t t;
	struct yantdhdr hdr;
	struct yantddatum *data;
	size_t nitems;
	
	// get local time
	if (time(&t) == (time_t)-1)
	{
		fatalsys("time");
	}
	
	// break out time fields
	if ((tm = localtime(&t)) == NULL)
	{
		fatalsys("localtime");
	}
	
	assert(tm->tm_mday < 1 || tm->tm_mday > DAYSINMONTH[tm->tm_mon]);
	
	snprintf(FILENAME, sizeof(FILENAME), "%s/%s-%s-%04d%02d.otf",
		CFG_DATA_DIR, HOSTNAME, CFG_IFACE, tm->tm_year + 1900, tm->tm_mon + 1);
	
	dprintf("write_dev_bytes: filename=%s\n", FILENAME);
	
	// filesize is based on days in month
	nitems = DAYSINMONTH[tm->tm_mon];
	
	// allocate buffer for rx/tx for each day in month
	data = malloc(sizeof(struct yantddatum) * nitems);
	
	// read current year/month/day bytes
	if ((fp = fopen(FILENAME, "r")) == NULL)
	{
		// first time writing, set hdr record to current date
		hdr.year = (uint16_t) tm->tm_year;
		hdr.month = (uint8_t) tm->tm_mon;
		
		// zero out data bytes
		memset(data, 0, sizeof(struct yantddatum) * nitems);
	}
	else
	{
		// read out hdr
		if (fread(&hdr, sizeof(struct yantdhdr), 1, fp) != 1)
		{
			fatalsys("fread");
		}
		
		// read out previous recorded bytes
		if (fread(data, sizeof(struct yantddatum), nitems, fp) != nitems)
		{
			fatalsys("fread");
		}
		
		if (fclose(fp) != 0)
		{
			fatalsys("fclose");
		}
	}
	
	// append new bytes
	data[tm->tm_mday - 1].rx += rx_bytes;
	data[tm->tm_mday - 1].tx += tx_bytes;
	
	dprintf("rx_bytes=%"PRIu64", tx_bytes=%"PRIu64"\n",
		data[tm->tm_mday - 1].rx, data[tm->tm_mday - 1].tx);
	
	// write out new bytes
	if ((fp = fopen(FILENAME, "w")) == NULL)
	{
		fatalsys("fopen");
	}
	
	// write year/month header
	if (fwrite(&hdr, sizeof(struct yantdhdr), 1, fp) != 1)
	{
		fatalsys("fwrite");
	}
	
	// write byte array
	if (fwrite(data, sizeof(struct yantddatum), nitems, fp) != nitems)
	{
		fatalsys("fwrite");
	}
	
	if (fclose(fp) != 0)
	{
		fatalsys("fclose");
	}
	
	free(data);
}
