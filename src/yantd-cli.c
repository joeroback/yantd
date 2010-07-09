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

#include <yantd.h>
#include <unistd.h>

#define PROGRAM "yantd"
#define VERSION "1.0"

enum {
	kDisplayKB,
	kDisplayMB,
	kDisplayGB,
	kDisplayTB
};

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

static void __attribute__((__noreturn__)) usage(int status)
{
	fprintf(stderr,
		"Usage: %s [-gkmtv] [-r start-end] <traffic file>\n\n", PROGRAM);
	fprintf(stderr,
		"\t-g\tOutput format Gigabytes\n");
	fprintf(stderr,
		"\t-k\tOutput format Kilobytes\n");
	fprintf(stderr,
		"\t-m\tOutput format Megabytes\n");
	fprintf(stderr,
		"\t-r\tOnly shows days in range (e.g. 3-5 shows 3rd through 5th)\n");
	fprintf(stderr,
		"\t-t\tOutput format Terabytes\n");
	fprintf(stderr,
		"\t-v\tShow version info\n\n");
	exit(status);
}

static __inline__ double formatbytes(int fmt, double bytes)
{
	switch (fmt)
	{
		case kDisplayKB:
		{
			return bytes / 1024.0f;
		}
		case kDisplayMB:
		{
			return bytes / 1024.0f / 1024.0f;
		}
		case kDisplayGB:
		{
			return bytes / 1024.0f / 1024.0f / 1024.0f;
		}
		case kDisplayTB:
		{
			return bytes / 1024.0f / 1024.0f / 1024.0f / 1024.0f;
		}
		default:
		{
			abort();
		}
	}
}

int main(int argc, char **argv)
{
	FILE *fp;
	struct yantdhdr hdr;
	struct yantddatum *data;
	size_t nitems;
	int range_start = -1;
	int range_end = -1;
	int i, n, fmt = kDisplayMB;
	char *suffix = "MB";
	double rx_total, tx_total;
	
	// parse cmd line options
	while ((i = getopt(argc, argv, "gkmr:tv")) != -1)
	{
		switch (i)
		{
			case 'g':
			{
				fmt = kDisplayGB;
				suffix = "GB";
				break;
			}
			case 'k':
			{
				fmt = kDisplayKB;
				suffix = "KB";
				break;
			}
			case 'm':
			{
				fmt = kDisplayMB;
				suffix = "MB";
				break;
			}
			case 'r':
			{
				if(sscanf(optarg, "%d-%d", &range_start, &range_end) != 2)
				{
					fatalcli("invalid day range format\n");
				}
				if (range_start > range_end)
				{
					fatalcli("invalid day range format\n");
				}
				break;
			}
			case 't':
			{
				fmt = kDisplayTB;
				suffix = "TB";
				break;
			}
			case 'v':
			{
				fprintf(stderr, PROGRAM"-cli v"VERSION"\n");
				exit(EXIT_SUCCESS);
			}
			case '?':
			default:
			{
				usage(EXIT_FAILURE);
			}
		}
	}
	
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
	{
		usage(EXIT_FAILURE);
	}
	
	if ((fp = fopen(argv[0], "r")) == NULL)
	{
		fatalsys("fopen");
	}
	
	if (flock(fileno(fp), LOCK_SH) != 0)
	{
		fatalsys("flock");
	}
	
	if (fread(&hdr, sizeof(struct yantdhdr), 1, fp) != 1)
	{
		fatalcli("data file is corrupt\n");
	}
	
	// allocate space for data
	nitems = (size_t) DAYSINMONTH[hdr.month];
	data = malloc(sizeof(struct yantddatum) * nitems);
	
	if (fread(data, sizeof(struct yantddatum), nitems, fp) != nitems)
	{
		fatalcli("data file is corrupt\n");
	}
	
	if (flock(fileno(fp), LOCK_UN) != 0)
	{
		fatalsys("flock");
	}
	
	if (fclose(fp) != 0)
	{
		fatalsys("fclose");
	}
	
	if (range_start != -1)
	{
		if (range_start < 1 || range_start > DAYSINMONTH[hdr.month])
		{
			fatalcli("invalid start day value\n");
		}
		
		i = range_start - 1;
	}
	else
	{
		i = 0;
	}
	
	if (range_end != -1)
	{
		if (range_end < 1 || range_end > DAYSINMONTH[hdr.month])
		{
			fatalcli("invalid end day value\n");
		}
		
		n = range_end;
	}
	else
	{
		n = DAYSINMONTH[hdr.month];
	}
	
	// initialize totals
	rx_total = 0.0f;
	tx_total = 0.0f;
	
	printf("   Day\t%21s\t%21s\t%21s\n", "Received", "Transmitted", "Total");
	printf("------"
		"\t---------------------"
		"\t---------------------"
		"\t---------------------\n");
	
	for (; i < n; i++)
	{
		printf("    %02d\t%18.1f %s\t%18.1f %s\t%18.1f %s\n", i+1,
			formatbytes(fmt, be64toh(data[i].rx)), suffix,
			formatbytes(fmt, be64toh(data[i].tx)), suffix,
			formatbytes(fmt, be64toh(data[i].rx)+be64toh(data[i].tx)), suffix);
		
		rx_total += be64toh(data[i].rx);
		tx_total += be64toh(data[i].tx);
	}
	
	printf("------"
		"\t---------------------"
		"\t---------------------"
		"\t---------------------\n");
	printf("Totals\t%18.1f %s\t%18.1f %s\t%18.1f %s\n",
		formatbytes(fmt, rx_total), suffix,
		formatbytes(fmt, tx_total), suffix,
		formatbytes(fmt, rx_total+tx_total), suffix);
	
	// free data
	free(data);
	
	return 0;
}
