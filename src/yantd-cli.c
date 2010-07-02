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
	kDisplayBytes,
	kDisplayKiB,
	kDisplayMiB,
	kDisplayGiB,
	kDisplayHumanReadable
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
	fprintf(stderr, "Usage: %s <traffic file>\n", PROGRAM);
	exit(status);
}

static __inline__ double formatbytes(int format, uint64_t bytes)
{
	switch (format)
	{
		case kDisplayBytes:
		{
			return ((double) bytes);
		}
		case kDisplayKiB:
		{
			return ((double) bytes) / 1024.0f;
		}
		case kDisplayMiB:
		{
			return ((double) bytes) / 1024.0f / 1024.0f;
		}
		case kDisplayGiB:
		{
			return ((double) bytes) / 1024.0f / 1024.0f / 1024.0f;
		}
		case kDisplayHumanReadable:
		{
			if (bytes < 1024)
			{
				return ((double) bytes);
			}
			else if (bytes < 1024 * 1024)
			{
				return formatbytes(kDisplayKiB, bytes);
			}
			else if (bytes < 1024 * 1024 * 1024)
			{
				return formatbytes(kDisplayMiB, bytes);
			}
			else
			{
				return formatbytes(kDisplayGiB, bytes);
			}
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
	int i, opt, format = kDisplayHumanReadable;
	double rx_total, tx_total;
	
	// parse cmd line options
	while ((opt = getopt(argc, argv, "bghkmv")) != -1)
	{
		switch (opt)
		{
			case 'b':
			{
				format = kDisplayBytes;
				break;
			}
			case 'g':
			{
				format = kDisplayGiB;
				break;
			}
			case 'h':
			{
				format = kDisplayHumanReadable;
				break;
			}
			case 'k':
			{
				format = kDisplayKiB;
				break;
			}
			case 'm':
			{
				format = kDisplayMiB;
				break;
			}
			case 'v':
			{
				fprintf(stderr, PROGRAM"-cli v"VERSION"\n");
				exit(EXIT_SUCCESS);
			}
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
	
	if (fread(&hdr, sizeof(struct yantdhdr), 1, fp) != 1)
	{
		fatalusr("fread", "data file is corrupt");
	}
	
	// allocate space for data
	nitems = DAYSINMONTH[hdr.month];
	data = malloc(sizeof(struct yantddatum) * nitems);
	
	if (fread(data, sizeof(struct yantddatum), nitems, fp) != nitems)
	{
		fatalusr("fread", "data file is corrupt");
	}
	
	if (fclose(fp) != 0)
	{
		fatalsys("fclose");
	}
	
	// initialize totals
	rx_total = 0.0f;
	tx_total = 0.0f;
	
	printf("   Day\t%12s (MiB)\t%12s (MiB)\n", "Received", "Transmitted");
	printf("------\t------------------\t------------------\n");
	
	for (i = 0; i < DAYSINMONTH[hdr.month]; i++)
	{
		printf("    %02d\t%18.2f\t%18.2f\n",
			i+1, formatbytes(format, data[i].rx), formatbytes(format, data[i].tx));
		
		rx_total += data[i].rx;
		tx_total += data[i].tx;
	}
	
	printf("------\t------------------\t------------------\n");
	printf("Totals\t%18.2f\t%18.2f\n",
		formatbytes(format, rx_total), formatbytes(format, tx_total));
	
	// free data
	free(data);
	
	return 0;
}
