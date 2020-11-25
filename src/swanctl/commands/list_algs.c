/*
 * Copyright (C) 2015 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "command.h"

#include <errno.h>

CALLBACK(algs, int,
	void *null, vici_res_t *res, char *name, void *value, int len)
{
	if (chunk_printable(chunk_create(value, len), NULL, ' '))
	{
		printf("  %s[%.*s]\n", name, len, value);
	}
	return 0;
}

CALLBACK(types, int,
	void *null, vici_res_t *res, char *name)
{
	printf("%s:\n", name);
	return vici_parse_cb(res, NULL, algs, NULL, NULL);
}

static int algorithms(vici_conn_t *conn)
{
	vici_req_t *req;
	vici_res_t *res;
	char *arg;
	vici_format_t format = VICI_FMT_NONE;
	int ret;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'P':
				format |= VICI_FMT_PRETTY;
				/* fall through to raw */
			case 'r':
				format |= VICI_FMT_RAW;
				continue;
			case 'j':
				format |= VICI_FMT_RAW |
					  VICI_FMT_JSON;
			case '0':
				format |= VICI_FMT_JSON_INTS;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --list-algs option");
		}
		break;
	}

	req = vici_begin("get-algorithms");
	if (format & VICI_FMT_JSON_INTS)
	{
		vici_add_key_valuef(req, "json-integers", "yes");
	}
	res = vici_submit(req, conn);
	if (!res)
	{
		ret = errno;
		fprintf(stderr, "get-algorithms request failed: %s\n", strerror(errno));
		return ret;
	}
	if (format & VICI_FMT_RAW)
	{
		vici_dump(res, "get-algorithms reply", format, stdout);
	}
	else
	{
		if (vici_parse_cb(res, types, NULL, NULL, NULL) != 0)
		{
			fprintf(stderr, "parsing get-algorithms reply failed: %s\n",
					strerror(errno));
		}
	}
	vici_free_res(res);
	return 0;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		algorithms, 'g', "list-algs", "show loaded algorithms",
		{"[--raw|--pretty|--json] [--json-integers]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
			{"json",		'j', 0, "dump raw response message as JSON"},
			{"json-integers",	'0', 0, "format integer values as decimal where possible"},
		}
	});
}
