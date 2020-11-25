/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

static int reload_settings(vici_conn_t *conn)
{
	vici_req_t *req;
	vici_res_t *res;
	char *arg;
	int ret = 0;
	vici_format_t format = VICI_FMT_NONE;

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
				format |= VICI_FMT_RAW | VICI_FMT_JSON;
				continue;
			case '0':
				format |= VICI_FMT_JSON_INTS;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --reload-settings option");
		}
		break;
	}

	req = vici_begin("reload-settings");
	if (format & VICI_FMT_JSON_INTS)
	{
		vici_add_key_valuef(req, "json-integers", "yes");
	}
	res = vici_submit(req, conn);
	if (!res)
	{
		ret = errno;
		fprintf(stderr, "reload-settings request failed: %s\n", strerror(errno));
		return ret;
	}
	if (format & VICI_FMT_RAW)
	{
		vici_dump(res, "reload-settings reply", format, stdout);
	}
	else
	{
		if (!streq(vici_find_str(res, "no", "success"), "yes"))
		{
			fprintf(stderr, "reload-settings failed: %s\n",
					vici_find_str(res, "", "errmsg"));
			ret = 1;
		}
	}
	vici_free_res(res);
	return ret;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		reload_settings, 'r', "reload-settings", "reload daemon strongswan.conf",
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
