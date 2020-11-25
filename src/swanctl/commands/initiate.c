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

CALLBACK(log_cb, void,
	vici_format_t *format, char *name, vici_res_t *msg)
{
	if (*format & VICI_FMT_RAW)
	{
		vici_dump(msg, "log", *format, stdout);
	}
	else
	{
		printf("[%s] %s\n",
			   vici_find_str(msg, "   ", "group"),
			   vici_find_str(msg, "", "msg"));
	}
}

static int initiate(vici_conn_t *conn)
{
	vici_req_t *req;
	vici_res_t *res;
	vici_format_t format = VICI_FMT_NONE;
	char *arg, *child = NULL, *ike = NULL;
	int ret = 0, timeout = 0, level = 1;

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
			case 'c':
				child = arg;
				continue;
			case 'i':
				ike = arg;
				continue;
			case 't':
				timeout = atoi(arg);
				continue;
			case 'l':
				level = atoi(arg);
				continue;
			case '0':
				format |= VICI_FMT_JSON_INTS;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --initiate option");
		}
		break;
	}

	if (vici_register(conn, "control-log", log_cb, &format) != 0)
	{
		ret = errno;
		fprintf(stderr, "registering for log failed: %s\n", strerror(errno));
		return ret;
	}
	req = vici_begin("initiate");
	if (child)
	{
		vici_add_key_valuef(req, "child", "%s", child);
	}
	if (ike)
	{
		vici_add_key_valuef(req, "ike", "%s", ike);
	}
	if (timeout)
	{
		vici_add_key_valuef(req, "timeout", "%d", timeout * 1000);
	}
	vici_add_key_valuef(req, "loglevel", "%d", level);
	if (format & VICI_FMT_JSON_INTS)
	{
		vici_add_key_valuef(req, "json-integers", "yes");
	}
	res = vici_submit(req, conn);
	if (!res)
	{
		ret = errno;
		fprintf(stderr, "initiate request failed: %s\n", strerror(errno));
		return ret;
	}
	if (format & VICI_FMT_RAW && !(format & VICI_FMT_JSON))
	{
		vici_dump(res, "initiate reply", format, stdout);
	}
	else
	{
		if (streq(vici_find_str(res, "no", "success"), "yes"))
		{
			printf("initiate completed successfully\n");
		}
		else
		{
			fprintf(stderr, "initiate failed: %s\n",
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
		initiate, 'i', "initiate", "initiate a connection",
		{"[--child <name>] [--ike <name>] [--timeout <s>] [--raw|--pretty|--json]",
		 "[--json-integers]"
		},
		{
			{"help",		'h', 0, "show usage information"},
			{"child",		'c', 1, "initiate a CHILD_SA configuration"},
			{"ike",			'i', 1, "initiate an IKE_SA, or name of child's parent"},
			{"timeout",		't', 1, "timeout in seconds before detaching"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
			{"json",		'j', 0, "dump raw response message as JSON"},
			{"json-integers",	'0', 0, "format integer values as decimal where possible"},
			{"loglevel",	'l', 1, "verbosity of redirected log"},
		}
	});
}
