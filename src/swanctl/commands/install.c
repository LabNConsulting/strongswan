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

static int manage_policy(vici_conn_t *conn, char *label)
{
	vici_req_t *req;
	vici_res_t *res;
	vici_format_t format = VICI_FMT_NONE;
	char *arg, *child = NULL, *ike = NULL;
	int ret = 0;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'P':
				format |= VICI_FMT_RAW;
				/* fall through to raw */
			case 'r':
				format |= VICI_FMT_PRETTY;
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
			case '0':
				format |= VICI_FMT_JSON_INTS;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --%s option", label);
		}
		break;
	}
	req = vici_begin(label);
	if (child)
	{
		vici_add_key_valuef(req, "child", "%s", child);
	}
	if (ike)
	{
		vici_add_key_valuef(req, "ike", "%s", ike);
	}
	if (format & VICI_FMT_JSON_INTS)
	{
		vici_add_key_valuef(req, "json-integers", "yes");
	}
	res = vici_submit(req, conn);
	if (!res)
	{
		ret = errno;
		fprintf(stderr, "%s request failed: %s\n", label, strerror(errno));
		return ret;
	}
	if (format & VICI_FMT_RAW)
	{
		puts(label);
		vici_dump(res, " reply", format, stdout);
	}
	else
	{
		if (streq(vici_find_str(res, "no", "success"), "yes"))
		{
			printf("%s completed successfully\n", label);
		}
		else
		{
			fprintf(stderr, "%s failed: %s\n",
					label, vici_find_str(res, "", "errmsg"));
			ret = 1;
		}
	}
	vici_free_res(res);
	return ret;
}

static int uninstall(vici_conn_t *conn)
{
	return manage_policy(conn, "uninstall");
}

static int install(vici_conn_t *conn)
{
	return manage_policy(conn, "install");
}

/**
 * Register the uninstall command.
 */
static void __attribute__ ((constructor))reg_uninstall()
{
	command_register((command_t) {
		uninstall, 'u', "uninstall", "uninstall a trap or shunt policy",
		{"--child <name> [--ike <name>] [--raw|--pretty|--json]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"child",		'c', 1, "CHILD_SA configuration to uninstall"},
			{"ike",			'i', 1, "name of the connection to which the child belongs"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
			{"json",		'j', 0, "dump raw response message as JSON"},
			{"json-integers",	'0', 0, "format integer values as decimal where possible"},
		}
	});
}

/**
 * Register install the command.
 */
static void __attribute__ ((constructor))reg_install()
{
	command_register((command_t) {
		install, 'p', "install", "install a trap or shunt policy",
		{"--child <name> [--ike <name>] [--raw|--pretty|--json]",
		 "[--json-integers]"
		},
		{
			{"help",		'h', 0, "show usage information"},
			{"child",		'c', 1, "CHILD_SA configuration to install"},
			{"ike",			'i', 1, "name of the connection to which the child belongs"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
			{"json",		'j', 0, "dump raw response message as JSON"},
			{"json-integers",	'0', 0, "format integer values as decimal where possible"},
		}
	});
}
