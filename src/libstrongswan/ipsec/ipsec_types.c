/*
 * Copyright (C) 2012-2013 Tobias Brunner
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

/*
 * Copyright (C) 2020 LabN Consulting, L.L.C.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "ipsec_types.h"

ENUM(ipsec_mode_names, MODE_TRANSPORT, MODE_DROP,
	"TRANSPORT",
	"TUNNEL",
	"BEET",
	"PASS",
	"DROP"
);

ENUM(policy_dir_names, POLICY_IN, POLICY_FWD,
	"in",
	"out",
	"fwd"
);

ENUM(ipcomp_transform_names, IPCOMP_NONE, IPCOMP_LZJH,
	"IPCOMP_NONE",
	"IPCOMP_OUI",
	"IPCOMP_DEFLATE",
	"IPCOMP_LZS",
	"IPCOMP_LZJH"
);

ENUM(hw_offload_names, HW_OFFLOAD_NO, HW_OFFLOAD_AUTO,
	"no",
	"yes",
	"auto",
);

ENUM(dscp_copy_names, DSCP_COPY_OUT_ONLY, DSCP_COPY_NO,
	"out",
	"in",
	"yes",
	"no",
);

ENUM(iptfs_enable_names, IPTFS_ENABLE_NO, IPTFS_ENABLE_TRY,
	"no",
	"yes",
	"try",
);

ENUM(iptfs_df_names, IPTFS_DF_NO, IPTFS_DF_YES,
	 "no",
	 "rx",
	 "tx",
	 "yes",
);

/*
 * See header
 */
bool ipsec_sa_cfg_equals(ipsec_sa_cfg_t *a, ipsec_sa_cfg_t *b)
{
	return a->mode == b->mode &&
		a->reqid == b->reqid &&
		a->policy_count == b->policy_count &&
		a->esp.use == b->esp.use &&
		a->esp.spi == b->esp.spi &&
		a->ah.use == b->ah.use &&
		a->ah.spi == b->ah.spi &&
		a->ipcomp.transform == b->ipcomp.transform &&
		a->ipcomp.cpi == b->ipcomp.cpi;
}

/*
 * See header
 */
bool mark_from_string(const char *value, mark_op_t ops, mark_t *mark)
{
	char *endptr;

	if (!value)
	{
		return FALSE;
	}
	if (strcasepfx(value, "%unique"))
	{
		if (!(ops & MARK_OP_UNIQUE))
		{
			DBG1(DBG_APP, "unexpected use of %%unique mark", value);
			return FALSE;
		}
		endptr = (char*)value + strlen("%unique");
		if (strcasepfx(endptr, "-dir"))
		{
			mark->value = MARK_UNIQUE_DIR;
			endptr += strlen("-dir");
		}
		else if (!*endptr || *endptr == '/')
		{
			mark->value = MARK_UNIQUE;
		}
		else
		{
			DBG1(DBG_APP, "invalid mark value: %s", value);
			return FALSE;
		}
	}
	else if (strcasepfx(value, "%same"))
	{
		if (!(ops & MARK_OP_SAME))
		{
			DBG1(DBG_APP, "unexpected use of %%same mark", value);
			return FALSE;
		}
		endptr = (char*)value + strlen("%same");
		if (!*endptr || *endptr == '/')
		{
			mark->value = MARK_SAME;
		}
		else
		{
			DBG1(DBG_APP, "invalid mark value: %s", value);
			return FALSE;
		}
	}
	else
	{
		mark->value = strtoul(value, &endptr, 0);
	}
	if (*endptr)
	{
		if (*endptr != '/')
		{
			DBG1(DBG_APP, "invalid mark value: %s", value);
			return FALSE;
		}
		mark->mask = strtoul(endptr+1, &endptr, 0);
		if (*endptr)
		{
			DBG1(DBG_LIB, "invalid mark mask: %s", endptr);
			return FALSE;
		}
	}
	else
	{
		mark->mask = 0xffffffff;
	}
	if (!MARK_IS_UNIQUE(mark->value))
	{
		/* apply the mask to ensure the value is in range */
		mark->value &= mark->mask;
	}
	return TRUE;
}

/*
 * Described in header
 */
bool if_id_from_string(const char *value, uint32_t *if_id)
{
	char *endptr;

	if (!value)
	{
		return FALSE;
	}
	if (strcasepfx(value, "%unique"))
	{
		endptr = (char*)value + strlen("%unique");
		if (strcasepfx(endptr, "-dir"))
		{
			*if_id = IF_ID_UNIQUE_DIR;
			endptr += strlen("-dir");
		}
		else if (!*endptr)
		{
			*if_id = IF_ID_UNIQUE;
		}
		else
		{
			DBG1(DBG_APP, "invalid interface ID: %s", value);
			return FALSE;
		}
	}
	else
	{
		*if_id = strtoul(value, &endptr, 0);
	}
	if (*endptr)
	{
		DBG1(DBG_APP, "invalid interface ID: %s", value);
		return FALSE;
	}
	return TRUE;
}

/*
 * Described in header
 */
void allocate_unique_if_ids(uint32_t *in, uint32_t *out)
{
	static refcount_t unique_if_id = 0;

	if (IF_ID_IS_UNIQUE(*in) || IF_ID_IS_UNIQUE(*out))
	{
		refcount_t if_id = 0;
		bool unique_dir = *in == IF_ID_UNIQUE_DIR ||
						  *out == IF_ID_UNIQUE_DIR;

		if (!unique_dir)
		{
			if_id = ref_get(&unique_if_id);
		}
		if (IF_ID_IS_UNIQUE(*in))
		{
			*in = unique_dir ? ref_get(&unique_if_id) : if_id;
		}
		if (IF_ID_IS_UNIQUE(*out))
		{
			*out = unique_dir ? ref_get(&unique_if_id) : if_id;
		}
	}
}
