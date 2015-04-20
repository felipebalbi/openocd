/***************************************************************************
 *   Copyright (C) 2015  Felipe Balbi <balbi@ti.com>                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 ***************************************************************************/

#ifndef ARMV7A_TRACE_H
#define ARMV7A_TRACE_H

#include <target/target.h>
#include <command.h>

struct ptm_context {
	struct target	*target;

	uint32_t	base_addr;

	uint8_t		ext_input_size;
	uint8_t		impl_revision;
	uint8_t		num_ext_input_sel;
	uint8_t		num_inst_resources;
	uint8_t		revision;

	uint32_t	has_32bit_thumb:1;
	uint32_t	has_dmb_dsb_timestamp:1;
	uint32_t	has_dmb_dsb_waypoint:1;
	uint32_t	has_lock_implementation:1;
	uint32_t	has_readable_regs:1;
	uint32_t	has_return_stack:1;
	uint32_t	has_security_ext:1;
	uint32_t	has_timestamping:1;

	uint32_t	is_locked:1;
};

extern const struct command_registration armv7a_trace_command_handlers[];

#endif /* ARMV7A_TRACE_H */
