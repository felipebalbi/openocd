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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <target/target.h>
#include <target/armv7a.h>
#include <target/cortex_a.h>
#include <target/armv7a_trace.h>
#include <jtag/interface.h>

#define TRACE_BUF_SIZE 65536 /* kB */

#define ETMCR		0x0000
#define ETMCCR		0x0004
#define ETMTRIGGER	0x0008
#define ETMSR		0x0010
#define ETMSCR		0x0014
#define ETMTSSCR	0x0018
#define ETMTEEVR	0x0020
#define ETMTECR1	0x0024
#define ETMACVR(n)	(0x0040 + (4 * ((n) - 1)))
#define ETMACTR(n)	(0x0080 + (4 * ((n) - 1)))
#define ETMCNTRLDVR(n)	(0x0140 + (4 * ((n) - 1)))
#define ETMCNTENR(n)	(0x0150 + (4 * ((n) - 1)))
#define ETMCNTRLDEVR(n)	(0x0160 + (4 * ((n) - 1)))
#define ETMCNTVR(n)	(0x0170 + (4 * ((n) - 1)))
#define ETMSQR		0x019c
#define ETMEXTOUTEVR(n)	(0x01a0 + (4 * ((n) - 1)))
#define ETMCIDCVR1	0x01b0
#define ETMCIDCMR	0x01bc
#define ETMSYNCFR	0x01e0
#define ETMIDR		0x01e4
#define ETMCCER		0x01e8
#define ETMEXTINSELR	0x01ec
#define ETMTSEVR	0x01f8
#define ETMAUXCR	0x01fc
#define ETMTRACEIDR	0x0200
#define OSLSR		0x0304
#define ETMPDSR		0x0314
#define ITMISCOUT	0x0edc
#define ITMISCIN	0x0ee0
#define ITTRIGGER	0x0ee8
#define ITATBDATA0	0x0eec
#define ITATBCTR2	0x0ef0
#define ITATBID		0x0ef4
#define ITATBCTR0	0x0ef8
#define ETMITCTRL	0x0f00
#define ETMLAR		0x0fb0
#define ETMLAR_STATUS	0x0fb4
#define ETMAUTHSTATUS	0x0fb8
#define ETMDEVID	0x0fc8
#define ETMDEVTYPE	0x0fcc
#define PERIPHERAL_ID4	0x0fd0
#define PERIPHERAL_ID5	0x0fd4
#define PERIPHERAL_ID6	0x0fd8
#define PERIPHERAL_ID7	0x0fdc
#define PERIPHERAL_ID0	0x0fe0
#define PERIPHERAL_ID1	0x0fe4
#define COMPONENT_ID0	0x0ff0
#define COMPONENT_ID1	0x0ff4
#define COMPONENT_ID2	0x0ff8
#define COMPONENT_ID3	0x0ffc

/* ETMCR */
#define ETMCR_POWERDOWN		(1 << 0)
#define ETMCR_STALL_PROCESSOR	(1 << 7)
#define ETMCR_BRANCH_OUTPUT	(1 << 8)
#define ETMCR_DEBUG_REQ_CTRL	(1 << 9)
#define ETMCR_PROG_BIT		(1 << 10)
#define ETMCR_CYCLE_ACCURATE	(1 << 12)
#define ETMCR_CTX_ID_SIZE(n)	(((n) & 3) << 14)
#define ETMCR_PROC_SELECT(n)	(((n) & 7) << 25)
#define ETMCR_TIMESTAMP_EN	(1 << 28)
#define ETMCR_RET_STACK_EN	(1 << 29)

/* ETMSR */
#define ETMSR_PROG_BIT		(1 << 1)

/* ETMLAR */
#define ETMLAR_KEY		0xc5acce55

/* ETMLAR_STATUS */
#define ETMLAR_STATUS_LOCK_IMPL	(1 << 0)
#define ETMLAR_STATUS_LOCKED	(1 << 1)

/* ETMIDR */
#define ETMIDR_IMPL_REVISION(n)	((n) & 0xf)
#define ETMIDR_REVISION(n)	(((n) >> 4) & 0xff) /* Major and Minor */
#define ETMIDR_32BIT_THUMB	(1 << 18)
#define ETMIDR_SECURITY_EXT	(1 << 19)
#define ETMIDR_IMPL_CODE(n)	(((n) >> 24) & 0xff) /* should be 'A' */

/* ETMCCER */
#define ETMCCER_EXT_INPUT_NUM(n) ((n) & 3)
#define ETMCCER_EXT_INPUT_SZ(n)	(((n) >> 3) & 0xff)
#define ETMCCER_REG_READ	(1 << 11)
#define ETMCCER_INST_RES(n)	(((n) >> 13) & 7)
#define ETMCCER_TIMESTAMP	(1 << 22)
#define ETMCCER_RET_STACK	(1 << 23)
#define ETMCCER_DMB_DSB		(1 << 24)
#define ETMCCER_DMB_DSB_TSTAMP	(1 << 25)

/* ITTRIGGER */
#define ITTRIGGER_PTMTRIGGER	(1 << 0)

/* ETMTECR1 */
#define ETMTECR1_ADDR_COMP(n)	((n) & 0xf)
#define ETMTECR1_EXCLUDE	(1 << 24)
#define ETMTECR1_TRACE_CTRL_EN	(1 << 25)

/* ETMTEEVR */
#define ETMTEEVR_RESOURCE_A(n)	((n) & 0x3f)
#define ETMTEEVR_RESOURCE_B(n)	(((n) >> 7) & 0x3f)
#define ETMTEEVR_FUNCTION(n)	(((n) >> 14) & 3)

/* PTM Event Resources, see IHI0035B section 3.8.1 for details */
#define PTM_SINGLE_ADDR_COMP(n)	((n) & 0xf)
#define PTM_ADDR_RANG_COMP(n)	(0x10 | ((n) & 3))
#define PTM_INSTR_RESOURCE(n)	(0x10 | ((n) & 0xb))
#define PTM_E_ICE_WATCH_COMP(n)	(0x20 | ((n) & 7))
#define PTM_COUNTER(n)		(0x40 | ((n) & 3))
#define PTM_SEQ_IN_STATE(n)	(0x50 | ((n) & 3))
#define PTM_CTX_ID_COMP(n)	(0x50 | ((n) & 0xb))
#define PTM_EXT_INPUT(n)	(0x60 | ((n) & 2))
#define PTM_EXT_INPUT_SEL(n)	(0x60 | ((n) & 0xb))
#define PTM_PROC_NON_SECURE	(0x60 | 0xd)
#define PTM_TRACE_PROHIBITED	(0x60 | 0xe)
#define PTM_ALWAYS_TRUE		(0x60 | 0xf)

static inline int ptm_read_reg(struct ptm_context *ptm, uint32_t reg,
		uint32_t *val)
{
	return target_read_u32(ptm->target, ptm->base_addr + reg, val);
}

static inline int ptm_write_reg(struct ptm_context *ptm, uint32_t reg,
		uint32_t val)
{
	return target_write_u32(ptm->target, ptm->base_addr + reg, val);
}

static inline int ptm_try_unlock(struct ptm_context *ptm)
{
	uint32_t reg;
	int ret;

	if (!(ptm->has_lock_implementation && ptm->is_locked))
		return ERROR_OK;

	ret = ptm_write_reg(ptm, ETMLAR, ETMLAR_KEY);
	if (ret != ERROR_OK)
		return ret;

	ret = ptm_read_reg(ptm, ETMLAR_STATUS, &reg);
	if (ret != ERROR_OK)
		return ret;

	if (reg & ETMLAR_STATUS_LOCKED)
		return ERROR_FAIL;

	ptm->is_locked = 0;

	return ERROR_OK;
}

static void ptm_lock(struct ptm_context *ptm)
{
	uint32_t reg;
	int ret;

	if (!ptm->has_lock_implementation || ptm->is_locked)
		return;

	/* writing anything other than ETMLAR_KEY locks access */
	ret = ptm_write_reg(ptm, ETMLAR, 0xd06f00d);
	if (ret != ERROR_OK)
		return;

	ret = ptm_read_reg(ptm, ETMLAR_STATUS, &reg);
	if (ret != ERROR_OK)
		return;

	if (!(reg & ETMLAR_STATUS_LOCKED))
		return;

	ptm->is_locked = 1;
}

COMMAND_HANDLER(handle_ptm_setup_command)
{
	struct ptm_context *ptm;
	struct target *target;
	struct arm *arm;

	uint32_t base_addr;
	uint32_t reg;

	int ret;

	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	target = get_current_target(CMD_CTX);
	arm = target_to_arm(target);
	if (!is_arm(arm)) {
		command_print(CMD_CTX, "target '%s' is '%s'; not an ARM",
				target_name(target),
				target_type_name(target));
		return ERROR_FAIL;
	}

	ptm = malloc(sizeof(*ptm));
	if (!ptm)
		return -ENOMEM;

	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], base_addr);

	ptm->target = target;
	ptm->base_addr = base_addr;

	ret = ptm_read_reg(ptm, ETMLAR_STATUS, &reg);
	if (ret != ERROR_OK)
		return ret;

	ptm->has_lock_implementation = reg & ETMLAR_STATUS_LOCK_IMPL;
	ptm->is_locked = reg & ETMLAR_STATUS_LOCKED;

	ret = ptm_try_unlock(ptm);
	if (ret != ERROR_OK)
		return ret;

	ret = ptm_read_reg(ptm, ETMCR, &reg);
	if (ret != ERROR_OK)
		return ret;

	reg &= ~ETMCR_POWERDOWN;

	ret = ptm_write_reg(ptm, ETMCR, reg);
	if (ret != ERROR_OK)
		return ret;

	reg |= ETMCR_PROG_BIT;

	/* set Programming Bit on Main Control Register */
	ret = ptm_write_reg(ptm, ETMCR, reg);
	if (ret != ERROR_OK)
		return ret;

	/* add 1ms sleep to be sure write has gone through */
	jtag_add_sleep(1000);

	/* check that Status register's bit 2 is set */
	ret = ptm_read_reg(ptm, ETMSR, &reg);
	if (ret != ERROR_OK)
		return ret;
	if (!(reg & ETMSR_PROG_BIT)) {
		LOG_ERROR("ProgBit should be set");
		return ERROR_FAIL;
	}

	arm->ptm = ptm;

	ret = ptm_read_reg(ptm, ETMIDR, &reg);
	if (ret != ERROR_OK)
		return ret;

	ptm->impl_revision = ETMIDR_IMPL_REVISION(reg);
	ptm->revision = ETMIDR_REVISION(reg);
	ptm->has_32bit_thumb = reg & ETMIDR_32BIT_THUMB;
	ptm->has_security_ext = reg & ETMIDR_SECURITY_EXT;

	ret = ptm_read_reg(ptm, ETMCCER, &reg);
	if (ret != ERROR_OK)
		return ret;

	ptm->num_ext_input_sel = ETMCCER_EXT_INPUT_NUM(reg);
	ptm->ext_input_size = ETMCCER_EXT_INPUT_SZ(reg);
	ptm->has_readable_regs = reg & ETMCCER_REG_READ;
	ptm->num_inst_resources = ETMCCER_INST_RES(reg);
	ptm->has_timestamping = reg & ETMCCER_TIMESTAMP;
	ptm->has_return_stack = reg & ETMCCER_RET_STACK;
	ptm->has_dmb_dsb_waypoint = reg & ETMCCER_DMB_DSB;
	ptm->has_dmb_dsb_timestamp = reg & ETMCCER_DMB_DSB_TSTAMP;

	/* By default, trace all processor execution */
	ret = ptm_write_reg(ptm, ETMTECR1, ETMTECR1_EXCLUDE);
	if (ret != ERROR_OK)
		return ret;

	/* And set TraceEnable Event Register to Resource A Always True */
	ret = ptm_write_reg(ptm, ETMTEEVR,
			ETMTEEVR_RESOURCE_A(PTM_ALWAYS_TRUE));
	if (ret != ERROR_OK)
		return ret;

	ptm_lock(ptm);

	return ERROR_OK;
}

COMMAND_HANDLER(handle_ptm_info_command)
{
	struct ptm_context *ptm;
	struct target *target;
	struct arm *arm;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	target = get_current_target(CMD_CTX);
	arm = target_to_arm(target);
	if (!is_arm(arm)) {
		command_print(CMD_CTX, "target '%s' is '%s'; not an ARM",
				target_name(target),
				target_type_name(target));
		return ERROR_FAIL;
	}

	ptm = arm->ptm;
	if (!ptm) {
		command_print(CMD_CTX, "No PTM configured, please call 'ptm setup'.");
		return ERROR_FAIL;
	}

	command_print(CMD_CTX, "PTM v%d.%d", ptm->revision >> 4,
			ptm->revision & 0xf);
	command_print(CMD_CTX, "    Implementation Revision v%d",
			ptm->impl_revision);
	command_print(CMD_CTX, "    Number of external inputs: %d",
			ptm->num_ext_input_sel);
	command_print(CMD_CTX, "    External input bus size: %d",
			ptm->ext_input_size);
	command_print(CMD_CTX, "    Number of instr resources: %d",
			ptm->num_inst_resources);
	command_print(CMD_CTX, "    Support for 32-bit Thumb %spresent",
			ptm->has_32bit_thumb ? "" : "not ");
	command_print(CMD_CTX, "    Support for Security Extensions %spresent",
			ptm->has_security_ext ? "" : "not ");
	command_print(CMD_CTX, "    Support for readable registers %spresent",
			ptm->has_readable_regs ? "" : "not ");
	command_print(CMD_CTX, "    Support for timestamping %spresent",
			ptm->has_timestamping ? "" : "not ");
	command_print(CMD_CTX, "    Support for return stack %spresent",
			ptm->has_return_stack ? "" : "not ");
	command_print(CMD_CTX, "    Support for DMB/DSB as waypoints %spresent",
			ptm->has_dmb_dsb_waypoint ? "" : "not ");
	command_print(CMD_CTX, "    Support for DMB/DSB timestamps %spresent",
			ptm->has_dmb_dsb_timestamp ? "" : "not ");

	return ERROR_OK;
}

COMMAND_HANDLER(handle_ptm_trace_config_command)
{
	struct ptm_context *ptm;
	struct target *target;
	struct arm *arm;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	target = get_current_target(CMD_CTX);
	arm = target_to_arm(target);
	if (!is_arm(arm)) {
		command_print(CMD_CTX, "target '%s' is '%s'; not an ARM",
				target_name(target),
				target_type_name(target));
		return ERROR_FAIL;
	}

	ptm = arm->ptm;
	if (!ptm) {
		command_print(CMD_CTX, "No PTM configured, please call 'ptm setup'.");
		return ERROR_FAIL;
	}

	return ERROR_OK;
}

COMMAND_HANDLER(handle_ptm_trace_start_command)
{
	struct ptm_context *ptm;
	struct target *target;
	struct arm *arm;

	uint32_t reg;

	int ret;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	target = get_current_target(CMD_CTX);
	arm = target_to_arm(target);
	if (!is_arm(arm)) {
		command_print(CMD_CTX, "target '%s' is '%s'; not an ARM",
				target_name(target),
				target_type_name(target));
		return ERROR_FAIL;
	}

	ptm = arm->ptm;
	if (!ptm) {
		command_print(CMD_CTX, "No PTM configured, please call 'ptm setup'.");
		return ERROR_FAIL;
	}

	ret = ptm_try_unlock(ptm);
	if (ret != ERROR_OK)
		return ret;

	ret = ptm_read_reg(ptm, ETMCR, &reg);
	if (ret != ERROR_OK)
		return ret;

	reg &= ~ETMCR_PROG_BIT;

	/* Clear Programming Bit to start tracing */
	ret = ptm_write_reg(ptm, ETMCR, reg);
	if (ret != ERROR_OK)
		return ret;

	/* add 1ms sleep to be sure write has gone through */
	jtag_add_sleep(1000);

	ret = ptm_read_reg(ptm, ETMSR, &reg);
	if (ret != ERROR_OK)
		return ret;
	if (reg & ETMSR_PROG_BIT) {
		LOG_ERROR("ProgBit should be set");
		return ERROR_FAIL;
	}

	ptm_lock(ptm);

	return ERROR_OK;
}

COMMAND_HANDLER(handle_ptm_trace_stop_command)
{
	struct ptm_context *ptm;
	struct target *target;
	struct arm *arm;

	uint32_t reg;

	int ret;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	target = get_current_target(CMD_CTX);
	arm = target_to_arm(target);
	if (!is_arm(arm)) {
		command_print(CMD_CTX, "target '%s' is '%s'; not an ARM",
				target_name(target),
				target_type_name(target));
		return ERROR_FAIL;
	}

	ptm = arm->ptm;
	if (!ptm) {
		command_print(CMD_CTX, "current target doesn't have PTM configured");
		return ERROR_FAIL;
	}

	ret = ptm_try_unlock(ptm);
	if (ret != ERROR_OK)
		return ret;

	ret = ptm_read_reg(ptm, ETMCR, &reg);
	if (ret != ERROR_OK)
		return ret;

	reg |= ETMCR_PROG_BIT;

	/* set Programming Bit on Main Control Register */
	ret = ptm_write_reg(ptm, ETMCR, reg);
	if (ret != ERROR_OK)
		return ret;

	/* add 1ms sleep to be sure write has gone through */
	jtag_add_sleep(1000);

	/* check that Status register's bit 2 is set */
	ret = ptm_read_reg(ptm, ETMSR, &reg);
	if (ret != ERROR_OK)
		return ret;
	if (!(reg & ETMSR_PROG_BIT)) {
		LOG_ERROR("ProgBit should be set");
		return ERROR_FAIL;
	}

	ptm_lock(ptm);

	return ERROR_OK;
}

static const struct command_registration ptm_trace_command_handlers[] = {
	{
		.name		= "config",
		.handler	= handle_ptm_trace_config_command,
		.mode		= COMMAND_ANY,
		.help		= "Configure trace parameters",
		.usage		= "",
	},
	{
		.name		= "start",
		.handler	= handle_ptm_trace_start_command,
		.mode		= COMMAND_ANY,
		.help		= "Start tracing",
		.usage		= "",
	},
	{
		.name		= "stop",
		.handler	= handle_ptm_trace_stop_command,
		.mode		= COMMAND_ANY,
		.help		= "Stop tracing",
		.usage		= "",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration ptm_command_handlers[] = {
	{
		.name		= "setup",
		.handler	= handle_ptm_setup_command,
		.mode		= COMMAND_ANY,
		.help		= "Setup a PTM context for target",
		.usage		= "base_addr",
	},
	{
		.name		= "info",
		.handler	= handle_ptm_info_command,
		.mode		= COMMAND_ANY,
		.help		= "Dump information about PTM",
		.usage		= "",
	},
	{
		.name		= "trace",
		.mode		= COMMAND_ANY,
		.help		= "ptm trace command group",
		.usage		= "",
		.chain		= ptm_trace_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

const struct command_registration armv7a_trace_command_handlers[] = {
	{
		.name		= "ptm",
		.mode		= COMMAND_ANY,
		.help		= "ptm command group",
		.usage		= "",
		.chain		= ptm_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};
