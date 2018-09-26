/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2018 Intel Corporation. All rights reserved. */
/*
 * Intel specific definitions for NVDIMM Firmware Interface Table - NFIT
 */
#ifndef _NFIT_INTEL_H_
#define _NFIT_INTEL_H_

/*
 * While the security ops require CONFIG_X86 due to the need to
 * coordinate cache management, the ND_INTEL_SMART command could be
 * generically supported on any arch.
 */
#define ND_INTEL_SMART 1

#define ND_INTEL_SMART_SHUTDOWN_COUNT_VALID     (1 << 5)
#define ND_INTEL_SMART_SHUTDOWN_VALID           (1 << 10)

struct nd_intel_smart {
	u32 status;
	union {
		struct {
			u32 flags;
			u8 reserved0[4];
			u8 health;
			u8 spares;
			u8 life_used;
			u8 alarm_flags;
			u16 media_temperature;
			u16 ctrl_temperature;
			u32 shutdown_count;
			u8 ait_status;
			u16 pmic_temperature;
			u8 reserved1[8];
			u8 shutdown_state;
			u32 vendor_size;
			u8 vendor_data[92];
		} __packed;
		u8 data[128];
	};
} __packed;

#ifdef CONFIG_X86

extern const struct nvdimm_security_ops *intel_security_ops;

#define ND_INTEL_STATUS_SIZE		4
#define ND_INTEL_PASSPHRASE_SIZE	32

#define ND_INTEL_STATUS_RETRY		5
#define ND_INTEL_STATUS_NOT_READY	9
#define ND_INTEL_STATUS_INVALID_STATE	10
#define ND_INTEL_STATUS_INVALID_PASS	11

#define ND_INTEL_SEC_STATE_ENABLED	0x02
#define ND_INTEL_SEC_STATE_LOCKED	0x04
#define ND_INTEL_SEC_STATE_FROZEN	0x08
#define ND_INTEL_SEC_STATE_PLIMIT	0x10
#define ND_INTEL_SEC_STATE_UNSUPPORTED	0x20

struct nd_intel_get_security_state {
	u32 status;
	u32 reserved;
	u8 state;
	u8 reserved1[3];
} __packed;

struct nd_intel_set_passphrase {
	u8 old_pass[ND_INTEL_PASSPHRASE_SIZE];
	u8 new_pass[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_unlock_unit {
	u8 passphrase[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_disable_passphrase {
	u8 passphrase[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_freeze_lock {
	u32 status;
} __packed;

struct nd_intel_secure_erase {
	u8 passphrase[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_overwrite {
	u8 passphrase[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_query_overwrite {
	u32 status;
} __packed;
#else /* CONFIG_X86 */
#define intel_security_ops (NULL)
#endif /* CONFIG_X86 */

#endif
