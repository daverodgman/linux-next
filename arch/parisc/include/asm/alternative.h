/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_PARISC_ALTERNATIVE_H
#define __ASM_PARISC_ALTERNATIVE_H

#define INSN_PxTLB	0x02		/* modify pdtlb, pitlb */
#define INSN_NOP	0x8000240	/* nop */


#ifndef __ASSEMBLY__

#include <linux/init.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/stringify.h>

struct alt_instr {
	s32 orig_offset;	/* offset to original instructions */
	u32 len;		/* end of original instructions */
	u32 replacement;	/* replacement instruction or code */
};

void set_kernel_text_rw(int enable_read_write);
// int __init apply_alternatives_all(void);

/* Alternative SMP implementation. */
#define ALTERNATIVE(replacement)		"!0:"	\
	".section .altinstructions, \"aw\"	!"	\
	".word (0b-4-.), 1, " __stringify(replacement) "	!"	\
	".previous"

#else

#define ALTERNATIVE(from, to, replacement)	\
	.section .altinstructions, "aw"	!	\
	.word (from - .), (to - from)/4	!	\
	.word replacement		!	\
	.previous

#endif  /*  __ASSEMBLY__  */

#endif /* __ASM_PARISC_ALTERNATIVE_H */
