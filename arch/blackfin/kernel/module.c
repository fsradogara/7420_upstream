/*
 * File:         arch/blackfin/kernel/module.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

 * Copyright 2004-2009 Analog Devices Inc.
 *
 * Licensed under the GPL-2 or later
 */

#include <linux/moduleloader.h>
#include <linux/elf.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <asm/dma.h>
#include <asm/cacheflush.h>

/*
 * handle arithmetic relocations.
 * See binutils/bfd/elf32-bfin.c for more details
 */
#define RELOC_STACK_SIZE 100
static uint32_t reloc_stack[RELOC_STACK_SIZE];
static unsigned int reloc_stack_tos;

#define is_reloc_stack_empty() ((reloc_stack_tos > 0)?0:1)

static void reloc_stack_push(uint32_t value)
{
	reloc_stack[reloc_stack_tos++] = value;
}

static uint32_t reloc_stack_pop(void)
{
	return reloc_stack[--reloc_stack_tos];
}

static uint32_t reloc_stack_operate(unsigned int oper, struct module *mod)
{
	uint32_t value;

	switch (oper) {
	case R_add:
		value = reloc_stack[reloc_stack_tos - 2] +
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_sub:
		value = reloc_stack[reloc_stack_tos - 2] -
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_mult:
		value = reloc_stack[reloc_stack_tos - 2] *
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_div:
		value = reloc_stack[reloc_stack_tos - 2] /
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_mod:
		value = reloc_stack[reloc_stack_tos - 2] %
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_lshift:
		value = reloc_stack[reloc_stack_tos - 2] <<
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_rshift:
		value = reloc_stack[reloc_stack_tos - 2] >>
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_and:
		value = reloc_stack[reloc_stack_tos - 2] &
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_or:
		value = reloc_stack[reloc_stack_tos - 2] |
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_xor:
		value = reloc_stack[reloc_stack_tos - 2] ^
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_land:
		value = reloc_stack[reloc_stack_tos - 2] &&
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_lor:
		value = reloc_stack[reloc_stack_tos - 2] ||
			reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 2;
		break;
	case R_neg:
		value = -reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos--;
		break;
	case R_comp:
		value = ~reloc_stack[reloc_stack_tos - 1];
		reloc_stack_tos -= 1;
		break;
	default:
		printk(KERN_WARNING "module %s: unhandled reloction\n",
				mod->name);
		return 0;
	}

	/* now push the new value back on stack */
	reloc_stack_push(value);

	return value;
}

void *module_alloc(unsigned long size)
{
	if (size == 0)
		return NULL;
	return vmalloc(size);
}

/* Free memory returned from module_alloc */
void module_free(struct module *mod, void *module_region)
{
	vfree(module_region);
}

/* Transfer the section to the L1 memory */
int
module_frob_arch_sections(Elf_Ehdr * hdr, Elf_Shdr * sechdrs,
#include <asm/uaccess.h>
#include <linux/uaccess.h>

#define mod_err(mod, fmt, ...)						\
	pr_err("module %s: " fmt, (mod)->name, ##__VA_ARGS__)
#define mod_debug(mod, fmt, ...)					\
	pr_debug("module %s: " fmt, (mod)->name, ##__VA_ARGS__)

/* Transfer the section to the L1 memory */
int
module_frob_arch_sections(Elf_Ehdr *hdr, Elf_Shdr *sechdrs,
			  char *secstrings, struct module *mod)
{
	/*
	 * XXX: sechdrs are vmalloced in kernel/module.c
	 * and would be vfreed just after module is loaded,
	 * so we hack to keep the only information we needed
	 * in mod->arch to correctly free L1 I/D sram later.
	 * NOTE: this breaks the semantic of mod->arch structure.
	 */
	Elf_Shdr *s, *sechdrs_end = sechdrs + hdr->e_shnum;
	void *dest = NULL;

	for (s = sechdrs; s < sechdrs_end; ++s) {
		if ((strcmp(".l1.text", secstrings + s->sh_name) == 0) ||
		    ((strcmp(".text", secstrings + s->sh_name) == 0) &&
		     (hdr->e_flags & EF_BFIN_CODE_IN_L1) && (s->sh_size > 0))) {
			dest = l1_inst_sram_alloc(s->sh_size);
			mod->arch.text_l1 = dest;
			if (dest == NULL) {
				printk(KERN_ERR
				       "module %s: L1 instruction memory allocation failed\n",
				       mod->name);
				return -1;
			}
			dma_memcpy(dest, (void *)s->sh_addr, s->sh_size);
			s->sh_flags &= ~SHF_ALLOC;
			s->sh_addr = (unsigned long)dest;
		}
		if ((strcmp(".l1.data", secstrings + s->sh_name) == 0) ||
		    ((strcmp(".data", secstrings + s->sh_name) == 0) &&
		     (hdr->e_flags & EF_BFIN_DATA_IN_L1) && (s->sh_size > 0))) {
			dest = l1_data_sram_alloc(s->sh_size);
			mod->arch.data_a_l1 = dest;
			if (dest == NULL) {
				printk(KERN_ERR
					"module %s: L1 data memory allocation failed\n",
					mod->name);
				return -1;
			}
			memcpy(dest, (void *)s->sh_addr, s->sh_size);
			s->sh_flags &= ~SHF_ALLOC;
			s->sh_addr = (unsigned long)dest;
		}
		if (strcmp(".l1.bss", secstrings + s->sh_name) == 0 ||
		    ((strcmp(".bss", secstrings + s->sh_name) == 0) &&
		     (hdr->e_flags & EF_BFIN_DATA_IN_L1) && (s->sh_size > 0))) {
			dest = l1_data_sram_alloc(s->sh_size);
			mod->arch.bss_a_l1 = dest;
			if (dest == NULL) {
				printk(KERN_ERR
					"module %s: L1 data memory allocation failed\n",
					mod->name);
				return -1;
			}
			memset(dest, 0, s->sh_size);
			s->sh_flags &= ~SHF_ALLOC;
			s->sh_addr = (unsigned long)dest;
		}
		if (strcmp(".l1.data.B", secstrings + s->sh_name) == 0) {
			dest = l1_data_B_sram_alloc(s->sh_size);
			mod->arch.data_b_l1 = dest;
			if (dest == NULL) {
				printk(KERN_ERR
					"module %s: L1 data memory allocation failed\n",
					mod->name);
				return -1;
			}
			memcpy(dest, (void *)s->sh_addr, s->sh_size);
			s->sh_flags &= ~SHF_ALLOC;
			s->sh_addr = (unsigned long)dest;
		}
		if (strcmp(".l1.bss.B", secstrings + s->sh_name) == 0) {
			dest = l1_data_B_sram_alloc(s->sh_size);
			mod->arch.bss_b_l1 = dest;
			if (dest == NULL) {
				printk(KERN_ERR
					"module %s: L1 data memory allocation failed\n",
					mod->name);
				return -1;
			}
			memset(dest, 0, s->sh_size);
			s->sh_flags &= ~SHF_ALLOC;
			s->sh_addr = (unsigned long)dest;
		}
		if ((strcmp(".l2.text", secstrings + s->sh_name) == 0) ||
		    ((strcmp(".text", secstrings + s->sh_name) == 0) &&
		     (hdr->e_flags & EF_BFIN_CODE_IN_L2) && (s->sh_size > 0))) {
			dest = l2_sram_alloc(s->sh_size);
			mod->arch.text_l2 = dest;
			if (dest == NULL) {
				printk(KERN_ERR
				       "module %s: L2 SRAM allocation failed\n",
				       mod->name);
				return -1;
			}
			memcpy(dest, (void *)s->sh_addr, s->sh_size);
			s->sh_flags &= ~SHF_ALLOC;
			s->sh_addr = (unsigned long)dest;
		}
		if ((strcmp(".l2.data", secstrings + s->sh_name) == 0) ||
		    ((strcmp(".data", secstrings + s->sh_name) == 0) &&
		     (hdr->e_flags & EF_BFIN_DATA_IN_L2) && (s->sh_size > 0))) {
			dest = l2_sram_alloc(s->sh_size);
			mod->arch.data_l2 = dest;
			if (dest == NULL) {
				printk(KERN_ERR
					"module %s: L2 SRAM allocation failed\n",
					mod->name);
				return -1;
			}
			memcpy(dest, (void *)s->sh_addr, s->sh_size);
			s->sh_flags &= ~SHF_ALLOC;
			s->sh_addr = (unsigned long)dest;
		}
		if (strcmp(".l2.bss", secstrings + s->sh_name) == 0 ||
		    ((strcmp(".bss", secstrings + s->sh_name) == 0) &&
		     (hdr->e_flags & EF_BFIN_DATA_IN_L2) && (s->sh_size > 0))) {
			dest = l2_sram_alloc(s->sh_size);
			mod->arch.bss_l2 = dest;
			if (dest == NULL) {
				printk(KERN_ERR
					"module %s: L2 SRAM allocation failed\n",
					mod->name);
				return -1;
			}
			memset(dest, 0, s->sh_size);
			s->sh_flags &= ~SHF_ALLOC;
			s->sh_addr = (unsigned long)dest;
		}
	}
	return 0;
}

int
apply_relocate(Elf_Shdr * sechdrs, const char *strtab,
	       unsigned int symindex, unsigned int relsec, struct module *me)
{
	printk(KERN_ERR "module %s: .rel unsupported\n", me->name);
	return -ENOEXEC;
	void *dest;

	for (s = sechdrs; s < sechdrs_end; ++s) {
		const char *shname = secstrings + s->sh_name;

		if (s->sh_size == 0)
			continue;

		if (!strcmp(".l1.text", shname) ||
		    (!strcmp(".text", shname) &&
		     (hdr->e_flags & EF_BFIN_CODE_IN_L1))) {

			dest = l1_inst_sram_alloc(s->sh_size);
			mod->arch.text_l1 = dest;
			if (dest == NULL) {
				mod_err(mod, "L1 inst memory allocation failed\n");
				return -1;
			}
			dma_memcpy(dest, (void *)s->sh_addr, s->sh_size);

		} else if (!strcmp(".l1.data", shname) ||
		           (!strcmp(".data", shname) &&
		            (hdr->e_flags & EF_BFIN_DATA_IN_L1))) {

			dest = l1_data_sram_alloc(s->sh_size);
			mod->arch.data_a_l1 = dest;
			if (dest == NULL) {
				mod_err(mod, "L1 data memory allocation failed\n");
				return -1;
			}
			memcpy(dest, (void *)s->sh_addr, s->sh_size);

		} else if (!strcmp(".l1.bss", shname) ||
		           (!strcmp(".bss", shname) &&
		            (hdr->e_flags & EF_BFIN_DATA_IN_L1))) {

			dest = l1_data_sram_zalloc(s->sh_size);
			mod->arch.bss_a_l1 = dest;
			if (dest == NULL) {
				mod_err(mod, "L1 data memory allocation failed\n");
				return -1;
			}

		} else if (!strcmp(".l1.data.B", shname)) {

			dest = l1_data_B_sram_alloc(s->sh_size);
			mod->arch.data_b_l1 = dest;
			if (dest == NULL) {
				mod_err(mod, "L1 data memory allocation failed\n");
				return -1;
			}
			memcpy(dest, (void *)s->sh_addr, s->sh_size);

		} else if (!strcmp(".l1.bss.B", shname)) {

			dest = l1_data_B_sram_alloc(s->sh_size);
			mod->arch.bss_b_l1 = dest;
			if (dest == NULL) {
				mod_err(mod, "L1 data memory allocation failed\n");
				return -1;
			}
			memset(dest, 0, s->sh_size);

		} else if (!strcmp(".l2.text", shname) ||
		           (!strcmp(".text", shname) &&
		            (hdr->e_flags & EF_BFIN_CODE_IN_L2))) {

			dest = l2_sram_alloc(s->sh_size);
			mod->arch.text_l2 = dest;
			if (dest == NULL) {
				mod_err(mod, "L2 SRAM allocation failed\n");
				return -1;
			}
			memcpy(dest, (void *)s->sh_addr, s->sh_size);

		} else if (!strcmp(".l2.data", shname) ||
		           (!strcmp(".data", shname) &&
		            (hdr->e_flags & EF_BFIN_DATA_IN_L2))) {

			dest = l2_sram_alloc(s->sh_size);
			mod->arch.data_l2 = dest;
			if (dest == NULL) {
				mod_err(mod, "L2 SRAM allocation failed\n");
				return -1;
			}
			memcpy(dest, (void *)s->sh_addr, s->sh_size);

		} else if (!strcmp(".l2.bss", shname) ||
		           (!strcmp(".bss", shname) &&
		            (hdr->e_flags & EF_BFIN_DATA_IN_L2))) {

			dest = l2_sram_zalloc(s->sh_size);
			mod->arch.bss_l2 = dest;
			if (dest == NULL) {
				mod_err(mod, "L2 SRAM allocation failed\n");
				return -1;
			}

		} else
			continue;

		s->sh_flags &= ~SHF_ALLOC;
		s->sh_addr = (unsigned long)dest;
	}

	return 0;
}

/*************************************************************************/
/* FUNCTION : apply_relocate_add                                         */
/* ABSTRACT : Blackfin specific relocation handling for the loadable     */
/*            modules. Modules are expected to be .o files.              */
/*            Arithmetic relocations are handled.                        */
/*            We do not expect LSETUP to be split and hence is not       */
/*            handled.                                                   */
/*            R_byte and R_byte2 are also not handled as the gas         */
/*            does not generate it.                                      */
/*************************************************************************/
int
apply_relocate_add(Elf_Shdr * sechdrs, const char *strtab,
/*            R_BFIN_BYTE and R_BFIN_BYTE2 are also not handled as the   */
/*            gas does not generate it.                                  */
/*************************************************************************/
int
apply_relocate_add(Elf_Shdr *sechdrs, const char *strtab,
		   unsigned int symindex, unsigned int relsec,
		   struct module *mod)
{
	unsigned int i;
	unsigned short tmp;
	Elf32_Rela *rel = (void *)sechdrs[relsec].sh_addr;
	Elf32_Sym *sym;
	uint32_t *location32;
	uint16_t *location16;
	uint32_t value;

	pr_debug("Applying relocate section %u to %u\n", relsec,
	       sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		location16 =
		    (uint16_t *) (sechdrs[sechdrs[relsec].sh_info].sh_addr +
				  rel[i].r_offset);
		location32 = (uint32_t *) location16;
	Elf32_Rela *rel = (void *)sechdrs[relsec].sh_addr;
	Elf32_Sym *sym;
	unsigned long location, value, size;

	mod_debug(mod, "applying relocate section %u to %u\n",
		  relsec, sechdrs[relsec].sh_info);

	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		location = sechdrs[sechdrs[relsec].sh_info].sh_addr +
		           rel[i].r_offset;

		/* This is the symbol it is referring to. Note that all
		   undefined symbols have been resolved. */
		sym = (Elf32_Sym *) sechdrs[symindex].sh_addr
		    + ELF32_R_SYM(rel[i].r_info);
		if (is_reloc_stack_empty()) {
			value = sym->st_value;
		} else {
			value = reloc_stack_pop();
		}
		value += rel[i].r_addend;
		pr_debug("location is %x, value is %x type is %d \n",
			 (unsigned int) location32, value,
			 ELF32_R_TYPE(rel[i].r_info));

		switch (ELF32_R_TYPE(rel[i].r_info)) {

		case R_pcrel24:
		case R_pcrel24_jump_l:
			/* Add the value, subtract its postition */
			location16 =
			    (uint16_t *) (sechdrs[sechdrs[relsec].sh_info].
					  sh_addr + rel[i].r_offset - 2);
			location32 = (uint32_t *) location16;
			value -= (uint32_t) location32;
			value >>= 1;
			pr_debug("value is %x, before %x-%x after %x-%x\n", value,
			       *location16, *(location16 + 1),
			       (*location16 & 0xff00) | (value >> 16 & 0x00ff),
			       value & 0xffff);
			*location16 =
			    (*location16 & 0xff00) | (value >> 16 & 0x00ff);
			*(location16 + 1) = value & 0xffff;
			break;
		case R_pcrel12_jump:
		case R_pcrel12_jump_s:
			value -= (uint32_t) location32;
			value >>= 1;
			*location16 = (value & 0xfff);
			break;
		case R_pcrel10:
			value -= (uint32_t) location32;
			value >>= 1;
			*location16 = (value & 0x3ff);
			break;
		case R_luimm16:
			pr_debug("before %x after %x\n", *location16,
				       (value & 0xffff));
			tmp = (value & 0xffff);
			if ((unsigned long)location16 >= L1_CODE_START) {
				dma_memcpy(location16, &tmp, 2);
			} else
				*location16 = tmp;
			break;
		case R_huimm16:
			pr_debug("before %x after %x\n", *location16,
				       ((value >> 16) & 0xffff));
			tmp = ((value >> 16) & 0xffff);
			if ((unsigned long)location16 >= L1_CODE_START) {
				dma_memcpy(location16, &tmp, 2);
			} else
				*location16 = tmp;
			break;
		case R_rimm16:
			*location16 = (value & 0xffff);
			break;
		case R_byte4_data:
			pr_debug("before %x after %x\n", *location32, value);
			*location32 = value;
			break;
		case R_push:
			reloc_stack_push(value);
			break;
		case R_const:
			reloc_stack_push(rel[i].r_addend);
			break;
		case R_add:
		case R_sub:
		case R_mult:
		case R_div:
		case R_mod:
		case R_lshift:
		case R_rshift:
		case R_and:
		case R_or:
		case R_xor:
		case R_land:
		case R_lor:
		case R_neg:
		case R_comp:
			reloc_stack_operate(ELF32_R_TYPE(rel[i].r_info), mod);
			break;
		default:
			printk(KERN_ERR "module %s: Unknown relocation: %u\n",
			       mod->name, ELF32_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
		value = sym->st_value;
		value += rel[i].r_addend;

#ifdef CONFIG_SMP
		if (location >= COREB_L1_DATA_A_START) {
			mod_err(mod, "cannot relocate in L1: %u (SMP kernel)\n",
				ELF32_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
#endif

		mod_debug(mod, "location is %lx, value is %lx type is %d\n",
			  location, value, ELF32_R_TYPE(rel[i].r_info));

		switch (ELF32_R_TYPE(rel[i].r_info)) {

		case R_BFIN_HUIMM16:
			value >>= 16;
		case R_BFIN_LUIMM16:
		case R_BFIN_RIMM16:
			size = 2;
			break;
		case R_BFIN_BYTE4_DATA:
			size = 4;
			break;

		case R_BFIN_PCREL24:
		case R_BFIN_PCREL24_JUMP_L:
		case R_BFIN_PCREL12_JUMP:
		case R_BFIN_PCREL12_JUMP_S:
		case R_BFIN_PCREL10:
			mod_err(mod, "unsupported relocation: %u (no -mlong-calls?)\n",
				ELF32_R_TYPE(rel[i].r_info));
			return -ENOEXEC;

		default:
			mod_err(mod, "unknown relocation: %u\n",
				ELF32_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}

		switch (bfin_mem_access_type(location, size)) {
		case BFIN_MEM_ACCESS_CORE:
		case BFIN_MEM_ACCESS_CORE_ONLY:
			memcpy((void *)location, &value, size);
			break;
		case BFIN_MEM_ACCESS_DMA:
			dma_memcpy((void *)location, &value, size);
			break;
		case BFIN_MEM_ACCESS_ITEST:
			isram_memcpy((void *)location, &value, size);
			break;
		default:
			mod_err(mod, "invalid relocation for %#lx\n", location);
			return -ENOEXEC;
		}
	}

	return 0;
}

int
module_finalize(const Elf_Ehdr * hdr,
		const Elf_Shdr * sechdrs, struct module *mod)
{
	unsigned int i, strindex = 0, symindex = 0;
	char *secstrings;
	long err = 0;

	secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (i = 1; i < hdr->e_shnum; i++) {
		/* Internal symbols and strings. */
		if (sechdrs[i].sh_type == SHT_SYMTAB) {
			symindex = i;
			strindex = sechdrs[i].sh_link;
		}
	}

	for (i = 1; i < hdr->e_shnum; i++) {
		const char *strtab = (char *)sechdrs[strindex].sh_addr;
		unsigned int info = sechdrs[i].sh_info;
		const char *shname = secstrings + sechdrs[i].sh_name;

		/* Not a valid relocation section? */
		if (info >= hdr->e_shnum)
			continue;

		if ((sechdrs[i].sh_type == SHT_RELA) &&
		    ((strcmp(".rela.l2.text", secstrings + sechdrs[i].sh_name) == 0) ||
		    (strcmp(".rela.l1.text", secstrings + sechdrs[i].sh_name) == 0) ||
		    ((strcmp(".rela.text", secstrings + sechdrs[i].sh_name) == 0) &&
			(hdr->e_flags & (EF_BFIN_CODE_IN_L1|EF_BFIN_CODE_IN_L2))))) {
			apply_relocate_add((Elf_Shdr *) sechdrs, strtab,
					   symindex, i, mod);
		}
	}
		/* Only support RELA relocation types */
		if (sechdrs[i].sh_type != SHT_RELA)
			continue;

		if (!strcmp(".rela.l2.text", shname) ||
		    !strcmp(".rela.l1.text", shname) ||
		    (!strcmp(".rela.text", shname) &&
			 (hdr->e_flags & (EF_BFIN_CODE_IN_L1 | EF_BFIN_CODE_IN_L2)))) {

			err = apply_relocate_add((Elf_Shdr *) sechdrs, strtab,
					   symindex, i, mod);
			if (err < 0)
				return -ENOEXEC;
		}
	}

	return 0;
}

void module_arch_cleanup(struct module *mod)
{
	l1_inst_sram_free(mod->arch.text_l1);
	l1_data_A_sram_free(mod->arch.data_a_l1);
	l1_data_A_sram_free(mod->arch.bss_a_l1);
	l1_data_B_sram_free(mod->arch.data_b_l1);
	l1_data_B_sram_free(mod->arch.bss_b_l1);
	l2_sram_free(mod->arch.text_l2);
	l2_sram_free(mod->arch.data_l2);
	l2_sram_free(mod->arch.bss_l2);
}
