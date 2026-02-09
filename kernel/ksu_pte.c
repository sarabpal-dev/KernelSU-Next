// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KernelSU-Next - Dirty PageTable Memory Write
 * Ported from kpatch_lkm
 * 
 * Directly manipulates page table entries to make kernel memory writable.
 * This bypasses set_memory_rw by directly clearing the RO bit in the PTE/PMD.
 * Supports both 4KB page mappings (PTE) and 2MB section mappings (PMD).
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "ksu_kallsyms.h"
#include "klog.h"

/* Cached pointer to swapper_pg_dir */
static pgd_t *ksu_swapper_pg_dir = NULL;

/* ARM64 page table entry bits for section mappings */
#define PMD_SECT_AP_RW      (0UL << 7)   /* AP[2]=0: Read/Write */
#define PMD_SECT_AP_RO      (1UL << 7)   /* AP[2]=1: Read-Only */

/* Get kernel PGD from swapper_pg_dir */
static pgd_t *ksu_pgd_offset_k(unsigned long addr)
{
    if (!ksu_swapper_pg_dir)
        return NULL;
    return ksu_swapper_pg_dir + pgd_index(addr);
}

/*
 * Check if PMD is a huge page (section mapping)
 */
static inline bool ksu_pmd_is_section(pmd_t pmd)
{
    /* PMD_TYPE_SECT = 0x01, PMD_TYPE_TABLE = 0x03 */
    return ((pmd_val(pmd) & 0x3) == 0x1);
}

/*
 * Initialize PTE module
 */
int ksu_pte_init(unsigned long swapper_addr)
{
    if (swapper_addr) {
        ksu_swapper_pg_dir = (pgd_t *)swapper_addr;
        pr_info("ksu: PTE module initialized, swapper_pg_dir: 0x%lx\n", swapper_addr);
        return 0;
    }
    return -EINVAL;
}
EXPORT_SYMBOL(ksu_pte_init);

/*
 * Lookup the PMD for a kernel address
 */
static pmd_t *lookup_kernel_pmd(unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    
    pgd = ksu_pgd_offset_k(addr);
    if (!pgd || pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;
    
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;
    
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;
    
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd))
        return NULL;
    
    return pmd;
}

/*
 * Make a section mapping writable by modifying the PMD
 */
static int ksu_make_rw_section(unsigned long addr)
{
    pmd_t *pmd;
    pmd_t old_pmd;
    unsigned long flags;
    unsigned long new_val;
    
    if (!ksu_syms.aarch64_insn_write) {
        pr_err("ksu: aarch64_insn_write not available\n");
        return -ENOENT;
    }
    
    pmd = lookup_kernel_pmd(addr);
    if (!pmd) {
        pr_err("ksu: failed to lookup PMD for 0x%lx\n", addr);
        return -EINVAL;
    }
    
    old_pmd = *pmd;
    
    if (!ksu_pmd_is_section(old_pmd)) {
        pr_err("ksu: PMD at 0x%lx is not a section mapping\n", addr);
        return -EINVAL;
    }
    
    /* Clear the AP[2] bit (bit 7) to make it writable */
    new_val = pmd_val(old_pmd) & ~PMD_SECT_AP_RO;
    
    if (pmd_val(old_pmd) == new_val) {
        return 0;  /* Already writable */
    }
    
    local_irq_save(flags);
    
    /* PMD is 64-bit, write in two 32-bit operations */
    ksu_syms.aarch64_insn_write((void *)pmd, new_val & 0xFFFFFFFF);
    ksu_syms.aarch64_insn_write((void *)((unsigned long)pmd + 4), new_val >> 32);
    
    /* Flush TLB for this 2MB region */
    flush_tlb_kernel_range(addr & ~((1UL << 21) - 1), 
                           (addr & ~((1UL << 21) - 1)) + (1UL << 21));
    
    local_irq_restore(flags);
    
    return 0;
}

/*
 * Walk page tables to find PTE
 */
static pte_t *lookup_kernel_pte(unsigned long addr)
{
    pmd_t *pmd;
    pte_t *pte;
    
    pmd = lookup_kernel_pmd(addr);
    if (!pmd)
        return NULL;
    
    if (ksu_pmd_is_section(*pmd))
        return NULL;  /* Section mapping, not PTE */
    
    pte = pte_offset_kernel(pmd, addr);
    if (pte_none(*pte))
        return NULL;
    
    return pte;
}

/*
 * Make a kernel address writable by modifying its PTE
 */
static int ksu_make_rw_pte_internal(unsigned long addr)
{
    pte_t *pte;
    pte_t old_pte, new_pte;
    unsigned long flags;
    
    if (!ksu_syms.aarch64_insn_write) {
        pr_err("ksu: aarch64_insn_write not available\n");
        return -ENOENT;
    }
    
    pte = lookup_kernel_pte(addr);
    if (!pte) {
        return -EINVAL;
    }
    
    old_pte = *pte;
    new_pte = pte_mkwrite(old_pte);
    new_pte = pte_mkdirty(new_pte);
    
    if (pte_val(old_pte) == pte_val(new_pte)) {
        return 0;  /* Already writable */
    }
    
    local_irq_save(flags);
    
    ksu_syms.aarch64_insn_write((void *)pte, pte_val(new_pte) & 0xFFFFFFFF);
    ksu_syms.aarch64_insn_write((void *)((unsigned long)pte + 4), pte_val(new_pte) >> 32);
    
    flush_tlb_kernel_range(addr & PAGE_MASK, (addr & PAGE_MASK) + PAGE_SIZE);
    
    local_irq_restore(flags);
    
    return 0;
}

/*
 * Make a kernel address writable - handles both PTE and PMD mappings
 */
int ksu_make_rw_pte(unsigned long addr)
{
    pmd_t *pmd;
    
    if (!ksu_swapper_pg_dir) {
        pr_err("ksu: PTE module not initialized\n");
        return -EINVAL;
    }
    
    pmd = lookup_kernel_pmd(addr);
    if (!pmd) {
        pr_err("ksu: failed to lookup PMD for 0x%lx\n", addr);
        return -EINVAL;
    }
    
    if (ksu_pmd_is_section(*pmd)) {
        return ksu_make_rw_section(addr);
    } else {
        return ksu_make_rw_pte_internal(addr);
    }
}
EXPORT_SYMBOL(ksu_make_rw_pte);

/*
 * Make a kernel address executable by clearing PXN bit
 */
int ksu_make_exec_pte(unsigned long addr)
{
    pmd_t *pmd;
    pte_t *pte;
    unsigned long old_val, new_val;
    unsigned long flags;
    
    if (!ksu_swapper_pg_dir || !ksu_syms.aarch64_insn_write) {
        return -EINVAL;
    }
    
    pmd = lookup_kernel_pmd(addr);
    if (!pmd) {
        return -EINVAL;
    }
    
    if (ksu_pmd_is_section(*pmd)) {
        /* Section mapping - modify PMD to clear PXN */
        unsigned long pmd_val_old = pmd_val(*pmd);
        unsigned long pmd_val_new = pmd_val_old & ~PMD_SECT_PXN;
        
        if (pmd_val_old == pmd_val_new)
            return 0;
        
        local_irq_save(flags);
        ksu_syms.aarch64_insn_write((void *)pmd, pmd_val_new & 0xFFFFFFFF);
        ksu_syms.aarch64_insn_write((void *)((unsigned long)pmd + 4), pmd_val_new >> 32);
        flush_tlb_kernel_range(addr & ~((1UL << 21) - 1), 
                               (addr & ~((1UL << 21) - 1)) + (1UL << 21));
        local_irq_restore(flags);
        
        return 0;
    }
    
    /* PTE mapping */
    pte = pte_offset_kernel(pmd, addr);
    if (!pte || pte_none(*pte))
        return -EINVAL;
    
    old_val = pte_val(*pte);
    new_val = old_val & ~PTE_PXN;
    
    if (old_val == new_val)
        return 0;
    
    local_irq_save(flags);
    ksu_syms.aarch64_insn_write((void *)pte, new_val & 0xFFFFFFFF);
    ksu_syms.aarch64_insn_write((void *)((unsigned long)pte + 4), new_val >> 32);
    flush_tlb_kernel_range(addr & PAGE_MASK, (addr & PAGE_MASK) + PAGE_SIZE);
    local_irq_restore(flags);
    
    return 0;
}
EXPORT_SYMBOL(ksu_make_exec_pte);

/*
 * Write to protected kernel memory using PTE manipulation
 */
int ksu_write_kernel_protected(unsigned long addr, unsigned long value)
{
    unsigned long flags;
    int ret;
    
    ret = ksu_make_rw_pte(addr);
    if (ret)
        return ret;
    
    local_irq_save(flags);
    *(unsigned long *)addr = value;
    local_irq_restore(flags);
    
    return 0;
}
EXPORT_SYMBOL(ksu_write_kernel_protected);
