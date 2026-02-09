// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KernelSU-Next - CFI Bypass
 * Ported from kpatch_lkm
 * 
 * Patches CFI verification functions with RET instruction to disable
 * Control Flow Integrity checks, allowing indirect function pointer calls
 * to resolved symbols.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/list.h>

#include "ksu_kallsyms.h"
#include "klog.h"

/* Track patched functions */
static unsigned long patched_cfi_slowpath = 0;
static unsigned long patched_cfi_slowpath_diag = 0;
static unsigned long patched_cfi_check_fail = 0;
static unsigned long patched_ubsan_cfi_abort = 0;
static unsigned long patched_report_cfi_failure = 0;

/* Resolved aarch64_insn_write for early patching */
static int (*early_insn_write)(void *, u32) = NULL;

/*
 * Early kprobe-based symbol lookup (before full init)
 */
static unsigned long KSU_NO_CFI ksu_early_lookup(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0)
        return 0;
    
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

/*
 * Disable kprobe blacklist to allow hooking protected functions
 */
static int KSU_NO_CFI disable_kprobe_blacklist(void)
{
    struct kprobe_blacklist_entry *ent;
    struct list_head *kprobe_blacklist;
    int count = 0;
    
    kprobe_blacklist = (struct list_head *)ksu_early_lookup("kprobe_blacklist");
    if (!kprobe_blacklist) {
        pr_warn("ksu: kprobe_blacklist not found\n");
        return -ENOENT;
    }
    
    list_for_each_entry(ent, kprobe_blacklist, list) {
        if (!ent || ent->start_addr == 0 || ent->end_addr == 0)
            continue;
        count++;
        ent->start_addr = 0;
        ent->end_addr = 0;
    }
    
    pr_info("ksu: disabled %d kprobe blacklist entries\n", count);
    return 0;
}

/*
 * Write instruction using inline assembly to bypass CFI
 */
static noinline int ksu_call_insn_write(void *fn, void *addr, u32 insn)
{
    long ret;
    
    asm volatile(
        "mov x0, %1\n"      /* addr */
        "mov w1, %w2\n"     /* insn (32-bit) */
        "blr %3\n"          /* call aarch64_insn_write */
        "mov %0, x0\n"      /* return value */
        : "=r"(ret)
        : "r"(addr), "r"(insn), "r"(fn)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "x30", "memory", "cc"
    );
    
    return (int)ret;
}

/*
 * Early CFI bypass - patches CFI check functions with RET
 * MUST be called before any indirect function pointer calls
 */
int KSU_NO_CFI ksu_early_cfi_bypass(void)
{
    int patched = 0;
    unsigned long addr;
    int ret;
    
    pr_info("ksu: performing early CFI bypass\n");
    
    /* Step 1: Disable kprobe blacklist */
    ret = disable_kprobe_blacklist();
    if (ret < 0) {
        pr_warn("ksu: failed to disable kprobe blacklist: %d\n", ret);
        /* Continue anyway */
    }
    
    /* Step 2: Resolve aarch64_insn_write */
    early_insn_write = (void *)ksu_early_lookup("aarch64_insn_write");
    if (!early_insn_write) {
        pr_err("ksu: aarch64_insn_write not found\n");
        return -ENOENT;
    }
    pr_info("ksu: aarch64_insn_write at 0x%lx\n", (unsigned long)early_insn_write);
    
    /* Step 3: Patch __cfi_slowpath */
    addr = ksu_early_lookup("__cfi_slowpath");
    if (addr) {
        u32 *p = (u32 *)addr;
        if (*p != ARM64_RET && *p != ARM64_BTI_C) {
            /* Patch with: bti c; ret */
            ksu_call_insn_write(early_insn_write, p, ARM64_BTI_C);
            ksu_call_insn_write(early_insn_write, p + 1, ARM64_RET);
            patched_cfi_slowpath = addr;
            patched++;
            pr_info("ksu: patched __cfi_slowpath\n");
        } else {
            pr_info("ksu: __cfi_slowpath already patched\n");
        }
    }
    
    /* Step 4: Patch __cfi_slowpath_diag */
    addr = ksu_early_lookup("__cfi_slowpath_diag");
    if (addr) {
        u32 *p = (u32 *)addr;
        if (*p != ARM64_RET && *p != ARM64_BTI_C) {
            ksu_call_insn_write(early_insn_write, p, ARM64_BTI_C);
            ksu_call_insn_write(early_insn_write, p + 1, ARM64_RET);
            patched_cfi_slowpath_diag = addr;
            patched++;
            pr_info("ksu: patched __cfi_slowpath_diag\n");
        }
    }
    
    /* Step 5: Patch __cfi_check_fail */
    addr = ksu_early_lookup("__cfi_check_fail");
    if (addr) {
        u32 *p = (u32 *)addr;
        if (*p != ARM64_RET && *p != ARM64_BTI_C) {
            ksu_call_insn_write(early_insn_write, p, ARM64_BTI_C);
            ksu_call_insn_write(early_insn_write, p + 1, ARM64_RET);
            patched_cfi_check_fail = addr;
            patched++;
            pr_info("ksu: patched __cfi_check_fail\n");
        }
    }
    
    /* Step 6: Patch __ubsan_handle_cfi_check_fail_abort */
    addr = ksu_early_lookup("__ubsan_handle_cfi_check_fail_abort");
    if (addr) {
        u32 *p = (u32 *)addr;
        if (*p != ARM64_RET && *p != ARM64_BTI_C) {
            ksu_call_insn_write(early_insn_write, p, ARM64_BTI_C);
            ksu_call_insn_write(early_insn_write, p + 1, ARM64_RET);
            patched_ubsan_cfi_abort = addr;
            patched++;
            pr_info("ksu: patched __ubsan_handle_cfi_check_fail_abort\n");
        }
    }
    
    /* Step 7: Patch report_cfi_failure (returns success) */
    addr = ksu_early_lookup("report_cfi_failure");
    if (addr) {
        u32 *p = (u32 *)addr;
        if (*p != ARM64_BTI_C) {
            /* bti c; mov x0, #1; ret */
            ksu_call_insn_write(early_insn_write, p, ARM64_BTI_C);
            ksu_call_insn_write(early_insn_write, p + 1, 0xD2800020);  /* mov x0, #1 */
            ksu_call_insn_write(early_insn_write, p + 2, ARM64_RET);
            patched_report_cfi_failure = addr;
            patched++;
            pr_info("ksu: patched report_cfi_failure\n");
        }
    }
    
    pr_info("ksu: early CFI bypass complete, patched %d functions\n", patched);
    return 0;
}
EXPORT_SYMBOL(ksu_early_cfi_bypass);

/*
 * Late CFI bypass - uses resolved symbols to patch CFI functions
 * This is more robust than early bypass as it uses kallsyms_on_each_symbol
 */
void ksu_patch_cfi_functions(void)
{
    unsigned long cfi_funcs[7];
    const char *cfi_names[] = {
        "__cfi_slowpath",
        "__cfi_slowpath_diag", 
        "_cfi_slowpath",
        "__cfi_check_fail",
        "__ubsan_handle_cfi_check_fail_abort",
        "__ubsan_handle_cfi_check_fail",
        "report_cfi_failure"
    };
    int i, patched = 0;
    
    // We reuse the static variable to avoid double patching if early bypass succeeded
    // But we check again anyway just in case
    
    if (!ksu_syms.aarch64_insn_write) {
        pr_err("ksu: aarch64_insn_write not resolved, cannot patch CFI\n");
        return;
    }
    
    pr_info("ksu: patching CFI functions using resolved aarch64_insn_write at 0x%lx\n",
            (unsigned long)ksu_syms.aarch64_insn_write);
    
    /* Lookup all CFI functions using unrestricted lookup */
    for (i = 0; i < 7; i++) {
        cfi_funcs[i] = ksu_lookup_name_unrestricted(cfi_names[i]);
    }
    
    /* Patch each CFI function with BTI C + RET instruction */
    for (i = 0; i < 7; i++) {
        if (!cfi_funcs[i])
            continue;
        
        /* Check if already patched (first instruction is BTI C) */
        u32 current_insn = *(u32 *)cfi_funcs[i];
        u32 next_insn = *(u32 *)(cfi_funcs[i] + 4);
        
        /* Check for BTI C + RET (or mov+ret) */
        if (current_insn == ARM64_BTI_C) {
            if (i == 6 && next_insn == 0xD2800020) { /* report_cfi_failure */
                pr_info("ksu: %s already patched (BTI)\n", cfi_names[i]);
                patched++;
                continue;
            }
            if (next_insn == ARM64_RET) {
                pr_info("ksu: %s already patched (BTI)\n", cfi_names[i]);
                patched++;
                continue;
            }
        }
        
        /* For report_cfi_failure, patch with: bti c; mov x0, #1; ret */
        if (i == 6) {  /* report_cfi_failure */
            ksu_call_insn_write((void *)ksu_syms.aarch64_insn_write, (void *)cfi_funcs[i], ARM64_BTI_C);
            ksu_call_insn_write((void *)ksu_syms.aarch64_insn_write, (void *)(cfi_funcs[i] + 4), 0xD2800020);  /* mov x0, #1 */
            ksu_call_insn_write((void *)ksu_syms.aarch64_insn_write, (void *)(cfi_funcs[i] + 8), ARM64_RET);
        } else {
            /* Patch with: bti c; ret */
            ksu_call_insn_write((void *)ksu_syms.aarch64_insn_write, (void *)cfi_funcs[i], ARM64_BTI_C);
            ksu_call_insn_write((void *)ksu_syms.aarch64_insn_write, (void *)(cfi_funcs[i] + 4), ARM64_RET);
        }
        
        pr_info("ksu: patched %s at 0x%lx with BTI bypass\n", cfi_names[i], cfi_funcs[i]);
        patched++;
    }
    
    if (patched > 0) {
        pr_info("ksu: late CFI bypass active (%d functions patched)\n", patched);
    } else {
        pr_warn("ksu: no CFI functions found to patch in late init\n");
    }
}
EXPORT_SYMBOL(ksu_patch_cfi_functions);
