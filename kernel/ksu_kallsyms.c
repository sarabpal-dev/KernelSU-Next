// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KernelSU-Next - Kallsyms-based symbol resolution
 * Ported from kpatch_lkm for LKM compatibility
 * 
 * Resolves all non-exported kernel symbols at runtime using:
 * 1. Kprobe trick for kallsyms_lookup_name equivalent
 * 2. kallsyms_on_each_symbol for blacklisted symbols
 * 3. Inline assembly to bypass CFI checks
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#include "ksu_kallsyms.h"
#include "klog.h"
#include <linux/lsm_hooks.h>

/* Global symbol table */
struct ksu_symbols ksu_syms = {0};
EXPORT_SYMBOL(ksu_syms);

/* Define selinux_blob_sizes to satisfy undefined symbol reference in included headers */
struct lsm_blob_sizes selinux_blob_sizes;
EXPORT_SYMBOL(selinux_blob_sizes); /* Export to other objects in this module */

/* Forward declaration for CFI patch */
extern void ksu_patch_cfi_functions(void);

/* kallsyms_on_each_symbol function pointer */
typedef int (*kallsyms_on_each_symbol_fn)(int (*fn)(void *, const char *, 
                                          struct module *, unsigned long), void *data);
static kallsyms_on_each_symbol_fn ksu_kallsyms_on_each_symbol = NULL;

/* Symbol search context */
struct ksu_symbol_search {
    const char *name;
    unsigned long addr;
};

/*
 * Kprobe-based symbol lookup (works for most symbols)
 */
unsigned long KSU_NO_CFI ksu_kallsyms_lookup_name(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name
    };
    unsigned long addr;
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_debug("ksu: kprobe failed for %s: %d\n", name, ret);
        return 0;
    }
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}
EXPORT_SYMBOL(ksu_kallsyms_lookup_name);

/*
 * Callback for kallsyms_on_each_symbol iteration
 */
static int ksu_find_symbol_callback(void *data, const char *name,
                                    struct module *mod, unsigned long addr)
{
    struct ksu_symbol_search *search = data;
    
    if (strcmp(name, search->name) == 0) {
        search->addr = addr;
        return 1;  /* Stop iteration */
    }
    return 0;  /* Continue */
}

/*
 * Call kallsyms_on_each_symbol using inline assembly to bypass CFI
 */
static noinline int ksu_call_kallsyms_on_each_symbol(void *fn, void *callback, void *data)
{
    long ret;
    
    asm volatile(
        "mov x0, %1\n"      /* callback */
        "mov x1, %2\n"      /* data */
        "blr %3\n"          /* call fn */
        "mov %0, x0\n"      /* return value */
        : "=r"(ret)
        : "r"(callback), "r"(data), "r"(fn)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "x30", "memory", "cc"
    );
    
    return (int)ret;
}

/*
 * Initialize kallsyms_on_each_symbol pointer
 */
static int ksu_init_kallsyms_iterator(void)
{
    if (ksu_kallsyms_on_each_symbol)
        return 0;
    
    ksu_kallsyms_on_each_symbol = (kallsyms_on_each_symbol_fn)
        ksu_kallsyms_lookup_name("kallsyms_on_each_symbol");
    
    if (!ksu_kallsyms_on_each_symbol) {
        pr_warn("ksu: kallsyms_on_each_symbol not found\n");
        return -ENOENT;
    }
    
    pr_info("ksu: kallsyms_on_each_symbol found at 0x%lx\n", 
            (unsigned long)ksu_kallsyms_on_each_symbol);
    return 0;
}

/*
 * Lookup any symbol - uses kallsyms_on_each_symbol to bypass blacklist
 */
unsigned long ksu_lookup_name_unrestricted(const char *name)
{
    struct ksu_symbol_search search = {
        .name = name,
        .addr = 0
    };
    
    /* First try kprobe method */
    search.addr = ksu_kallsyms_lookup_name(name);
    if (search.addr)
        return search.addr;
    
    /* Fallback to kallsyms_on_each_symbol */
    if (!ksu_kallsyms_on_each_symbol) {
        if (ksu_init_kallsyms_iterator() < 0)
            return 0;
    }
    
    /* Call via inline assembly to bypass CFI */
    ksu_call_kallsyms_on_each_symbol((void *)ksu_kallsyms_on_each_symbol,
                                     ksu_find_symbol_callback, &search);
    return search.addr;
}
EXPORT_SYMBOL(ksu_lookup_name_unrestricted);

/*
 * Resolve all required symbols
 */
int ksu_init_symbols(void)
{
    int missing = 0;
    
    pr_info("ksu: resolving kernel symbols...\n");
    
    /* Initialize kallsyms iterator first */
    ksu_init_kallsyms_iterator();
    
    /* Page table base */
    ksu_syms.swapper_pg_dir = ksu_lookup_name_unrestricted("swapper_pg_dir");
    if (ksu_syms.swapper_pg_dir) {
        pr_info("ksu: swapper_pg_dir: 0x%lx\n", ksu_syms.swapper_pg_dir);
        ksu_pte_init(ksu_syms.swapper_pg_dir);
    }
    
    /* Instruction patching */
    ksu_syms.aarch64_insn_write = (void *)ksu_lookup_name_unrestricted("aarch64_insn_write");
    if (!ksu_syms.aarch64_insn_write) {
        pr_err("ksu: aarch64_insn_write not found - critical!\n");
        missing++;
    } else {
        /* 
         * Now that we have aarch64_insn_write and unrestricted lookup, 
         * retry CFI patching in case early bypass failed.
         */
        ksu_patch_cfi_functions();
        pr_info("ksu: aarch64_insn_write: 0x%lx\n", (unsigned long)ksu_syms.aarch64_insn_write);
    }
    
    /* SELinux state */
    ksu_syms.selinux_state = (void *)ksu_lookup_name_unrestricted("selinux_state");
    void *real_selinux_blob_sizes = (void *)ksu_lookup_name_unrestricted("selinux_blob_sizes");
    ksu_syms.selinux_blob_sizes = real_selinux_blob_sizes;
    
    if (real_selinux_blob_sizes) {
         memcpy(&selinux_blob_sizes, real_selinux_blob_sizes, sizeof(selinux_blob_sizes));
    }
    
    pr_info("ksu: selinux_state: 0x%lx, selinux_blob_sizes: 0x%lx\n",
            (unsigned long)ksu_syms.selinux_state, (unsigned long)ksu_syms.selinux_blob_sizes);
    
    /* SELinux policy functions */
    ksu_syms.selinux_status_update_policyload = (void *)
        ksu_lookup_name_unrestricted("selinux_status_update_policyload");
    ksu_syms.selnl_notify_policyload = (void *)
        ksu_lookup_name_unrestricted("selnl_notify_policyload");
    ksu_syms.avc_ss_reset = (void *)ksu_lookup_name_unrestricted("avc_ss_reset");
    
    /* AVtab functions */
    ksu_syms.avtab_search_node = (void *)ksu_lookup_name_unrestricted("avtab_search_node");
    ksu_syms.avtab_search_node_next = (void *)ksu_lookup_name_unrestricted("avtab_search_node_next");
    ksu_syms.avtab_insert_nonunique = (void *)ksu_lookup_name_unrestricted("avtab_insert_nonunique");
    
    pr_info("ksu: avtab_search_node: 0x%lx, avtab_insert_nonunique: 0x%lx\n",
            (unsigned long)ksu_syms.avtab_search_node, 
            (unsigned long)ksu_syms.avtab_insert_nonunique);
    
    /* Ebitmap functions */
    ksu_syms.ebitmap_get_bit = (void *)ksu_lookup_name_unrestricted("ebitmap_get_bit");
    ksu_syms.ebitmap_set_bit = (void *)ksu_lookup_name_unrestricted("ebitmap_set_bit");
    
    /* Symtab functions */
    ksu_syms.symtab_search = (void *)ksu_lookup_name_unrestricted("symtab_search");
    ksu_syms.symtab_insert = (void *)ksu_lookup_name_unrestricted("symtab_insert");
    ksu_syms.__hashtab_insert = (void *)ksu_lookup_name_unrestricted("__hashtab_insert");
    
    /* Policydb functions */
    ksu_syms.policydb_filenametr_search = (void *)
        ksu_lookup_name_unrestricted("policydb_filenametr_search");
    
    pr_info("ksu: symtab_search: 0x%lx, policydb_filenametr_search: 0x%lx\n",
            (unsigned long)ksu_syms.symtab_search,
            (unsigned long)ksu_syms.policydb_filenametr_search);
    
    /* Namespace operations */
    ksu_syms.path_mount = (void *)ksu_lookup_name_unrestricted("path_mount");
    ksu_syms.path_umount = (void *)ksu_lookup_name_unrestricted("path_umount");
    ksu_syms.mntns_operations = (void *)ksu_lookup_name_unrestricted("mntns_operations");
    ksu_syms.ns_get_path = (void *)ksu_lookup_name_unrestricted("ns_get_path");
    
    pr_info("ksu: path_mount: 0x%lx, mntns_operations: 0x%lx\n",
            (unsigned long)ksu_syms.path_mount, (unsigned long)ksu_syms.mntns_operations);
    
    /* Syscall/process helpers */
    ksu_syms.ksys_unshare = (void *)ksu_lookup_name_unrestricted("ksys_unshare");
    ksu_syms.__arm64_sys_setns = (void *)ksu_lookup_name_unrestricted("__arm64_sys_setns");
    ksu_syms.set_fs_pwd = (void *)ksu_lookup_name_unrestricted("set_fs_pwd");
    
    pr_info("ksu: ksys_unshare: 0x%lx, __arm64_sys_setns: 0x%lx\n",
            (unsigned long)ksu_syms.ksys_unshare, (unsigned long)ksu_syms.__arm64_sys_setns);
    
    /* Tracepoint */
    ksu_syms.__tracepoint_sys_enter = (void *)
        ksu_lookup_name_unrestricted("__tracepoint_sys_enter");
    
    /* String/memory helpers */
    ksu_syms.strncpy_from_user_nofault = (void *)
        ksu_lookup_name_unrestricted("strncpy_from_user_nofault");
    
    /* Task work */
    ksu_syms.task_work_add = (void *)ksu_lookup_name_unrestricted("task_work_add");
    
    /* Seccomp */
    ksu_syms.seccomp_filter_release = (void *)
        ksu_lookup_name_unrestricted("seccomp_filter_release");
    
    /* PTE helpers */
    ksu_syms.ptep_set_access_flags = (void *)
        ksu_lookup_name_unrestricted("ptep_set_access_flags");
    
    /* Filesystem */
    ksu_syms.ext4_unregister_sysfs = (void *)
        ksu_lookup_name_unrestricted("ext4_unregister_sysfs");
    
    /* UTS */
    ksu_syms.uts_sem = (void *)ksu_lookup_name_unrestricted("uts_sem");
    
    /* Security */
    ksu_syms.security_inode_init_security_anon = (void *)
        ksu_lookup_name_unrestricted("security_inode_init_security_anon");
    
    /* Credentials */
    ksu_syms.prepare_creds = (void *)ksu_lookup_name_unrestricted("prepare_creds");
    ksu_syms.commit_creds = (void *)ksu_lookup_name_unrestricted("commit_creds");
    ksu_syms.prepare_kernel_cred = (void *)ksu_lookup_name_unrestricted("prepare_kernel_cred");
    ksu_syms.__put_cred = (void *)ksu_lookup_name_unrestricted("__put_cred");
    ksu_syms.abort_creds = (void *)ksu_lookup_name_unrestricted("abort_creds");
    ksu_syms.get_task_cred = (void *)ksu_lookup_name_unrestricted("get_task_cred");
    ksu_syms.override_creds = (void *)ksu_lookup_name_unrestricted("override_creds");
    ksu_syms.revert_creds = (void *)ksu_lookup_name_unrestricted("revert_creds");

    /* Groups */
    ksu_syms.groups_alloc = (void *)ksu_lookup_name_unrestricted("groups_alloc");
    ksu_syms.groups_free = (void *)ksu_lookup_name_unrestricted("groups_free");
    ksu_syms.groups_sort = (void *)ksu_lookup_name_unrestricted("groups_sort");
    ksu_syms.set_groups = (void *)ksu_lookup_name_unrestricted("set_groups");

    /* Filesystem/Path */
    ksu_syms.alloc_file_pseudo = (void *)ksu_lookup_name_unrestricted("alloc_file_pseudo");
    ksu_syms.dentry_open = (void *)ksu_lookup_name_unrestricted("dentry_open");
    ksu_syms.iterate_dir = (void *)ksu_lookup_name_unrestricted("iterate_dir");
    ksu_syms.path_get = (void *)ksu_lookup_name_unrestricted("path_get");
    ksu_syms.kernel_read = (void *)ksu_lookup_name_unrestricted("kernel_read");
    ksu_syms.kernel_write = (void *)ksu_lookup_name_unrestricted("kernel_write");

    /* Security */
    ksu_syms.security_inode_init_security_anon = (void *)
        ksu_lookup_name_unrestricted("security_inode_init_security_anon");
    ksu_syms.security_release_secctx = (void *)ksu_lookup_name_unrestricted("security_release_secctx");
    ksu_syms.security_secctx_to_secid = (void *)ksu_lookup_name_unrestricted("security_secctx_to_secid");
    ksu_syms.security_secid_to_secctx = (void *)ksu_lookup_name_unrestricted("security_secid_to_secctx");

    /* Memory/User copy */
    ksu_syms.copy_from_user_nofault = (void *)ksu_lookup_name_unrestricted("copy_from_user_nofault");
    ksu_syms.copy_to_user_nofault = (void *)ksu_lookup_name_unrestricted("copy_to_user_nofault");
    
    pr_info("ksu: task_work_add: 0x%lx, strncpy_from_user_nofault: 0x%lx\n",
            (unsigned long)ksu_syms.task_work_add,
            (unsigned long)ksu_syms.strncpy_from_user_nofault);
    
    /* Memory protection (optional) */
    ksu_syms.set_memory_rw = (void *)ksu_lookup_name_unrestricted("set_memory_rw");
    ksu_syms.set_memory_ro = (void *)ksu_lookup_name_unrestricted("set_memory_ro");
    ksu_syms.set_memory_x = (void *)ksu_lookup_name_unrestricted("set_memory_x");
    ksu_syms.set_memory_nx = (void *)ksu_lookup_name_unrestricted("set_memory_nx");
    
    /* fsnotify functions */
    ksu_syms.fsnotify_alloc_group = (void *)ksu_lookup_name_unrestricted("fsnotify_alloc_group");
    ksu_syms.fsnotify_put_group = (void *)ksu_lookup_name_unrestricted("fsnotify_put_group");
    ksu_syms.fsnotify_init_mark = (void *)ksu_lookup_name_unrestricted("fsnotify_init_mark");
    ksu_syms.fsnotify_destroy_mark = (void *)ksu_lookup_name_unrestricted("fsnotify_destroy_mark");
    ksu_syms.fsnotify_add_mark = (void *)ksu_lookup_name_unrestricted("fsnotify_add_mark");
    ksu_syms.fsnotify_put_mark = (void *)ksu_lookup_name_unrestricted("fsnotify_put_mark");

    /* UMH functions for LKM late init */
    ksu_syms.call_usermodehelper_setup = (void *)ksu_lookup_name_unrestricted("call_usermodehelper_setup");
    ksu_syms.call_usermodehelper_exec = (void *)ksu_lookup_name_unrestricted("call_usermodehelper_exec");

    if (!ksu_syms.fsnotify_alloc_group) {
        pr_warn("ksu: fsnotify symbols not found, module may fail to load\n");

        // fsnotify is critical for observer, so consider it missing
        missing++;
    }

    pr_info("ksu: symbol resolution complete, %d critical missing\n", missing);
    
    return missing > 0 ? -ENOENT : 0;
}
EXPORT_SYMBOL(ksu_init_symbols);
