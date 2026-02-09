/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelSU-Next - Kallsyms-based symbol resolution
 * Ported from kpatch_lkm for LKM compatibility
 */

#ifndef _KSU_KALLSYMS_H
#define _KSU_KALLSYMS_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/mm.h>

/* CFI bypass support */
#ifdef CONFIG_CFI_CLANG
#define KSU_NO_CFI __nocfi
#else
#define KSU_NO_CFI
#endif

/* ARM64 instruction constants */
#define ARM64_NOP       0xD503201F
#define ARM64_RET       0xD65F03C0
#define ARM64_BTI_C     0xD503245F

/* Forward declarations for SELinux types */
struct selinux_state;
struct selinux_policy;
struct avtab;
struct avtab_key;
struct avtab_node;
struct avtab_datum;
struct avtab_extended_perms;
struct ebitmap;
struct symtab;
struct policydb;
struct filename_trans_key;
struct filename_trans_datum;
struct path;
struct callback_head;
struct task_struct;
struct cred;
struct pt_regs;
struct super_block;
struct fsnotify_group;
struct fsnotify_ops;
struct fsnotify_mark;
struct fsnotify_mark;
struct fsnotify_mark_connector;
struct fsnotify_mark_connector;
struct subprocess_info;
struct nsproxy;



/*
 * Resolved kernel symbols structure
 * All non-exported symbols used by KernelSU-Next
 */
struct ksu_symbols {
    /* Page table base */
    unsigned long swapper_pg_dir;
    
    /* Instruction patching */
    int (*aarch64_insn_write)(void *addr, u32 insn);
    
    /* SELinux state */
    struct selinux_state *selinux_state;
    void *selinux_blob_sizes;
    
    /* SELinux policy functions */
    void (*selinux_status_update_policyload)(int seqno);
    void (*selnl_notify_policyload)(u32 seqno);
    void (*avc_ss_reset)(u32 seqno);
    
    /* AVtab functions */
    struct avtab_node *(*avtab_search_node)(struct avtab *h, struct avtab_key *key);
    struct avtab_node *(*avtab_search_node_next)(struct avtab_node *node, int specified);
    struct avtab_node *(*avtab_insert_nonunique)(struct avtab *h, struct avtab_key *key, 
                                                  struct avtab_datum *datum);
    
    /* Ebitmap functions */
    int (*ebitmap_get_bit)(struct ebitmap *e, unsigned long bit);
    int (*ebitmap_set_bit)(struct ebitmap *e, unsigned long bit, int value);
    
    /* Symtab functions */
    void *(*symtab_search)(struct symtab *s, const char *name);
    int (*symtab_insert)(struct symtab *s, char *name, void *datum);
    int (*__hashtab_insert)(void *h, void *key, void *datum, void *key_params);
    
    /* Policydb functions */
    struct filename_trans_datum *(*policydb_filenametr_search)(struct policydb *p,
                                                                struct filename_trans_key *key);
    
    /* Namespace operations */
    int (*path_mount)(const char *dev_name, struct path *path, const char *type,
                      unsigned long flags, void *data);
    int (*path_umount)(struct path *path, int flags);
    void *mntns_operations;  /* const struct proc_ns_operations * */
    int (*ns_get_path)(struct path *path, struct task_struct *task, void *ns_ops);
    
    /* Syscall/process helpers */
    long (*ksys_unshare)(unsigned long unshare_flags);
    long (*__arm64_sys_setns)(const struct pt_regs *regs);
    void (*set_fs_pwd)(void *fs, const struct path *path);
    void (*set_fs_root)(void *fs, const struct path *path);
    struct task_struct *(*find_task_by_vpid)(pid_t nr);
    int (*switch_task_namespaces)(struct task_struct *tsk, struct nsproxy *new);
    
    /* Tracepoint */
    void *__tracepoint_sys_enter;
    
    /* String/memory helpers */
    long (*strncpy_from_user_nofault)(char *dst, const void __user *src, long count);
    
    /* Task work */
    int (*task_work_add)(struct task_struct *task, struct callback_head *work, int notify);
    
    /* Seccomp */
    void (*seccomp_filter_release)(struct task_struct *task);
    
    /* PTE helpers */
    int (*ptep_set_access_flags)(struct vm_area_struct *vma, unsigned long address, pte_t *pte,
                                  pte_t entry, int dirty);
    
    /* Filesystem */
    void (*ext4_unregister_sysfs)(struct super_block *sb);
    
    /* UTS */
    void *uts_sem;  /* struct rw_semaphore * */
    
    /* Security */
    int (*security_inode_init_security_anon)(void *inode, const void *name,
                                              const void *context_inode);
    
    /* Credentials */
    struct cred *(*prepare_creds)(void);
    int (*commit_creds)(struct cred *new);
    struct cred *(*prepare_kernel_cred)(struct task_struct *task);
    void (*__put_cred)(struct cred *cred);
    void (*abort_creds)(struct cred *new);
    const struct cred *(*get_task_cred)(struct task_struct *task);
    const struct cred *(*override_creds)(const struct cred *new);
    void (*revert_creds)(const struct cred *old);
    
    /* Groups */
    struct group_info *(*groups_alloc)(int gidsetsize);
    void (*groups_free)(struct group_info *group_info);
    void (*groups_sort)(struct group_info *group_info);
    int (*set_groups)(struct cred *new, struct group_info *group_info);
    
    /* Filesystem/Path */
    struct file *(*alloc_file_pseudo)(struct inode *inode, struct vfsmount *mnt,
                        const char *name, int flags, const struct file_operations *fops);
    struct file *(*dentry_open)(const struct path *path, int flags, const struct cred *cred);
    int (*iterate_dir)(struct file *file, struct dir_context *ctx);
    void (*path_get)(const struct path *path);
    ssize_t (*kernel_read)(struct file *file, void *buf, size_t count, loff_t *pos);
    ssize_t (*kernel_write)(struct file *file, const void *buf, size_t count, loff_t *pos);

    /* Security */
    void (*security_release_secctx)(char *secdata, u32 seclen);
    int (*security_secctx_to_secid)(const char *secdata, u32 seclen, u32 *secid);
    int (*security_secid_to_secctx)(u32 secid, char **secdata, u32 *seclen);

    /* Memory/User copy (nofault wrappers) */
    long (*copy_from_user_nofault)(void *dst, const void __user *src, size_t size);
    long (*copy_to_user_nofault)(void __user *dst, const void *src, size_t size);

    /* Memory protection (optional) */
    int (*set_memory_rw)(unsigned long addr, int numpages);
    int (*set_memory_ro)(unsigned long addr, int numpages);
    int (*set_memory_x)(unsigned long addr, int numpages);
    int (*set_memory_nx)(unsigned long addr, int numpages);

    /* fsnotify functions */
    void *fsnotify_alloc_group;
    void (*fsnotify_put_group)(struct fsnotify_group *group);
    void (*fsnotify_init_mark)(struct fsnotify_mark *mark, struct fsnotify_group *group);
    void (*fsnotify_destroy_mark)(struct fsnotify_mark *mark, struct fsnotify_group *group);
    int (*fsnotify_add_mark)(struct fsnotify_mark *mark, struct fsnotify_mark_connector __rcu **connp,
                             unsigned int type, int allow_dups, __kernel_fsid_t *fsid);
    void (*fsnotify_put_mark)(struct fsnotify_mark *mark);

    /* UMH functions for LKM late init */
    struct subprocess_info *(*call_usermodehelper_setup)(const char *path, char **argv,
                                                         char **envp, gfp_t gfp_mask,
                                                         int (*init)(struct subprocess_info *info, struct cred *new),
                                                         void (*cleanup)(struct subprocess_info *info),
                                                         void *data);
    int (*call_usermodehelper_exec)(struct subprocess_info *info, int wait);
};


/* Global symbol table */
extern struct ksu_symbols ksu_syms;

/* Symbol resolution functions */
unsigned long ksu_kallsyms_lookup_name(const char *name);
unsigned long ksu_lookup_name_unrestricted(const char *name);
int ksu_init_symbols(void);

/* CFI bypass */
int ksu_early_cfi_bypass(void);

/* PTE manipulation */
int ksu_pte_init(unsigned long swapper_addr);
int ksu_make_rw_pte(unsigned long addr);
int ksu_make_exec_pte(unsigned long addr);
int ksu_write_kernel_protected(unsigned long addr, unsigned long value);

/* Inline asm call wrapper for CFI bypass */
static inline long ksu_call_func_cfi_bypass(void *fn, long arg0, long arg1)
{
    long ret;
    asm volatile(
        "mov x0, %1\n"
        "mov x1, %2\n"
        "blr %3\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(arg0), "r"(arg1), "r"(fn)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17", "x30", "memory", "cc"
    );
    return ret;
}

static inline void ksu_put_cred(const struct cred *cred)
{
    struct cred *non_const_cred = (struct cred *)cred;
    if (non_const_cred && atomic_dec_and_test(&non_const_cred->usage))
        ksu_syms.__put_cred(non_const_cred);
}

#endif /* _KSU_KALLSYMS_H */
