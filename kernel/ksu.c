#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/workqueue.h>

#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "throne_tracker.h"
#include "syscall_hook_manager.h"
#include "ksud.h"
#include "supercalls.h"
#include "ksu.h"
#include "file_wrapper.h"
#include "ksu_kallsyms.h"
#include "manager.h"

struct cred *ksu_cred;

static int manager_uid = -1;
module_param(manager_uid, int, 0644);
MODULE_PARM_DESC(manager_uid, "KernelSU Manager UID");

int __init kernelsu_init(void)
{
	int ret;

	pr_info("kernelsu: initializing KernelSU-Next LKM\n");

	/* Step 1: Early CFI bypass - MUST be first before any indirect calls */
	ret = ksu_early_cfi_bypass();
	if (ret) {
		pr_warn("kernelsu: early CFI bypass failed: %d (may not be needed)\n", ret);
		/* Continue - CFI may not be enabled */
	}

	/* Step 2: Resolve all kernel symbols */
	ret = ksu_init_symbols();
	if (ret) {
		pr_err("kernelsu: symbol resolution failed: %d\n", ret);
		return ret;
	}

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

    ksu_cred = ksu_syms.prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
    }

	ksu_feature_init();

	ksu_supercalls_init();

	ksu_syscall_hook_manager_init();

	ksu_allowlist_init();

	ksu_throne_tracker_init();

	ksu_ksud_init();

    ksu_file_wrapper_init();

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
    /* Trigger late init specific for LKM */
    ksu_lkm_late_init();

    if (manager_uid != -1) {
        pr_info("kernelsu: manual manager_uid set to %d\n", manager_uid);
        ksu_set_manager_appid(manager_uid % 100000);
    } else {
        pr_info("kernelsu: manager_uid not set, attempting auto-detection\n");
        track_throne(false);
    }
#endif
	return 0;
}


extern void ksu_observer_exit(void);
void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_throne_tracker_exit();

	ksu_observer_exit();

	ksu_ksud_exit();

#ifdef MODULE
    ksu_lkm_exit();
#endif

	ksu_syscall_hook_manager_exit();


	ksu_supercalls_exit();

	ksu_feature_exit();

	if (ksu_cred) {
		ksu_put_cred(ksu_cred);
	}
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
