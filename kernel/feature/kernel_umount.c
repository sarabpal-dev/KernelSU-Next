#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <uapi/linux/mount.h>

#include "feature/kernel_umount.h"
#include "klog.h" // IWYU pragma: keep
#include "policy/allowlist.h"
#include "selinux/selinux.h"
#include "policy/feature.h"
#include "runtime/ksud_boot.h"
#include "ksu_kallsyms.h"
#include "ksu.h"

static bool ksu_kernel_umount_enabled = true;

static int kernel_umount_feature_get(u64 *value)
{
	*value = ksu_kernel_umount_enabled ? 1 : 0;
	return 0;
}

static int kernel_umount_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_kernel_umount_enabled = enable;
	pr_info("kernel_umount: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
	.feature_id = KSU_FEATURE_KERNEL_UMOUNT,
	.name = "kernel_umount",
	.get_handler = kernel_umount_feature_get,
	.set_handler = kernel_umount_feature_set,
};

#define SYSTEM_UID 1000

static void isolate_system_server_mounts(void)
{
    struct path root_path;

    /* Make system_server mount namespace private (break master/slave propagation) */
    if (kern_path("/", 0, &root_path) == 0) {
        if (ksu_syms.path_mount)
            ksu_syms.path_mount(NULL, &root_path, NULL, MS_PRIVATE | MS_REC, NULL);
        path_put(&root_path);
    }
}

static void ksu_umount_mnt(const char *mnt, struct path *path, int flags)
{
	int err = ksu_syms.path_umount ? ksu_syms.path_umount(path, flags) : -ENOSYS;
	if (err) {
		pr_info("umount %s failed: %d\n", mnt, err);
	}
}

static void try_umount(const char *mnt, int flags)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		// it is not root mountpoint, maybe umounted by others already.
		path_put(&path);
		return;
	}

	ksu_umount_mnt(mnt, &path, flags);
}

struct umount_tw {
	struct callback_head cb;
};

int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
	bool is_system_server = (new_uid == SYSTEM_UID);

	// if there isn't any module mounted, just ignore it (unless system_server)!
	if (!is_system_server && !ksu_module_mounted) {
		return 0;
	}

	if (!ksu_kernel_umount_enabled) {
		return 0;
	}

	if (!ksu_cred) {
		return 0;
	}

	// There are 6 scenarios:
	// 1. Normal app: zygote -> appuid
	// 2. Isolated process forked from zygote: zygote -> isolated_process
	// 3. App zygote forked from zygote: zygote -> appuid
	// 4. Webview zygote forked from zygote: zygote -> WEBVIEW_ZYGOTE_UID (no need to handle, app cannot run custom code)
	// 5. Isolated process forked from app zygote: appuid -> isolated_process (already handled by 3)
	// 6. system_server forked from zygote: zygote -> 1000 (PackageManager mount isolation)
	if (!is_appuid(new_uid) && !is_isolated_process(new_uid) && !is_system_server) {
		return 0;
	}

	if (!is_system_server && !ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid)) {
		return 0;
	}

	// check old process's selinux context, if it is not zygote, ignore it!
	// because some su apps may setuid to untrusted_app but they are in global mount namespace
	// when we umount for such process, that is a disaster!
	// also handle case 4 and 5
	bool is_zygote_child = is_zygote(current_cred());
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n", current->pid);
		return 0;
	}
	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

	const struct cred *saved = ksu_syms.override_creds ? ksu_syms.override_creds(ksu_cred) : NULL;

	if (is_system_server) {
		isolate_system_server_mounts();
	}

	struct mount_entry *entry;
	down_read(&mount_list_lock);
	list_for_each_entry (entry, &mount_list, list) {
		pr_info("%s: unmounting: %s flags: 0x%x\n", __func__, entry->umountable, entry->flags);
		try_umount(entry->umountable, entry->flags);
	}
	up_read(&mount_list_lock);

	if (saved && ksu_syms.revert_creds)
		ksu_syms.revert_creds(saved);

	return 0;
}

/*
 * WP3: Force-umount a single mountpoint.
 * Resolves the path and detaches the mount using MNT_DETACH.
 * Called from FORCE_UMOUNT ioctl handler (already in root context).
 */
int ksu_force_umount_path(const char *mnt_path, int flags)
{
	struct path path;
	int err;

	if (!mnt_path || !*mnt_path) {
		pr_err("ksu: force_umount: empty path\n");
		return -EINVAL;
	}

	err = kern_path(mnt_path, 0, &path);
	if (err) {
		pr_warn("ksu: force_umount: path lookup failed for %s: %d\n", mnt_path, err);
		return err;
	}

	/* Only umount if it's actually a mount root (not a subdirectory) */
	if (path.dentry != path.mnt->mnt_root) {
		pr_info("ksu: force_umount: %s is not a mountpoint\n", mnt_path);
		path_put(&path);
		return -EINVAL;
	}

	/* Use MNT_DETACH as default if no flags specified — handles busy mounts */
	if (!flags)
		flags = MNT_DETACH;

	pr_info("ksu: force_umount: detaching %s, flags=0x%x\n", mnt_path, flags);
	ksu_umount_mnt(mnt_path, &path, flags);

	return 0;
}

void __init ksu_kernel_umount_init(void)
{
	if (ksu_register_feature_handler(&kernel_umount_handler)) {
		pr_err("Failed to register kernel_umount feature handler\n");
	}
}

void __exit ksu_kernel_umount_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
}
