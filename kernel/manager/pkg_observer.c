#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/fsnotify_backend.h>
#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/version.h>
#include "klog.h" // IWYU pragma: keep
#include "manager/throne_tracker.h"
#include "ksu_kallsyms.h"

#define MASK_SYSTEM (FS_CREATE | FS_MOVE | FS_EVENT_ON_CHILD)

struct watch_dir {
	const char *path;
	u32 mask;
	struct path kpath;
	struct inode *inode;
	struct fsnotify_mark *mark;
};

static struct fsnotify_group *g;

static int ksu_handle_inode_event(struct fsnotify_mark *mark, u32 mask,
                                  struct inode *inode, struct inode *dir,
                                  const struct qstr *file_name, u32 cookie)
{
    if (!file_name)
        return 0;
    if (mask & FS_ISDIR)
        return 0;
    if (file_name->len == 13 && !memcmp(file_name->name, "packages.list", 13)) {
        pr_info("packages.list detected: %d\n", mask);
        track_throne(false);
    }
    return 0;
}

static const struct fsnotify_ops ksu_ops = {
	.handle_inode_event = ksu_handle_inode_event,
};

static inline int ksu_fsnotify_add_inode_mark(struct fsnotify_mark *mark, struct inode *inode, int allow_dups)
{
    if (!ksu_syms.fsnotify_add_mark)
        return -ENOSYS;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
    return ksu_syms.fsnotify_add_mark(mark, (struct fsnotify_mark_connector __rcu **)&inode->i_fsnotify_marks, FSNOTIFY_OBJ_TYPE_INODE, allow_dups, NULL);
#else
    return ((int (*)(struct fsnotify_mark *, void *, unsigned int, int))ksu_syms.fsnotify_add_mark)(mark, &inode->i_fsnotify_marks, FSNOTIFY_OBJ_TYPE_INODE, allow_dups);
#endif
}

static int add_mark_on_inode(struct inode *inode, u32 mask,
                             struct fsnotify_mark **out)
{
	struct fsnotify_mark *m;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	if (ksu_syms.fsnotify_init_mark)
		ksu_syms.fsnotify_init_mark(m, g);
	m->mask = mask;

	if (ksu_fsnotify_add_inode_mark(m, inode, 0)) {
		if (ksu_syms.fsnotify_put_mark)
			ksu_syms.fsnotify_put_mark(m);
		return -EINVAL;
	}
	*out = m;
	return 0;
}

static int watch_one_dir(struct watch_dir *wd)
{
	int ret = kern_path(wd->path, LOOKUP_FOLLOW, &wd->kpath);
	if (ret) {
		pr_info("path not ready: %s (%d)\n", wd->path, ret);
		return ret;
	}
	wd->inode = d_inode(wd->kpath.dentry);
	ihold(wd->inode);

	ret = add_mark_on_inode(wd->inode, wd->mask, &wd->mark);
	if (ret) {
		pr_err("Add mark failed for %s (%d)\n", wd->path, ret);
		path_put(&wd->kpath);
		iput(wd->inode);
		wd->inode = NULL;
		return ret;
	}
	pr_info("watching %s\n", wd->path);
	return 0;
}

static void unwatch_one_dir(struct watch_dir *wd)
{
	if (wd->mark) {
		if (ksu_syms.fsnotify_destroy_mark)
			ksu_syms.fsnotify_destroy_mark(wd->mark, g);
		else if (ksu_syms.fsnotify_put_mark)
			ksu_syms.fsnotify_put_mark(wd->mark);
		wd->mark = NULL;
	}
	if (wd->inode) {
		iput(wd->inode);
		wd->inode = NULL;
	}
	if (wd->kpath.dentry) {
		path_put(&wd->kpath);
		memset(&wd->kpath, 0, sizeof(wd->kpath));
	}
}

static struct watch_dir g_watch = { .path = "/data/system",
                                    .mask = MASK_SYSTEM };

int ksu_observer_init(void)
{
	int ret = 0;

	if (g) {
		pr_info("observer already initialized\n");
		return 0;
	}

	if (!ksu_syms.fsnotify_alloc_group) {
		pr_warn("fsnotify_alloc_group not resolved\n");
		return -ENOSYS;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	g = ((struct fsnotify_group *(*)(const struct fsnotify_ops *, int))ksu_syms.fsnotify_alloc_group)(&ksu_ops, 0);
#else
	g = ((struct fsnotify_group *(*)(const struct fsnotify_ops *))ksu_syms.fsnotify_alloc_group)(&ksu_ops);
#endif
	if (IS_ERR(g))
		return PTR_ERR(g);

	ret = watch_one_dir(&g_watch);
	pr_info("observer init done\n");
	return 0;
}

void ksu_observer_exit(void)
{
	unwatch_one_dir(&g_watch);
	if (g && ksu_syms.fsnotify_put_group)
		ksu_syms.fsnotify_put_group(g);
	g = NULL;
	pr_info("observer exit done\n");
}
