#ifndef __KSU_UTIL_H
#define __KSU_UTIL_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/fdtable.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define ksu_close_fd close_fd
#else
#define ksu_close_fd ksys_close
#endif

#ifndef preempt_enable_no_resched_notrace
#define preempt_enable_no_resched_notrace()                                    \
    do {                                                                       \
        barrier();                                                             \
        __preempt_count_dec();                                                 \
    } while (0)
#endif

#ifndef preempt_disable_notrace
#define preempt_disable_notrace()                                              \
    do {                                                                       \
        __preempt_count_inc();                                                 \
        barrier();                                                             \
    } while (0)
#endif

bool try_set_access_flag(unsigned long addr);

#endif
