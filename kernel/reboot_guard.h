#ifndef __KSU_H_REBOOT_GUARD
#define __KSU_H_REBOOT_GUARD

#include <linux/types.h>

/*
 * WP4: Universal Reboot Interception ("Reboot Guard")
 *
 * Layer 2: sys.powerctl interception via sendmsg/sendto hook
 * Layer 3: reboot(2) backstop via existing kprobe
 *
 * Default: armed only in late-load/temp-root mode.
 */

/* Guard state queries */
bool ksu_reboot_guard_armed(void);
void ksu_reboot_guard_set(bool armed);

/* Layer 3: Check if a reboot(2) should be intercepted */
bool ksu_should_intercept_reboot(int cmd, pid_t caller_pid);

/* Escape hatch: disarm for one reboot cycle */
void ksu_real_reboot_once(void);

/* Debounce: check if soft reboot is already in progress */
bool ksu_soft_reboot_in_progress(void);
void ksu_set_soft_reboot_in_progress(bool val);

/* Init/exit */
void ksu_reboot_guard_init(void);
void ksu_reboot_guard_exit(void);

#endif /* __KSU_H_REBOOT_GUARD */
