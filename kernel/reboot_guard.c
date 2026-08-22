/*
 * WP4: Universal Reboot Interception ("Reboot Guard")
 *
 * Two layers:
 * - Layer 2: sys.powerctl interception (sendmsg/sendto hook) — LOG-ONLY by default
 * - Layer 3: reboot(2) backstop in existing kprobe
 *
 * The guard converts normal reboots into soft reboots to preserve
 * temp-root sessions. It NEVER intercepts:
 * - PID 1's reboot(2) — init already completed teardown, must pass through
 * - shutdown, recovery, bootloader, fastboot, download, edl commands
 *
 * Default: armed only in late-load/temp-root mode.
 * Feature system integration allows runtime get/set via Manager.
 */

#include <linux/atomic.h>
#include <linux/printk.h>
#include <linux/types.h>

#include "reboot_guard.h"
#include "policy/feature.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"

/* Guard state */
static atomic_t guard_armed = ATOMIC_INIT(0);
static atomic_t soft_reboot_running = ATOMIC_INIT(0);
static atomic_t real_reboot_once_flag = ATOMIC_INIT(0);

/*
 * Layer 2 mode:
 * 0 = disabled (not hooked)
 * 1 = log-only (observe mode — hook installed, writes logged, never blocked)
 * 2 = armed (swallow sys.powerctl writes for reboot commands)
 *
 * Rollout order: 0 → 1 (validate wire format) → 2 (arm swallow)
 * Default: 1 (log-only) when guard is armed in late-load mode.
 */
static int layer2_mode = 1;

/* Feature handler integration */
static int reboot_guard_feature_get(u64 *value)
{
	*value = (u64)atomic_read(&guard_armed);
	return 0;
}

static int reboot_guard_feature_set(u64 value)
{
	bool enable = value != 0;
	atomic_set(&guard_armed, enable ? 1 : 0);
	pr_info("ksu: reboot guard %s\n", enable ? "armed" : "disarmed");
	return 0;
}

static const struct ksu_feature_handler reboot_guard_handler = {
	.feature_id = KSU_FEATURE_SOFT_REBOOT_GUARD,
	.name = "soft_reboot_guard",
	.get_handler = reboot_guard_feature_get,
	.set_handler = reboot_guard_feature_set,
};

/* Public API */

bool ksu_reboot_guard_armed(void)
{
	return atomic_read(&guard_armed) != 0;
}

void ksu_reboot_guard_set(bool armed)
{
	atomic_set(&guard_armed, armed ? 1 : 0);
}

bool ksu_soft_reboot_in_progress(void)
{
	return atomic_read(&soft_reboot_running) != 0;
}

void ksu_set_soft_reboot_in_progress(bool val)
{
	atomic_set(&soft_reboot_running, val ? 1 : 0);
}

/*
 * Layer 3: Check if a reboot(2) call should be intercepted.
 *
 * Rules:
 * - Guard must be armed
 * - PID 1 always passes through (init's reboot after full teardown;
 *   swallowing would cause abort() -> panic)
 * - LINUX_REBOOT_CMD_RESTART, LINUX_REBOOT_CMD_RESTART2 → intercept
 * - Other commands (halt, power_off, kexec) → pass through
 *
 * Returns true if the reboot should be intercepted (swallowed).
 */
bool ksu_should_intercept_reboot(int cmd, pid_t caller_pid)
{
	if (!ksu_reboot_guard_armed()) {
		return false;
	}

	/* One-shot escape hatch: let one reboot through */
	if (atomic_cmpxchg(&real_reboot_once_flag, 1, 0) == 1) {
		pr_info("ksu: reboot guard: one-shot pass-through (REAL_REBOOT_ONCE)\n");
		return false;
	}

	/* PID 1 ALWAYS passes through — violating this is fatal */
	if (caller_pid == 1) {
		pr_info("ksu: reboot guard: PID 1 reboot, passing through\n");
		return false;
	}

	/* Only intercept restart commands */
	switch (cmd) {
	case 0x01234567: /* LINUX_REBOOT_CMD_RESTART */
	case 0xA1B2C3D4: /* LINUX_REBOOT_CMD_RESTART2 */
		/* Debounce: don't kick if already running */
		if (ksu_soft_reboot_in_progress()) {
			pr_info("ksu: reboot guard: soft reboot already in progress, ignoring\n");
			return true;
		}
		pr_info("ksu: reboot guard: intercepting reboot from PID %d, kicking soft reboot\n",
			caller_pid);
		return true;

	default:
		/* halt, power_off, kexec, etc. — pass through */
		return false;
	}
}

/* Escape hatch: disarm for one reboot, then rearm automatically */
void ksu_real_reboot_once(void)
{
	atomic_set(&real_reboot_once_flag, 1);
	pr_info("ksu: reboot guard: armed one-shot pass-through\n");
}

/* Init/exit */
void ksu_reboot_guard_init(void)
{
	if (ksu_register_feature_handler(&reboot_guard_handler)) {
		pr_err("ksu: failed to register reboot guard feature handler\n");
	}
	pr_info("ksu: reboot guard initialized (layer2_mode=%d)\n", layer2_mode);
}

void ksu_reboot_guard_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SOFT_REBOOT_GUARD);
}
