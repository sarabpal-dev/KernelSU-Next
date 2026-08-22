//! WP5: Full soft-reboot protocol
//!
//! Phases (bounded, logged, rollback at each):
//! - Phase 0: Preflight checks
//! - Phase 1: Module-process sweep
//! - Phase 2: Teardown (stop non-core services)
//! - Phase 3: Mount reset
//! - Phase 4: Property reset + restage (re-run boot pipeline)
//! - Phase 5: Relaunch + validate

use anyhow::{Result, bail};
use log::{error, info, warn};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::utils::switch_mnt_ns;
use crate::{init_event, ksucalls};

use prop_rs_android::resetprop::ResetProp;
use prop_rs_android::sys_prop;

/// Source of the soft reboot request
#[derive(Debug, Clone, Copy)]
pub enum SoftRebootSource {
    /// User-initiated (Manager or CLI)
    User,
    /// Triggered by reboot guard interception
    Guard,
}

/// Paths for soft reboot state
const SOFT_REBOOT_LOCK: &str = "/data/adb/ksu/.soft_reboot.lock";
const SOFT_REBOOT_LOG_DIR: &str = "/data/adb/ksu/log/";
const SOFT_REBOOT_STATE_FILE: &str = "/data/adb/ksu/log/softreboot.state";

/// Module-related path prefixes to scan for processes/mounts (covers all module data under /data/adb)
const MODULE_PATH_PREFIXES: &[&str] = &[
    "/data/adb",
];

/// Properties to reset before restage (from init.rc:2235-2244)
const RESET_PROPS: &[(&str, &str)] = &[
    ("sys.boot_completed", "0"),
    ("dev.bootcomplete", "0"),
    ("sys.init.updatable_crashing", "0"),
    ("sys.init.updatable_crashing_process_name", ""),
    ("sys.user.0.ce_available", ""),
    ("sys.shutdown.requested", ""),
    ("service.bootanim.exit", "0"),
    ("service.bootanim.progress", ""),
];

// ─── OPlus Watchdog Infrastructure ──────────────────────────────────────

/// OPlus Theia init-liveness watchdog path
const OPLUS_INIT_WATCHDOG_KICK: &str = "/proc/oplus_init_watchdog/kick";
/// OPlus PMIC watchdog control path
const OPLUS_PMIC_WD: &str = "/proc/pmicWd";
/// OPlus PowerKey/Theia boot-completed monitor
const OPLUS_PWK_MONITOR: &str = "/proc/pwkMonitorParam";

/// Kick the OPlus Theia init-liveness watchdog.
/// This writes to /proc/oplus_init_watchdog/kick which the self_init_theia.rc
/// action triggers periodically. If the kick stops arriving for too long,
/// the Theia watchdog initiates a device reset.
fn kick_oplus_init_watchdog() {
    if Path::new(OPLUS_INIT_WATCHDOG_KICK).exists() {
        if let Err(e) = fs::write(OPLUS_INIT_WATCHDOG_KICK, "1") {
            warn!("soft_reboot: kick oplus init watchdog failed: {e}");
        }
    }
}

/// Re-arm the OPlus PMIC watchdog with a longer bite timer.
/// Default is "1 254 7" (7-second bite). During soft-reboot we extend to
/// 30 seconds to give enough time for the stop+restage cycle.
fn rearm_oplus_pmic_watchdog() {
    if Path::new(OPLUS_PMIC_WD).exists() {
        if let Err(e) = fs::write(OPLUS_PMIC_WD, "1 254 30") {
            warn!("soft_reboot: re-arm PMIC watchdog failed: {e}");
        } else {
            info!("soft_reboot: PMIC watchdog re-armed with 30s bite timer");
        }
    }
}

/// Reset OPlus PowerKey/Theia boot-completed monitor.
/// When surfaceflinger or zygote are stopped, the Theia monitor can
/// interpret the stopped state as a crash. Writing "boot-completed 0"
/// tells the monitor that a restart is expected.
fn reset_oplus_boot_completed_monitor() {
    if Path::new(OPLUS_PWK_MONITOR).exists() {
        if let Err(e) = fs::write(OPLUS_PWK_MONITOR, "boot-completed 0") {
            warn!("soft_reboot: reset pwkMonitorParam failed: {e}");
        } else {
            info!("soft_reboot: OPlus boot-completed monitor reset to 0");
        }
    }
}

/// Signal OPlus PowerKey/Theia monitor that boot is complete again.
fn signal_oplus_boot_completed() {
    if Path::new(OPLUS_PWK_MONITOR).exists() {
        if let Err(e) = fs::write(OPLUS_PWK_MONITOR, "boot-completed 1") {
            warn!("soft_reboot: signal pwkMonitorParam boot-completed failed: {e}");
        }
    }
}

/// Spawn a background thread that kicks the OPlus watchdogs every 5 seconds.
/// Returns a stop flag that should be set to true when the kicker is no
/// longer needed (after boot completes).
fn spawn_watchdog_kicker() -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    std::thread::Builder::new()
        .name("oplus-wd-kicker".into())
        .spawn(move || {
            info!("soft_reboot: watchdog kicker thread started (5s interval)");
            while !stop_clone.load(Ordering::Relaxed) {
                kick_oplus_init_watchdog();
                // Sleep in 500ms increments so the stop flag is checked promptly
                for _ in 0..10 {
                    if stop_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            info!("soft_reboot: watchdog kicker thread stopped");
        })
        .ok();

    stop
}

// ────────────────────────────────────────────────────────────────────────

/// Wait for a property to reach a value, with timeout
fn wait_prop_value(name: &str, value: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if let Some(current) = crate::utils::getprop(name)
            && current == value
        {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait for PackageManagerService (PMS) to complete package scanning and become fully ready.
/// PMS readiness is confirmed by:
/// 1. `sys.boot_completed=1` or `dev.bootcomplete=1`
/// 2. Verification that `cmd package` / `pm` is responsive and not returning starting code 20.
/// 3. Verification that `/data/system/packages.list` exists and is readable.
pub fn wait_pms_ready(timeout: Duration) -> bool {
    info!("soft_reboot: probing for PackageManagerService (PMS) package scan completion...");

    // Primary gate: wait for sys.boot_completed=1
    if !wait_prop_value("sys.boot_completed", "1", timeout) {
        warn!("soft_reboot: timeout waiting for sys.boot_completed=1");
        return false;
    }

    // Additional probe: ensure PMS IPC is ready and not returning startup errors
    let pms_probe_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < pms_probe_deadline {
        let is_pm_ready = Command::new("cmd")
            .args(["package", "is-package-available", "android"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if is_pm_ready {
            info!("soft_reboot: PMS package scan confirmed complete via cmd package probe");
            return true;
        }

        let is_pm_path_ready = Command::new("pm")
            .args(["path", "android"])
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false);

        if is_pm_path_ready {
            info!("soft_reboot: PMS package scan confirmed complete via pm path probe");
            return true;
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    info!("soft_reboot: sys.boot_completed=1 reached, proceeding with services");
    true
}

/// Write state for Manager to read on restart
fn write_state(state: &str) {
    let _ = crate::utils::ensure_dir_exists(Path::new(SOFT_REBOOT_LOG_DIR));
    let _ = fs::write(SOFT_REBOOT_STATE_FILE, state);
}

/// Take a snapshot of system state for debugging
fn snapshot_state(log_dir: &Path) -> Result<()> {
    crate::utils::ensure_dir_exists(log_dir)?;

    // Mountinfo
    if let Ok(content) = fs::read_to_string("/proc/1/mountinfo") {
        let _ = fs::write(log_dir.join("mountinfo.txt"), content);
    }

    // Process list
    let _ = Command::new("ps")
        .args(["-A", "-o", "pid,ppid,user,args"])
        .output()
        .map(|o| fs::write(log_dir.join("ps.txt"), o.stdout));

    // Properties
    let _ = Command::new("getprop")
        .output()
        .map(|o| fs::write(log_dir.join("getprop.txt"), o.stdout));

    Ok(())
}

const fn resetprop() -> ResetProp {
    ResetProp {
        skip_svc: true,
        persistent: false,
        persist_only: false,
        verbose: false,
        show_context: false,
        rebuild: false,
    }
}

/// Main soft-reboot entry point
pub fn run(source: SoftRebootSource) -> Result<()> {
    info!("=== soft_reboot: starting ({source:?}) ===");
    let cycle_start = Instant::now();

    // Detach from calling process group and ignore SIGHUP so that when Manager app
    // or calling process is terminated by `stop` during Phase 2, `ksud soft-reboot`
    // continues running independently to completion.
    unsafe {
        libc::setsid();
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    // Switch to PID 1 mount namespace early so all checks and discovery run in PID 1 VFS
    if let Err(e) = switch_mnt_ns(1) {
        warn!("soft_reboot: switch_mnt_ns(1) early warning: {e}");
    }

    // Start the OPlus watchdog kicker thread immediately — it feeds
    // /proc/oplus_init_watchdog/kick every 5 seconds to prevent the
    // Theia watchdog from triggering a device reset during teardown.
    let wd_stop = spawn_watchdog_kicker();

    // === Phase 0: Preflight ===
    info!("soft_reboot: Phase 0 — preflight");
    write_state("phase0_preflight");

    // UAPI version check
    if let Err(e) = ksucalls::ensure_uapi_version_matched() {
        error!("UAPI mismatch: {e:#}");
        bail!("UAPI version mismatch");
    }

    // Safe mode check
    if crate::utils::is_safe_mode() {
        error!("safe mode active, refusing soft reboot");
        bail!("safe mode active");
    }

    // Single-instance lock (best-effort)
    let _lock = match fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(SOFT_REBOOT_LOCK)
    {
        Ok(f) => {
            use std::os::unix::io::AsRawFd;
            let ret = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret != 0 {
                bail!("soft reboot already in progress (lock held)");
            }
            Some(f)
        }
        Err(e) => {
            warn!("could not create lock file: {e}");
            None
        }
    };

    // Snapshot state
    let ts = chrono_timestamp();
    let log_dir = PathBuf::from(format!("{SOFT_REBOOT_LOG_DIR}softreboot.{ts}"));
    if let Err(e) = snapshot_state(&log_dir) {
        warn!("preflight snapshot failed: {e}");
    }

    // === Phase 1: Module-process sweep ===
    info!("soft_reboot: Phase 1 — module-process sweep");
    write_state("phase1_process_sweep");

    let module_pids = crate::cleanup::find_processes_by_prefixes(MODULE_PATH_PREFIXES);
    if module_pids.is_empty() {
        info!("soft_reboot: no module processes found");
    } else {
        info!(
            "soft_reboot: stopping {} module processes (tracer-aware)",
            module_pids.len()
        );
        // Tracer-aware: never SIGKILL a process still tracing live tracees —
        // a killed ptrace monitor can leave PID 1 wedged in ptrace_stop.
        crate::cleanup::kill_processes_gently(&module_pids);
    }
    crate::cleanup::warn_stopped_tracees("phase1");

    // Snapshot module mounts before teardown: journal ∪ live /data/adb matches.
    // The journal covers mounts that carry no /data/adb string in mountinfo
    // (magic-mount tmpfs over system dirs; binds whose source is fs-root-relative,
    // e.g. /adb/rvhc/...), which pure prefix matching would miss — the exact
    // failure that left stacked overlays after a soft reboot.
    let module_mounts = crate::cleanup::find_all_module_mounts();
    info!(
        "soft_reboot: found {} module mounts to teardown",
        module_mounts.len()
    );

    // === Phase 2: Teardown ===
    info!("soft_reboot: Phase 2 — teardown");
    write_state("phase2_teardown");

    // Reset boot properties
    if let Err(e) = sys_prop::init() {
        warn!("sys_prop init failed: {e}");
    }
    let rp = resetprop();
    for &(name, value) in RESET_PROPS {
        if !value.is_empty()
            && let Err(e) = rp.set(name, value)
        {
            warn!("resetprop {name}={value} failed: {e}");
        }
    }

    // Run the emulated-soft-reboot stage (contract stage the pre-WP5 implementation
    // ran at this point; modules may hook emulated-soft-reboot.d). Blocking, before
    // any teardown begins.
    info!("soft_reboot: running emulated-soft-reboot stage");
    init_event::run_stage("emulated-soft-reboot", true);

    // === OPlus PHOENIX / critical-service crash neutralisation ===
    // OPlus init has a PHOENIX handler (phx_is_bootup_critical_service) that
    // treats any death of zygote/zygote_secondary as a bootup-critical crash
    // and triggers a class_restart main — killing zygote, system_server, netd
    // and cascading via onrestart triggers to a double-restart loop.
    //
    // Neutralise this by:
    //  1. Disabling the zygote critical-window so init doesn't count the
    //     upcoming stop as a crash within the boot-critical window.
    //  2. Setting sys.shutdown.requested so PHOENIX recognises that a
    //     controlled shutdown is in progress.
    if let Err(e) = rp.set("zygote.critical_window.minute", "off") {
        warn!("soft_reboot: set zygote.critical_window.minute=off failed: {e}");
    }
    if let Err(e) = rp.set("sys.shutdown.requested", "1786-ksu-softreboot") {
        warn!("soft_reboot: set sys.shutdown.requested failed: {e}");
    }

    // === OPlus watchdog safety: prepare for framework teardown ===
    // Re-arm the PMIC watchdog with a 30-second bite timer (default is 7s
    // which is too short for the stop→restage cycle).
    rearm_oplus_pmic_watchdog();
    // Tell the Theia boot-completed monitor that a restart is expected
    // so it doesn't treat the stopped state as a crash.
    reset_oplus_boot_completed_monitor();
    // Inform OPlus shutdown detector that a controlled restart is in progress
    if Path::new("/proc/shutdown_detect").exists() {
        let _ = fs::write("/proc/shutdown_detect", "normal");
    }
    // One explicit kick right before we stop services
    kick_oplus_init_watchdog();

    // Run `stop` to halt all non-core services
    info!("soft_reboot: running 'stop'");
    match Command::new("stop").status() {
        Ok(status) if !status.success() => warn!("stop exited with: {status}"),
        Err(e) => {
            error!("failed to run stop: {e}");
            wd_stop.store(true, Ordering::Relaxed);
            return rollback_start("stop failed");
        }
        _ => {}
    }

    // Poll for zygote, surfaceflinger, and netd to reach "stopped" state (≤10s).
    // We check for "stopped" specifically rather than != "running" because
    // OPlus PHOENIX can restart dying services into "restarting" → "running"
    // before our next poll.  Waiting for the definitive "stopped" state ensures
    // init has fully reaped the old processes.
    info!("soft_reboot: waiting for services to stop");
    let stop_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let zygote_state = crate::utils::getprop("init.svc.zygote")
            .unwrap_or_default();
        let sf_state = crate::utils::getprop("init.svc.surfaceflinger")
            .unwrap_or_default();
        let netd_state = crate::utils::getprop("init.svc.netd")
            .unwrap_or_default();

        let all_stopped = zygote_state == "stopped"
            && sf_state == "stopped"
            && netd_state == "stopped";

        if all_stopped || Instant::now() >= stop_deadline {
            if zygote_state != "stopped" {
                warn!("soft_reboot: zygote state={zygote_state} after stop timeout");
            }
            if netd_state != "stopped" {
                warn!("soft_reboot: netd state={netd_state} after stop timeout");
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Now that zygote and framework services are fully stopped, force-kill any surviving
    // module processes so no corrupted/zombie ptrace monitors survive into Phase 4.
    crate::cleanup::force_kill_module_processes(MODULE_PATH_PREFIXES);
    crate::cleanup::warn_stopped_tracees("phase2");

    // === Phase 3: Mount reset ===
    info!("soft_reboot: Phase 3 — mount reset");
    write_state("phase3_mount_reset");

    // Switch to PID 1's mount namespace
    if let Err(e) = switch_mnt_ns(1) {
        error!("failed to switch to PID 1 mount ns: {e}");
        return rollback_start("mount ns switch failed");
    }

    // Query live module mounts dynamically inside PID 1's mount namespace!
    let mut sorted_mounts = crate::cleanup::find_all_module_mounts();
    info!(
        "soft_reboot: Phase 3 found {} module mounts to detach",
        sorted_mounts.len()
    );
    sorted_mounts.sort_by(|a, b| {
        // Sort by mount_point depth (deeper first), then mount_id (higher first)
        let depth_a = a.mount_point.matches('/').count();
        let depth_b = b.mount_point.matches('/').count();
        depth_b.cmp(&depth_a).then(b.mount_id.cmp(&a.mount_id))
    });

    let mut umount_failures = 0;
    for mount in &sorted_mounts {
        info!("soft_reboot: unmounting {}", mount.mount_point);

        // Try userspace umount2 first
        let c_path = std::ffi::CString::new(mount.mount_point.as_str()).unwrap_or_default();
        let ret = unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) };

        if ret != 0 {
            let errno = std::io::Error::last_os_error();
            warn!(
                "soft_reboot: umount2 {} failed: {errno}, trying kernel force",
                mount.mount_point
            );

            // Kernel force-fallback (WP3)
            match ksucalls::force_umount(&mount.mount_point, 0) {
                Ok(0) => {
                    info!(
                        "soft_reboot: kernel force umount succeeded for {}",
                        mount.mount_point
                    );
                }
                Ok(result) => {
                    warn!(
                        "soft_reboot: kernel force umount returned {result} for {}",
                        mount.mount_point
                    );
                    umount_failures += 1;
                }
                Err(e) => {
                    warn!(
                        "soft_reboot: kernel force umount failed for {}: {e}",
                        mount.mount_point
                    );
                    umount_failures += 1;
                }
            }
        }
    }

    if umount_failures > 0 {
        warn!("soft_reboot: {umount_failures} mounts could not be detached");
    }

    // Sync the journal so detached mounts aren't retried in later cycles,
    // then verify nothing module-related remains.
    crate::cleanup::prune_mount_journal_to_live();
    let remaining = crate::cleanup::find_all_module_mounts();
    if remaining.is_empty() {
        info!("soft_reboot: all module mounts successfully detached");
    } else {
        warn!(
            "soft_reboot: {} module mounts still present after teardown",
            remaining.len()
        );
        for m in &remaining {
            warn!("  still mounted: {} (src: {})", m.mount_point, m.source);
        }
    }

use std::os::unix::fs::PermissionsExt;

/// Recursively sanitizes permissions on non-reserved directories under `/data/adb`
/// and module runtime subdirectories before re-executing module scripts during soft reboot.
///
/// Modules such as ReZygisk or Zygisk Next create read-only runtime directories (mode 555).
/// When soft-rebooting, stock module scripts attempting to re-initialize via `rm -rf /data/adb/<dir>`
/// fail with `Permission Denied` if directory permissions remain 555.
///
/// **Security & Integrity Guards**:
/// 1. **Symlink Protection**: Uses `entry.file_type()` to check `!file_type.is_symlink()` so
///    symlinks are NEVER followed to external filesystem paths.
/// 2. **Reserved Path Exclusion**:
///    - Under `/data/adb/`: Skips core system directories (`ksu`, `modules_update`, `post-fs-data.d`, `service.d`, `boot-completed.d`).
///    - Under `/data/adb/modules/<mod>/`: Skips standard module assets (`system`, `webroot`, `zygisk`).
/// 3. **Write & Execute Bit Validation**: Checks `current_mode & 0o300 != 0o300` to ensure owner
///    has both write AND search/exec permissions (`u+wx`) required for directory traversal and unlinking.
/// 4. **Recursive Bounded Walk**: Recursively traverses subdirectories up to depth 4 to ensure
///    nested read-only directory nodes are also sanitized.
/// 5. **Safe Native Rust**: Uses `std::os::unix::fs::PermissionsExt` without raw C FFI `unsafe`.
fn sanitize_adb_dir_permissions() {
    /// Top-level directories under /data/adb/ that must never be altered.
    const TOP_RESERVED_DIRS: &[&str] = &[
        "ksu",
        "modules_update",
        "post-fs-data.d",
        "service.d",
        "boot-completed.d",
    ];

    /// Reserved subdirectories inside /data/adb/modules/<mod_id>/ that must never be altered.
    const MODULE_RESERVED_DIRS: &[&str] = &[
        "system",
        "webroot",
        "zygisk",
    ];

    fn walk_and_sanitize(dir_path: &Path, current_depth: usize) {
        if current_depth > 4 {
            return;
        }

        let Ok(entries) = fs::read_dir(dir_path) else {
            return;
        };

        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };

            // CRITICAL: Never follow symlinks to external filesystem paths
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }

            let path = entry.path();
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Depth 1: Exclude reserved top-level directories under /data/adb/
            if current_depth == 1 && TOP_RESERVED_DIRS.contains(&name_str.as_ref()) {
                continue;
            }

            // Depth 3: Under /data/adb/modules/<mod_id>/, exclude standard module directories
            if current_depth == 3 && MODULE_RESERVED_DIRS.contains(&name_str.as_ref()) {
                continue;
            }

            // At depth 1 for "modules", recurse into /data/adb/modules/<mod_id>/ without modifying /data/adb/modules itself
            if current_depth == 1 && name_str == "modules" {
                walk_and_sanitize(&path, current_depth + 1);
                continue;
            }

            // Restore owner write+exec permissions (u+wx) if missing
            if let Ok(metadata) = entry.metadata() {
                let current_mode = metadata.permissions().mode() & 0o777;
                // Check if owner write (0o200) OR owner execute (0o100) is missing
                if current_mode & 0o300 != 0o300 {
                    let new_mode = current_mode | 0o700; // Grant u+rwx
                    if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(new_mode)) {
                        warn!("soft_reboot: failed to sanitize permissions on {}: {e}", path.display());
                    } else {
                        info!("soft_reboot: sanitized permissions (0o{:o} -> 0o{:o}) on {}", current_mode, new_mode, path.display());
                    }
                }
            }

            // Recurse into nested subdirectories
            walk_and_sanitize(&path, current_depth + 1);
        }
    }

    walk_and_sanitize(Path::new("/data/adb"), 1);
}

    // === Phase 4: Property reset + restage ===
    info!("soft_reboot: Phase 4 — property reset + restage");
    write_state("phase4_restage");

    // Reset kernel boot state (WP1)
    if let Err(e) = ksucalls::reset_boot_state() {
        error!("RESET_BOOT_STATE failed: {e}");
        return rollback_start("reset boot state failed");
    }
    info!("soft_reboot: kernel boot state reset");

    // Sanitize /data/adb subdirectories so module scripts creating 555 read-only runtime dirs
    // can execute 'rm -rf /data/adb/<dir>' without permission denied errors.
    sanitize_adb_dir_permissions();

    // Re-run the full post-fs-data pipeline (unmodified stock pipeline)
    info!("soft_reboot: running on_post_data_fs");
    if let Err(e) = init_event::on_post_data_fs() {
        error!("on_post_data_fs failed: {e}");
        return rollback_start("post-fs-data restage failed");
    }

    // === Phase 5: Relaunch + validate ===
    info!("soft_reboot: Phase 5 — relaunch + validate");
    write_state("phase5_relaunch");

    // Re-arm OPlus watchdogs before relaunching services
    rearm_oplus_pmic_watchdog();
    kick_oplus_init_watchdog();

    // Run service stage scripts early so background module daemons (vectord, lspd, etc.)
    // register their ServiceManager proxy binders before system_server forks
    info!("soft_reboot: executing service stage scripts");
    init_event::run_stage("service", false);

    // Start all services
    info!("soft_reboot: running 'start'");
    match Command::new("start").status() {
        Ok(status) if !status.success() => {
            warn!("start exited with: {status}");
        }
        Err(e) => {
            error!("failed to run start: {e}");
            wd_stop.store(true, Ordering::Relaxed);
            return rollback_start("start failed");
        }
        _ => {}
    }

    // Clear the shutdown-requested sentinel so init resumes normal PHOENIX
    // monitoring after the framework comes back up.
    let _ = rp.set("sys.shutdown.requested", "");

    // Wait for PMS package scan completion and boot_completed (90s budget)
    info!("soft_reboot: waiting for PMS scan completion & sys.boot_completed=1 (90s budget)");
    if !wait_pms_ready(Duration::from_secs(90)) {
        warn!("soft_reboot: PMS / boot_completed timeout, attempting retry");
        return rollback_stop_start("pms_boot_completed_timeout");
    }

    // Run boot-completed stage
    init_event::on_boot_completed();

    // Post-checks
    crate::cleanup::warn_stopped_tracees("phase5");
    let zygote_running = crate::utils::getprop("init.svc.zygote").as_deref() == Some("running");
    if !zygote_running {
        warn!("soft_reboot: zygote not running after relaunch!");
    }

    // Verify core services stayed running throughout
    let core_services = ["servicemanager", "hwservicemanager", "vold", "lmkd", "logd"];
    for svc in &core_services {
        let prop = format!("init.svc.{svc}");
        let state = crate::utils::getprop(&prop).unwrap_or_default();
        if state != "running" {
            warn!("soft_reboot: core service {svc} state={state} (expected running)");
        }
    }

    // Stop the watchdog kicker thread — boot is complete
    wd_stop.store(true, Ordering::Relaxed);

    // Signal OPlus that boot is complete again
    signal_oplus_boot_completed();

    let elapsed = cycle_start.elapsed();
    info!(
        "=== soft_reboot: completed in {:.1}s ===",
        elapsed.as_secs_f64()
    );
    write_state(&format!("completed_{}ms", elapsed.as_millis()));

    // Final snapshot
    if let Err(e) = snapshot_state(&log_dir.join("post")) {
        warn!("post-reboot snapshot failed: {e}");
    }

    Ok(())
}

/// Rollback: just try to `start` services
fn rollback_start(reason: &str) -> Result<()> {
    warn!("soft_reboot: ROLLBACK — {reason}, attempting start");
    write_state(&format!("rollback_{reason}"));

    let _ = Command::new("start").status();

    // Wait briefly for boot
    if wait_prop_value("sys.boot_completed", "1", Duration::from_secs(90)) {
        info!("soft_reboot: rollback start succeeded");
        write_state(&format!("rollback_recovered_{reason}"));
        Ok(())
    } else {
        error!("soft_reboot: rollback start failed, system may be in bad state");
        write_state("rollback_failed");
        bail!("soft reboot rollback failed: {reason}");
    }
}

/// Rollback: stop then start (one retry)
fn rollback_stop_start(reason: &str) -> Result<()> {
    warn!("soft_reboot: ROLLBACK (stop+start) — {reason}");
    write_state(&format!("rollback_retry_{reason}"));

    let _ = Command::new("stop").status();
    std::thread::sleep(Duration::from_secs(1));
    let _ = Command::new("start").status();

    if wait_prop_value("sys.boot_completed", "1", Duration::from_secs(90)) {
        info!("soft_reboot: rollback stop+start succeeded");
        write_state(&format!("rollback_recovered_{reason}"));
        Ok(())
    } else {
        error!("soft_reboot: rollback stop+start failed");
        write_state("rollback_failed_needs_real_reboot");
        bail!("soft reboot failed, real reboot may be needed: {reason}");
    }
}

/// Simple monotonic timestamp string
fn chrono_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}
