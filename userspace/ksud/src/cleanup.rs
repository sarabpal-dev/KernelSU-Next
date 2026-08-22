//! WP6: Universal module cleanup — live uninstall / disable / bulk uninstall
//!
//! Pipeline (per-module, never module-specific):
//! 0. Snapshot system.prop entries + record baseline
//! 1. Generic process kill (exe/cwd/cmdline for all UIDs; maps only for uid 0)
//! 2. Generic mount detach (plain umount → MNT_DETACH → kernel FORCE_UMOUNT)
//! 3. Property re-aggregation (from snapshot; baseline restore for vanished keys)
//! 4. Re-run metamount.sh for remaining set
//! 5. Regenerate preinit.rc
//! 6. prune_single_module (metauninstall → uninstall.sh → clear configs → optionally delete)
//!    — deletion is LAST so that all identification (props, mounts, procs) can read the dir.
//!
//! Sepolicy: left in kernel (additive-only; harmless allows cleaned at next real boot).

use anyhow::{Context, Result, bail};
use log::{error, info, warn};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{Duration, Instant};

use prop_rs_android::resetprop::ResetProp;
use prop_rs_android::sys_prop;

use crate::{defs, ksucalls, metamodule, module};

/// Get a ResetProp instance configured for skip_svc (direct mmap)
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

/// Check if a path-prefix string matches against a candidate with proper boundary.
/// Matches `prefix` exactly or `prefix/...` anywhere in the candidate — avoids
/// `yt` matching `yt-revanced`. The contains arm covers mountinfo option strings
/// (e.g. "lowerdir=/data/adb/modules/<id>/...,upperdir=...").
fn matches_module_prefix(candidate: &str, prefix: &str) -> bool {
    candidate == prefix || candidate.contains(&format!("{prefix}/"))
}

/// Entry from /proc/PID/mountinfo or Mount Journal
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MountEntry {
    pub mount_id: u32,
    pub parent_id: u32,
    #[serde(default)]
    pub root: String,
    pub mount_point: String,
    pub source: String,
    pub options: String,
    /// Boot session this entry was recorded in. Mount IDs are per-boot, so
    /// entries from a previous boot must never be acted on (an ID from an old
    /// session can collide with an unrelated mount in this one).
    #[serde(default)]
    pub boot_id: String,
}

fn current_boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn load_mount_journal() -> Vec<MountEntry> {
    let path = defs::MOUNT_JOURNAL_PATH;
    let boot_id = current_boot_id();
    fs::read_to_string(path).map_or_else(
        |_| Vec::new(),
        |content| {
            let entries: Vec<MountEntry> = serde_json::from_str(&content).unwrap_or_default();
            // Boot-scope the journal: drop anything not recorded in this boot
            entries
                .into_iter()
                .filter(|e| !boot_id.is_empty() && e.boot_id == boot_id)
                .collect()
        },
    )
}

pub fn save_mount_journal(entries: &[MountEntry]) -> Result<()> {
    let content = serde_json::to_string_pretty(entries)?;
    fs::write(defs::MOUNT_JOURNAL_PATH, content).context("Failed to save mount journal")?;
    Ok(())
}

/// Wrap execution of mount script to record diff into mount journal.
pub fn record_mount_journal<F, R>(f: F) -> Result<R>
where
    F: FnOnce() -> Result<R>,
{
    let before_ids: HashSet<u32> = get_live_mounts(1).into_iter().map(|m| m.mount_id).collect();

    let result = f();

    let after_mounts = get_live_mounts(1);
    let mut journal = load_mount_journal();
    let mut added = 0;

    for mount in after_mounts {
        if !before_ids.contains(&mount.mount_id)
            && !journal.iter().any(|j| j.mount_id == mount.mount_id)
        {
            journal.push(mount);
            added += 1;
        }
    }
    if added > 0 {
        info!("cleanup: recorded {added} new mounts into mount journal");
    }
    if let Err(e) = save_mount_journal(&journal) {
        warn!("cleanup: failed to save mount journal: {e}");
    }

    result
}

/// Every mount attributable to modules: all journal entries (recorded around
/// module/metamodule script execution, so they cover mounts with no /data/adb
/// string in mountinfo — e.g. magic-mount tmpfs, fs-root-relative bind sources)
/// UNION live mounts referencing /data/adb paths.
pub fn find_all_module_mounts() -> Vec<MountEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for mount in get_live_mounts(1) {
        // "/data/adb" by absolute path, plus "/adb/..." fs-root-relative sources and roots:
        // when /data is the filesystem root, binds sourced under /data/adb appear
        // in mountinfo as root="/adb/..." or source="/adb/..." (path relative to the f2fs root mountpoint).
        // Without this check, module binds (e.g. apk-over-app binds applied by module service.sh)
        // survive framework restarts and PMS scans the testkey-signed file -> package deleted.
        let is_module = matches_module_prefix(&mount.source, "/data/adb")
            || matches_module_prefix(&mount.mount_point, "/data/adb")
            || matches_module_prefix(&mount.options, "/data/adb")
            || matches_module_prefix(&mount.root, "/data/adb")
            || matches_module_prefix(&mount.root, "/adb")
            || mount.source.contains("/adb/")
            || mount.root.contains("/adb/")
            || (mount.mount_point.contains("/data/app/") && mount.mount_point.ends_with(".apk"));
        if is_module && seen.insert(mount.mount_id) {
            info!(
                "cleanup: identified module mount: id={} root={} mnt={} src={}",
                mount.mount_id, mount.root, mount.mount_point, mount.source
            );
            out.push(mount);
        }
    }
    for mount in load_mount_journal() {
        if seen.insert(mount.mount_id) {
            out.push(mount);
        }
    }

    out
}

/// Drop journal entries whose mounts are no longer live. Call after a teardown
/// pass so later cycles don't attempt to unmount ghosts.
pub fn prune_mount_journal_to_live() {
    let live: HashSet<u32> = get_live_mounts(1).into_iter().map(|m| m.mount_id).collect();
    let journal: Vec<MountEntry> = load_mount_journal()
        .into_iter()
        .filter(|j| live.contains(&j.mount_id))
        .collect();
    if let Err(e) = save_mount_journal(&journal) {
        warn!("cleanup: failed to prune mount journal: {e}");
    }
}

fn get_live_mounts(pid: i32) -> Vec<MountEntry> {
    let path = format!("/proc/{pid}/mountinfo");
    let Ok(file) = fs::File::open(&path) else {
        return Vec::new();
    };
    let reader = BufReader::new(file);
    let boot_id = current_boot_id();
    let mut entries = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let mount_id: u32 = parts[0].parse().unwrap_or(0);
        let parent_id: u32 = parts[1].parse().unwrap_or(0);
        let root = parts[3].to_string();
        let mount_point = parts[4].to_string();

        let sep_idx = parts.iter().position(|&p| p == "-");
        let source = sep_idx
            .and_then(|i| parts.get(i + 2))
            .unwrap_or(&"")
            .to_string();

        let options = parts[5..].join(" ");

        entries.push(MountEntry {
            mount_id,
            parent_id,
            root,
            mount_point,
            source,
            options,
            boot_id: boot_id.clone(),
        });
    }

    entries
}

/// Parse /proc/<pid>/mountinfo + Mount Journal and return entries (journal ∪ live matches)
/// referencing the given module directory prefix with proper boundary matching.
fn find_module_mounts(pid: i32, module_dir_prefix: &str) -> Vec<MountEntry> {
    let mut seen_ids = HashSet::new();
    let mut entries = Vec::new();
    let root_alt_prefix = if module_dir_prefix.starts_with("/data/adb") {
        module_dir_prefix.replace("/data/adb", "/adb")
    } else {
        String::new()
    };

    // 1. Live matches from /proc/1/mountinfo
    for mount in get_live_mounts(pid) {
        let references_module = module_dir_prefix.is_empty()
            || matches_module_prefix(&mount.source, module_dir_prefix)
            || matches_module_prefix(&mount.mount_point, module_dir_prefix)
            || matches_module_prefix(&mount.options, module_dir_prefix)
            || matches_module_prefix(&mount.root, module_dir_prefix)
            || (!root_alt_prefix.is_empty()
                && matches_module_prefix(&mount.root, &root_alt_prefix));

        if references_module {
            seen_ids.insert(mount.mount_id);
            entries.push(mount);
        }
    }

    // 2. Union with Mount Journal entries
    for mount in load_mount_journal() {
        if seen_ids.contains(&mount.mount_id) {
            continue;
        }
        let references_module = module_dir_prefix.is_empty()
            || matches_module_prefix(&mount.source, module_dir_prefix)
            || matches_module_prefix(&mount.mount_point, module_dir_prefix)
            || matches_module_prefix(&mount.options, module_dir_prefix)
            || matches_module_prefix(&mount.root, module_dir_prefix)
            || (!root_alt_prefix.is_empty()
                && matches_module_prefix(&mount.root, &root_alt_prefix));

        if references_module {
            seen_ids.insert(mount.mount_id);
            entries.push(mount);
        }
    }

    entries
}

/// Unmount module-related mounts in PID 1's namespace.
/// Order: children before parents (deeper paths first, higher mount_id first).
/// Strategy: try plain umount first, then MNT_DETACH, then kernel FORCE_UMOUNT ioctl.
fn detach_module_mounts(module_dir_prefix: &str) -> usize {
    let mut mounts = find_module_mounts(1, module_dir_prefix);
    if mounts.is_empty() {
        info!("cleanup: no module mounts found for prefix {module_dir_prefix}");
        return 0;
    }

    // Sort: deeper paths first, then higher mount_id first
    mounts.sort_by(|a, b| {
        let depth_a = a.mount_point.matches('/').count();
        let depth_b = b.mount_point.matches('/').count();
        depth_b.cmp(&depth_a).then(b.mount_id.cmp(&a.mount_id))
    });

    let mut failures = 0;
    for mount in &mounts {
        info!("cleanup: unmounting {}", mount.mount_point);

        let c_path = std::ffi::CString::new(mount.mount_point.as_str()).unwrap_or_default();

        // Try plain umount first (plan: plain-then-detach)
        let ret = unsafe { libc::umount2(c_path.as_ptr(), 0) };
        if ret == 0 {
            continue;
        }

        // Fallback: MNT_DETACH (lazy unmount)
        let ret = unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) };
        if ret == 0 {
            info!("cleanup: MNT_DETACH succeeded for {}", mount.mount_point);
            continue;
        }

        let errno = std::io::Error::last_os_error();
        warn!(
            "cleanup: umount2 {} failed: {errno}, trying kernel force",
            mount.mount_point
        );

        // Kernel force-fallback (WP3: FORCE_UMOUNT ioctl)
        match ksucalls::force_umount(&mount.mount_point, 0) {
            Ok(0) => {
                info!(
                    "cleanup: kernel force umount succeeded for {}",
                    mount.mount_point
                );
            }
            Ok(result) => {
                warn!(
                    "cleanup: kernel force umount returned {result} for {}",
                    mount.mount_point
                );
                failures += 1;
            }
            Err(e) => {
                warn!(
                    "cleanup: kernel force umount failed for {}: {e}",
                    mount.mount_point
                );
                failures += 1;
            }
        }
    }

    if failures > 0 {
        warn!("cleanup: {failures} mounts could not be detached");
    }

    mounts.len() - failures
}

// ─── Process Kill ───────────────────────────────────────────────────────

/// Read the UID of a process from /proc/<pid>/status.
/// Shared by cleanup.rs and soft_reboot.rs process sweeps.
pub fn proc_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Format: "Uid:\treal\teffective\tsaved\tfs"
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Find processes whose /proc/*/exe, cwd, cmdline reference the given prefix (all UIDs),
/// plus /proc/*/maps for uid 0 only (native daemons).
///
/// Fix #2: Maps-based matching is restricted to uid 0 to avoid mass-killing apps
/// that have injected .so files from a zygisk module. Already-running app processes
/// keep stale code until natural death (plan requirement).
///
/// Fix #5: Init-managed framework services (zygote, netd, surfaceflinger, etc.) are
/// excluded even when running as UID 0 with module .so files mapped.  Killing these
/// before `stop` triggers OPlus PHOENIX crash handlers and cascading onrestart triggers
/// (class_restart main → double framework restart).
fn find_processes_by_prefix(prefix: &str) -> HashSet<u32> {
    let mut pids = HashSet::new();

    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return pids;
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Never touch PID 1 or self (I2)
        if pid <= 1 || pid == std::process::id() {
            continue;
        }

        // Fix #5: Skip init-managed framework processes.
        // These run as UID 0 and may have zygisk .so files mapped from /data/adb,
        // but killing them triggers PHOENIX/onrestart cascading restarts.
        if is_init_managed_process(pid) {
            continue;
        }

        // Check exe and cwd symlinks (all UIDs)
        for link in &[format!("/proc/{pid}/exe"), format!("/proc/{pid}/cwd")] {
            if let Ok(target) = fs::read_link(link)
                && matches_module_prefix(&target.to_string_lossy(), prefix)
            {
                pids.insert(pid);
            }
        }

        if pids.contains(&pid) {
            continue;
        }

        // Check /proc/PID/cmdline (all UIDs)
        let cmdline_path = format!("/proc/{pid}/cmdline");
        if let Ok(content) = fs::read_to_string(&cmdline_path)
            && matches_module_prefix(&content, prefix)
        {
            pids.insert(pid);
            continue;
        }

        // Check /proc/PID/maps ONLY for uid 0 (native daemons).
        // App processes (uid >= 10000) with injected .so files should NOT be killed —
        // they keep stale code until natural death per plan requirement.
        if proc_uid(pid) == Some(0) {
            let maps_path = format!("/proc/{pid}/maps");
            if let Ok(content) = fs::read_to_string(&maps_path)
                && matches_module_prefix(&content, prefix)
            {
                pids.insert(pid);
            }
        }
    }

    pids
}

/// Check if a PID belongs to an init-managed framework service that must NOT
/// be killed during the module-process sweep.
///
/// Check if a PID belongs to an init-managed framework service that must NOT
/// be killed during the module-process sweep.
///
/// Detection: match native daemons via /proc/PID/exe against known framework binaries,
/// and match app_process-based framework processes (zygote, system_server, USAP pool)
/// via comm with a cmdline fallback for the pre-rename window. Module daemons running
/// under app_process (vectord, shizuku, lspd) are NOT protected.
fn is_init_managed_process(pid: u32) -> bool {
    /// Framework binaries whose processes must never be killed by the module sweep.
    /// These are init-managed services with `onrestart` cascading triggers and/or
    /// OPlus PHOENIX critical-service monitoring.
    const PROTECTED_EXES: &[&str] = &[
        "/system/bin/netd",
        "/system/bin/surfaceflinger",
        "/system/bin/servicemanager",
        "/system/bin/hwservicemanager",
        "/system/bin/audioserver",
        "/system/bin/cameraserver",
        "/system/bin/installd",
        "/system/bin/vold",
        "/system/bin/lmkd",
        "/system/bin/logd",
        "/system/bin/healthd",
    ];

    let exe_link = format!("/proc/{pid}/exe");
    let Ok(exe_path) = fs::read_link(&exe_link) else {
        return false;
    };
    let exe_str = exe_path.to_string_lossy();

    for &protected in PROTECTED_EXES {
        if exe_str == protected || exe_str.starts_with(&format!("{protected} ")) {
            return true;
        }
    }

    // App process binaries: zygote, system_server, USAP pool, vs module daemons (vectord, shizuku, lspd)
    if exe_str.starts_with("/system/bin/app_process") {
        // Check comm first
        let comm_path = format!("/proc/{pid}/comm");
        if let Ok(comm) = fs::read_to_string(&comm_path) {
            let comm_trimmed = comm.trim();
            if matches!(
                comm_trimmed,
                "zygote" | "zygote64" | "system_server" | "usap32" | "usap64"
            ) {
                return true;
            }
        }

        // Pre-rename fallback: check cmdline for zygote/system_server startup flags
        let cmdline_path = format!("/proc/{pid}/cmdline");
        if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
            if cmdline.contains("--zygote") || cmdline.contains("--start-system-server") {
                return true;
            }
        }
    }

    false
}

/// Sends a signal to a process, targeting its process group if it has a dedicated group (> 1).
///
/// If `libc::getpgid(pid)` returns a valid PGID > 1, we send `sig` to `-pgid` to terminate
/// the process along with any background children/helpers (e.g. vectord spawning logcat).
///
/// Safety guard: `pgid > 1` ensures we never accidentally signal group 0 (the caller's own
/// group) or group -1 / 1 (init's group or system broadcast).
/// Falls back to signaling the single `pid` if group kill fails or pgid <= 1.
fn kill_pid_or_group(pid: u32, sig: libc::c_int) {
    let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
    if pgid > 1 {
        let ret = unsafe { libc::kill(-pgid, sig) };
        if ret == 0 {
            return;
        }
    }
    unsafe {
        libc::kill(pid as libc::pid_t, sig);
    }
}

/// Count live tracees per tracer, from /proc/*/status TracerPid.
fn tracer_tracee_counts() -> HashMap<u32, usize> {
    let mut counts: HashMap<u32, usize> = HashMap::new();
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return counts;
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(status) = fs::read_to_string(format!("/proc/{pid_str}/status")) else {
            continue;
        };
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                if let Ok(tracer) = rest.trim().parse::<u32>()
                    && tracer > 0
                {
                    *counts.entry(tracer).or_insert(0) += 1;
                }
                break;
            }
        }
    }

    counts
}

/// Warn about processes left in a tracing-stop state (State t/T) whose tracer
/// is gone — the wedge signature of a killed tracer. Diagnostics only.
pub fn warn_stopped_tracees(tag: &str) {
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return;
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(status) = fs::read_to_string(format!("/proc/{pid_str}/status")) else {
            continue;
        };
        let mut state = "";
        let mut tracer_pid = 0u32;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("State:") {
                state = rest.trim();
            } else if let Some(rest) = line.strip_prefix("TracerPid:") {
                tracer_pid = rest.trim().parse().unwrap_or(0);
            }
        }
        if (state.starts_with('t') || state.starts_with('T')) && tracer_pid > 0 {
            let tracer_alive = unsafe { libc::kill(tracer_pid as i32, 0) == 0 };
            if !tracer_alive {
                error!(
                    "cleanup({tag}): pid {pid_str} stuck in tracing stop ({state}) \
                     with dead tracer {tracer_pid} — possible wedge"
                );
            }
        }
    }
}

/// Kill processes with tracer-aware escalation:
/// - SIGTERM all, 2 s grace.
/// - Survivors with NO live tracees: SIGKILL.
/// - Survivors that ARE tracing live processes: never SIGKILL while tracees
///   remain — killing a tracer mid-event can leave a tracee (up to and including
///   PID 1) wedged in ptrace_stop. They get extended grace; if they still won't
///   exit, they are left running (logged) — a leftover monitor self-resolves far
///   more safely than a stopped init.
pub fn kill_processes_gently(pids: &HashSet<u32>) {
    if pids.is_empty() {
        return;
    }

    info!("cleanup: sending SIGTERM to {} processes", pids.len());
    for &pid in pids {
        kill_pid_or_group(pid, libc::SIGTERM);
    }

    // Up to 2s graceful exit (bounded, per §4)
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut alive: HashSet<u32> = pids.clone();
    while Instant::now() < deadline {
        alive.retain(|&p| unsafe { libc::kill(p as i32, 0) == 0 });
        if alive.is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Partition survivors: active tracers vs plain processes
    let tracee_counts = tracer_tracee_counts();
    let (tracers, plain): (Vec<u32>, Vec<u32>) = alive
        .iter()
        .copied()
        .partition(|p| tracee_counts.get(p).is_some_and(|&n| n > 0));

    if !plain.is_empty() {
        info!("cleanup: SIGKILL {} surviving processes", plain.len());
        for pid in &plain {
            kill_pid_or_group(*pid, libc::SIGKILL);
        }
    }

    // Extended grace for active tracers; SIGKILL only once their tracees detach
    if !tracers.is_empty() {
        info!(
            "cleanup: {} surviving processes are active tracers, extended grace",
            tracers.len()
        );
        let tracer_deadline = Instant::now() + Duration::from_secs(10);
        let mut pending: HashSet<u32> = tracers.into_iter().collect();
        while Instant::now() < tracer_deadline && !pending.is_empty() {
            let counts = tracer_tracee_counts();
            pending.retain(|&p| {
                let alive = unsafe { libc::kill(p as i32, 0) == 0 };
                let tracing = counts.get(&p).is_some_and(|&n| n > 0);
                if alive && !tracing {
                    // Tracees detached — safe to kill now
                    kill_pid_or_group(p, libc::SIGKILL);
                    info!("cleanup: SIGKILL tracer {p} after its tracees detached");
                    return false;
                }
                alive
            });
            if pending.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if !pending.is_empty() {
            error!(
                "cleanup: leaving {} tracer processes running (would wedge tracees): {:?}",
                pending.len(),
                pending
            );
        }
    }
}

/// Kill processes referencing a prefix (thin wrapper over kill_processes_gently)
fn kill_module_processes(prefix: &str) -> usize {
    let pids = find_processes_by_prefix(prefix);
    if pids.is_empty() {
        info!("cleanup: no processes found for prefix {prefix}");
        return 0;
    }

    kill_processes_gently(&pids);
    pids.len()
}

/// Union of find_processes_by_prefix over multiple prefixes (used by soft_reboot).
pub fn find_processes_by_prefixes(prefixes: &[&str]) -> HashSet<u32> {
    let mut out = HashSet::new();
    for prefix in prefixes {
        out.extend(find_processes_by_prefix(prefix));
    }
    out
}

/// Force SIGKILL all surviving module processes after services have stopped.
pub fn force_kill_module_processes(prefixes: &[&str]) {
    let pids = find_processes_by_prefixes(prefixes);
    if pids.is_empty() {
        return;
    }
    info!("cleanup: force-killing {} remaining module processes", pids.len());
    for &pid in &pids {
        kill_pid_or_group(pid, libc::SIGKILL);
    }
}

// ─── Property Re-aggregation ────────────────────────────────────────────

/// Property baseline: { prop_name: first_seen_value }
/// Maintained at PROP_BASELINE_PATH. First-seen = value BEFORE any module set it.
type PropBaseline = HashMap<String, String>;

fn load_prop_baseline() -> PropBaseline {
    let path = defs::PROP_BASELINE_PATH;
    fs::read_to_string(path).map_or_else(
        |_| HashMap::new(),
        |content| serde_json::from_str(&content).unwrap_or_default(),
    )
}

fn save_prop_baseline(baseline: &PropBaseline) -> Result<()> {
    let content = serde_json::to_string_pretty(baseline)?;
    fs::write(defs::PROP_BASELINE_PATH, content).context("Failed to save prop baseline")?;
    Ok(())
}

/// Parse a module's system.prop and return (key, value) pairs
fn parse_system_prop(module_path: &Path) -> Vec<(String, String)> {
    let prop_file = module_path.join("system.prop");
    if !prop_file.exists() {
        return Vec::new();
    }

    let Ok(content) = fs::read_to_string(&prop_file) else {
        return Vec::new();
    };

    let mut props = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            props.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    props
}

/// Collect the union of all system.prop keys from remaining active modules
fn collect_remaining_props() -> HashMap<String, String> {
    let mut union = HashMap::new();

    let _ = module::foreach_module(module::ModuleType::Active, |module_path| {
        for (key, value) in parse_system_prop(module_path) {
            // Last writer wins (matches load_system_prop iteration order)
            union.insert(key, value);
        }
        Ok(())
    });

    union
}

/// Record baseline values for properties a module is about to set.
/// Called BEFORE the module is removed so we can capture what was already set.
fn record_baseline_for_module(module_path: &Path) {
    let props = parse_system_prop(module_path);
    if props.is_empty() {
        return;
    }

    let mut baseline = load_prop_baseline();
    let mut changed = false;

    for (key, _value) in &props {
        if !baseline.contains_key(key) {
            // Record the current live value as baseline (what the system had before modules)
            let current = crate::utils::getprop(key).unwrap_or_default();
            baseline.insert(key.clone(), current);
            changed = true;
        }
    }

    if changed && let Err(e) = save_prop_baseline(&baseline) {
        warn!("cleanup: failed to save prop baseline: {e}");
    }
}

/// Re-aggregate properties after a module is removed.
/// Uses pre-captured prop snapshot (not the on-disk system.prop which may be deleted).
/// Vanished keys (no longer set by any remaining module) → restore baseline or delete.
fn reaggregate_properties(removed_prop_snapshot: &[(String, String)]) {
    if removed_prop_snapshot.is_empty() {
        return;
    }

    // Initialize sys_prop API
    if let Err(e) = sys_prop::init() {
        warn!("cleanup: failed to init sys_prop: {e}");
        return;
    }

    let rp = resetprop();
    let baseline = load_prop_baseline();
    let remaining = collect_remaining_props();

    for (key, _) in removed_prop_snapshot {
        if remaining.contains_key(key) {
            // Another module still sets this key — apply its value
            let new_value = &remaining[key];
            info!("cleanup: prop {key} still set by another module, applying {new_value}");
            if let Err(e) = rp.set(key, new_value) {
                warn!("cleanup: failed to set prop {key}={new_value}: {e}");
            }
        } else if let Some(baseline_value) = baseline.get(key) {
            // Key vanished — restore baseline
            if baseline_value.is_empty() {
                info!("cleanup: prop {key} vanished, deleting (baseline was empty)");
                if let Err(e) = rp.delete(key) {
                    warn!("cleanup: failed to delete prop {key}: {e:?}");
                }
            } else {
                info!("cleanup: prop {key} vanished, restoring baseline={baseline_value}");
                if let Err(e) = rp.set(key, baseline_value) {
                    warn!("cleanup: failed to restore prop {key}: {e}");
                }
            }
        } else {
            // No baseline recorded — best effort: delete the property
            info!("cleanup: prop {key} vanished, no baseline, deleting");
            if let Err(e) = rp.delete(key) {
                warn!("cleanup: failed to delete prop {key}: {e:?}");
            }
        }
    }
}

// ─── Public Entry Points ────────────────────────────────────────────────

/// Full live-cleanup pipeline for a single module.
///
/// `delete_dir`: true for uninstall, false for disable.
///
/// Fix #1: Dir deletion is LAST. Prop snapshot taken FIRST so reaggregation works
/// even after the module directory is gone.
///
/// Fix #4: Ensures PID 1's mount namespace inside the pipeline.
pub fn cleanup_module(id: &str, delete_dir: bool) -> Result<()> {
    module::validate_module_id(id)?;

    let module_path = Path::new(defs::MODULE_DIR).join(id);
    if !module_path.exists() {
        bail!("Module {id} not found");
    }

    let module_dir_prefix = format!("{}{id}", defs::MODULE_DIR);
    info!("cleanup: starting for module {id} (delete={delete_dir})");

    // Fix #8: on uninstall, set the `remove` marker up front. Without it the
    // metamount.sh re-run below would still see this module as enabled and
    // re-create the very mounts we are about to detach. The marker also matches
    // stock semantics (module::uninstall_module) and guarantees boot-time
    // prune_modules() finishes the job if we fail mid-pipeline.
    if delete_dir {
        let remove_path = module_path.join(defs::REMOVE_FILE_NAME);
        crate::utils::ensure_file_exists(&remove_path)?;
    }

    // Fix #4: Ensure we're in PID 1's mount namespace (I5)
    if let Err(e) = crate::utils::switch_mnt_ns(1) {
        warn!("cleanup: switch_mnt_ns(1) failed: {e}");
    }

    // Step 0: Snapshot system.prop entries + record baseline BEFORE anything modifies the dir
    let prop_snapshot = parse_system_prop(&module_path);
    record_baseline_for_module(&module_path);

    // Step 1: Process kill (before mounts so processes release file handles)
    info!("cleanup: killing module processes");
    let killed = kill_module_processes(&module_dir_prefix);
    info!("cleanup: killed {killed} processes for {id}");

    // Step 2: Mount detach (in PID 1's mount namespace)
    info!("cleanup: detaching module mounts");
    let detached = detach_module_mounts(&module_dir_prefix);
    info!("cleanup: detached {detached} mounts for {id}");
    // Drop detached mounts from the journal so later cycles don't retry ghosts
    prune_mount_journal_to_live();

    // Step 3: Property re-aggregation (from pre-captured snapshot)
    info!("cleanup: re-aggregating properties");
    reaggregate_properties(&prop_snapshot);

    // Step 4: Re-run metamount.sh for remaining enabled modules
    info!("cleanup: re-running metamount.sh for remaining set");
    if let Err(e) = metamodule::exec_mount_script(defs::MODULE_DIR) {
        warn!("cleanup: metamount.sh failed: {e}");
    }

    // Step 5: Regenerate preinit.rc
    info!("cleanup: regenerating preinit.rc");
    if let Err(e) = module::regenerate_preinit_rc() {
        warn!("cleanup: regenerate_preinit_rc failed: {e}");
    }

    // Step 6: Prune (metauninstall → uninstall.sh → clear configs → optionally delete)
    // This is LAST so all identification above can read the module directory.
    // Minor fix: only run uninstall.sh on actual uninstall (delete_dir=true),
    // not on disable — matches Magisk semantics.
    info!("cleanup: running prune pipeline for {id}");
    module::prune_single_module(&module_path, delete_dir)?;

    // Note: sepolicy rules stay in kernel (additive-only limitation;
    // harmless allows cleaned at next real boot)
    info!("cleanup: module {id} cleanup complete");
    println!("✓ Module '{id}' cleanup complete. Sepolicy rules persist until next real boot.");

    Ok(())
}

/// Disable a module live: same pipeline minus directory deletion.
pub fn disable_module_apply(id: &str) -> Result<()> {
    module::validate_module_id(id)?;

    let module_path = Path::new(defs::MODULE_DIR).join(id);
    if !module_path.exists() {
        bail!("Module {id} not found");
    }

    // First set the disable marker (so it won't be active on next boot)
    let disable_path = module_path.join(defs::DISABLE_FILE_NAME);
    crate::utils::ensure_file_exists(&disable_path)?;

    info!("cleanup: disabling module {id} with live cleanup");
    // Fix #4: switch_mnt_ns is now inside cleanup_module, no separate call needed
    cleanup_module(id, false)
}

/// Uninstall a module live: full pipeline including directory deletion.
pub fn uninstall_module_apply(id: &str) -> Result<()> {
    // Fix #4: switch_mnt_ns(1) is now inside cleanup_module
    cleanup_module(id, true)
}

/// Bulk uninstall: loop over the same single-module path (no second implementation).
/// Fix #6: metamodule is sorted to the end so other modules can still use metamount.sh
/// during their cleanup.
pub fn uninstall_all_apply() -> Result<()> {
    // Collect module IDs first (before we start deleting)
    let modules_dir = Path::new(defs::MODULE_DIR);
    let mut ids: Vec<String> = match fs::read_dir(modules_dir) {
        Ok(dir) => dir
            .flatten()
            .filter(|e| e.path().is_dir() && e.path().join("module.prop").exists())
            .filter_map(|e| e.file_name().to_str().map(ToString::to_string))
            .collect(),
        Err(e) => {
            bail!("Failed to read modules dir: {e}");
        }
    };

    if ids.is_empty() {
        info!("cleanup: no modules to uninstall");
        return Ok(());
    }

    // Fix #6: Sort metamodule to end of list so its mount script
    // remains available for other modules' teardown.
    // sort_by_key on a bool is a total order (false < true) — a hand-rolled
    // comparator here can violate totality and panic at runtime.
    let metamodule_id = metamodule::get_metamodule_id();
    if let Some(ref meta_id) = metamodule_id {
        ids.sort_by_key(|id| id == meta_id);
    }

    info!("cleanup: bulk uninstall of {} modules", ids.len());

    let mut errors = Vec::new();
    for id in &ids {
        if let Err(e) = cleanup_module(id, true) {
            error!("cleanup: failed to uninstall {id}: {e}");
            errors.push(format!("{id}: {e}"));
        }
    }

    if !errors.is_empty() {
        warn!(
            "cleanup: {} modules failed to uninstall: {:?}",
            errors.len(),
            errors
        );
    }

    Ok(())
}
