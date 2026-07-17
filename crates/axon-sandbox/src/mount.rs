//! Mount-namespace root setup for the clean worker (design §13.1).
//!
//! [`setup_root`] builds the worker's filesystem view inside a fresh mount
//! namespace and `pivot_root`s into it: a tmpfs root holding the digest-pinned
//! runtime as read-only binds and writable tmpfs scratch/output. After it
//! returns, the host filesystem is gone — only what the [`SandboxSpec`] named is
//! reachable. (A private `/proc` is mounted separately, once a PID namespace
//! exists — proc is tied to the PID namespace.)
//!
//! Called in the forked child after [`enter_namespaces`](crate::enter_namespaces)
//! (which must include [`Mount`](crate::Namespace::Mount)), before dropping
//! privileges and exec. Needs unprivileged user namespaces, so the live test is
//! `#[ignore]`d and runs in CI's `isolation` job or locally once userns is on.

use std::ffi::CString;
use std::io;

use crate::launcher::SandboxSpec;

/// Why building the sandbox root failed. Carries the failing step for diagnosis.
#[derive(Debug, thiserror::Error)]
#[error("sandbox root setup failed at {step} (errno {errno})")]
pub struct MountError {
    pub step: &'static str,
    pub errno: i32,
}

fn err(step: &'static str) -> MountError {
    MountError {
        step,
        errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
    }
}

fn cstr(s: &str) -> Result<CString, MountError> {
    CString::new(s).map_err(|_| MountError {
        step: "cstring",
        errno: 0,
    })
}

/// `mount(2)` wrapper. Empty `fstype`/`data` are passed as NULL.
fn do_mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: &str,
    step: &'static str,
) -> Result<(), MountError> {
    let (src, tgt, fst, dat) = (cstr(source)?, cstr(target)?, cstr(fstype)?, cstr(data)?);
    let fst_p = if fstype.is_empty() {
        std::ptr::null()
    } else {
        fst.as_ptr()
    };
    let dat_p = if data.is_empty() {
        std::ptr::null()
    } else {
        dat.as_ptr() as *const libc::c_void
    };
    // SAFETY: all pointers are valid C strings (or NULL); flags are valid mount flags.
    let rc = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst_p, flags, dat_p) };
    if rc == 0 {
        Ok(())
    } else {
        Err(err(step))
    }
}

/// The mount flags currently set on `target` (nosuid/nodev/noexec/atime), mapped
/// to their `MS_*` form. A read-only remount inside a user namespace must re-apply
/// these, since the kernel forbids clearing flags locked when the userns was made.
fn locked_flags(target: &str) -> Result<libc::c_ulong, MountError> {
    let t = cstr(target)?;
    // SAFETY: t is a valid C string; statvfs fills the zeroed struct.
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(t.as_ptr(), &mut vfs) } != 0 {
        return Err(err("statvfs"));
    }
    let mut ms: libc::c_ulong = 0;
    for (st, msf) in [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ] {
        if vfs.f_flag & st != 0 {
            ms |= msf;
        }
    }
    Ok(ms)
}

fn mkdir(path: &str, step: &'static str) -> Result<(), MountError> {
    let p = cstr(path)?;
    // SAFETY: p is a valid C string.
    let rc = unsafe { libc::mkdir(p.as_ptr(), 0o755) };
    // EEXIST is fine — the directory already being there is not a failure.
    if rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(err(step))
    }
}

/// Builds and pivots into the worker's root from `spec` (design §13.1). On
/// success the process is chrooted into a minimal filesystem: `/proc`, the
/// read-only runtime binds, and the tmpfs scratch/output — nothing else.
pub fn setup_root(spec: &SandboxSpec) -> Result<(), MountError> {
    // 1. Make the whole tree private so our mounts don't propagate to the host
    //    and host mount events don't leak in.
    do_mount(
        "none",
        "/",
        "",
        libc::MS_REC | libc::MS_PRIVATE,
        "",
        "make-rprivate",
    )?;

    // 2. A fresh tmpfs is the new root (must be a mount point for pivot_root).
    // SAFETY: getpid is always safe.
    let pid = unsafe { libc::getpid() };
    let newroot = format!("/tmp/.axon-root-{pid}");
    mkdir(&newroot, "mkdir-newroot")?;
    do_mount("tmpfs", &newroot, "tmpfs", 0, "mode=0755", "tmpfs-newroot")?;

    // (A private /proc is mounted separately, after entering a PID namespace —
    // proc is tied to the PID namespace and cannot be mounted without one.)

    // 3. Read-only, digest-pinned runtime binds.
    for (host, sandbox) in &spec.ro_binds {
        let target = format!("{newroot}{sandbox}");
        mkdir(&target, "mkdir-robind")?;
        do_mount(host, &target, "", libc::MS_BIND, "", "bind-ro")?;
        // A bind mount is read-write until remounted. Inside a user namespace the
        // read-only remount must preserve the mount's locked flags (nosuid, nodev,
        // …) or the kernel refuses it with EPERM — so read them back and re-apply.
        let preserved = locked_flags(&target)?;
        do_mount(
            "none",
            &target,
            "",
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | preserved,
            "",
            "remount-ro",
        )?;
    }

    // 5. Writable scratch/output tmpfs.
    for path in &spec.tmpfs {
        let target = format!("{newroot}{path}");
        mkdir(&target, "mkdir-tmpfs")?;
        do_mount("tmpfs", &target, "tmpfs", 0, "mode=0755", "mount-tmpfs")?;
    }

    // 6. pivot_root into the new root and detach the old one.
    let oldroot = format!("{newroot}/oldroot");
    mkdir(&oldroot, "mkdir-oldroot")?;
    chdir(&newroot, "chdir-newroot")?;
    pivot_root(".", "oldroot")?;
    chroot(".")?;
    chdir("/", "chdir-root")?;
    // Detach the old root so the host filesystem is unreachable.
    let old = cstr("/oldroot")?;
    // SAFETY: old is a valid C string.
    if unsafe { libc::umount2(old.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(err("umount-oldroot"));
    }
    // SAFETY: old is a valid C string.
    unsafe { libc::rmdir(old.as_ptr()) };
    Ok(())
}

fn chdir(path: &str, step: &'static str) -> Result<(), MountError> {
    let p = cstr(path)?;
    // SAFETY: p is a valid C string.
    if unsafe { libc::chdir(p.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(err(step))
    }
}

fn chroot(path: &str) -> Result<(), MountError> {
    let p = cstr(path)?;
    // SAFETY: p is a valid C string.
    if unsafe { libc::chroot(p.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(err("chroot"))
    }
}

fn pivot_root(new_root: &str, put_old: &str) -> Result<(), MountError> {
    let (n, o) = (cstr(new_root)?, cstr(put_old)?);
    // SAFETY: both are valid C strings; SYS_pivot_root takes two path pointers.
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, n.as_ptr(), o.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(err("pivot-root"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::enter_namespaces;
    use crate::launcher::Namespace;
    use std::fs;

    /// Live: after `setup_root`, the worker sees only its sandbox — a read of a
    /// read-only bind works, a write to it and to an unbound host path is denied,
    /// scratch is writable, and `/proc` is present. Needs unprivileged userns.
    #[test]
    #[ignore = "needs unprivileged user namespaces; runs in CI's isolation job"]
    fn pivoted_root_exposes_only_the_sandbox() {
        // Host layout (visible only before pivot): a runtime dir with a file, and
        // a secret outside it that must vanish from the sandbox.
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("axon-mnt-{pid}"));
        let runtime = base.join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        fs::write(runtime.join("lib"), b"runtime").unwrap();
        let secret = base.join("secret");
        fs::write(&secret, b"host-only").unwrap();

        let spec = SandboxSpec::clean_worker("/")
            .ro_bind(runtime.to_str().unwrap(), "/runtime")
            .tmpfs("/scratch");
        let secret_path = CString::new(secret.to_str().unwrap()).unwrap();

        // SAFETY: the child does mount setup + path opens, then _exit.
        let code = match unsafe { libc::fork() } {
            -1 => panic!("fork failed"),
            0 => {
                if enter_namespaces(&[Namespace::User, Namespace::Mount, Namespace::Net]).is_err() {
                    unsafe { libc::_exit(90) };
                }
                if let Err(e) = setup_root(&spec) {
                    eprintln!("setup_root failed: {e}");
                    unsafe { libc::_exit(91) };
                }
                let open = |p: &str, flags: i32| {
                    let c = CString::new(p).unwrap();
                    unsafe { libc::open(c.as_ptr(), flags) }
                };
                // Read of the read-only bind works.
                if open("/runtime/lib", libc::O_RDONLY) < 0 {
                    unsafe { libc::_exit(92) };
                }
                // Writing into the read-only bind is denied.
                if open("/runtime/new", libc::O_WRONLY | libc::O_CREAT) >= 0 {
                    unsafe { libc::_exit(93) };
                }
                // Scratch tmpfs is writable.
                if open("/scratch/out", libc::O_WRONLY | libc::O_CREAT) < 0 {
                    unsafe { libc::_exit(94) };
                }
                // The host secret (by its original absolute path) is gone.
                if unsafe { libc::open(secret_path.as_ptr(), libc::O_RDONLY) } >= 0 {
                    unsafe { libc::_exit(96) };
                }
                unsafe { libc::_exit(0) };
            }
            pid => {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                assert!(libc::WIFEXITED(status), "child should exit normally");
                libc::WEXITSTATUS(status)
            }
        };

        let _ = fs::remove_dir_all(&base);
        match code {
            0 => {}
            90 => panic!("entering namespaces failed"),
            91 => panic!("setup_root failed"),
            92 => panic!("read of the read-only bind failed"),
            93 => panic!("write to the read-only bind was allowed"),
            94 => panic!("write to scratch tmpfs failed"),
            96 => panic!("host secret was still reachable — pivot_root did not isolate"),
            other => panic!("unexpected child exit code {other}"),
        }
    }
}
