//! BPF RBAC Daemon - Minimal implementation
//!
//! Provides role-based access control for BPF operations.

use anyhow::{Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{Group, Uid, User};
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener as TokioUnixListener;
use tracing::{error, info, warn};

use bpf_rbacd::policy::Policy;
use bpf_rbacd::protocol::{Request, Response};

const SOCKET_PATH: &str = "/run/bpf-rbac.sock";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("BPF RBAC Daemon starting");

    // Load or use default policy
    let policy = Policy::load("/etc/bpf-rbac/policy.yaml").unwrap_or_else(|_| {
        info!("Using default policy");
        Policy::default()
    });
    let policy = Arc::new(policy);

    info!("Loaded policy with {} roles", policy.roles.len());

    // Remove old socket
    let _ = std::fs::remove_file(SOCKET_PATH);

    // Create Unix socket
    let listener = TokioUnixListener::bind(SOCKET_PATH).context("Failed to bind socket")?;

    std::fs::set_permissions(
        SOCKET_PATH,
        std::os::unix::fs::PermissionsExt::from_mode(0o777),
    )?;

    info!("Listening on {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let policy = Arc::clone(&policy);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, policy).await {
                        error!("Client error: {}", e);
                    }
                });
            }
            Err(e) => error!("Accept error: {}", e),
        }
    }
}

async fn handle_client(stream: tokio::net::UnixStream, policy: Arc<Policy>) -> Result<()> {
    let std_stream = stream.into_std()?;

    // Get client credentials
    let cred = getsockopt(&std_stream, PeerCredentials)?;
    let uid = Uid::from_raw(cred.uid());
    let pid = cred.pid();

    info!("Client connected: uid={}, pid={}", uid, pid);

    // Get user's groups
    let groups = get_user_groups(uid)?;
    info!("Client groups: {:?}", groups);

    // Determine role
    let role = policy.get_role_for_groups(&groups);
    info!("Client role: {:?}", role);

    // Convert back to tokio stream
    std_stream.set_nonblocking(true)?;
    let mut stream = tokio::net::UnixStream::from_std(std_stream)?;

    // Read request
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request: Request = bincode::deserialize(&buf[..n])?;
    info!("Request: {:?}", request);

    // Check authorization and execute
    let response = match &role {
        Some(role_name) => {
            if policy.is_allowed(role_name, &request) {
                match execute_bpf(&request) {
                    Ok(fd) => {
                        info!("Operation succeeded, fd={}", fd);
                        Response::Success { fd: Some(fd) }
                    }
                    Err(e) => {
                        error!("BPF error: {}", e);
                        Response::Error {
                            message: e.to_string(),
                        }
                    }
                }
            } else {
                warn!("Denied for role {}", role_name);
                Response::Denied {
                    reason: format!("Role '{}' not allowed for {:?}", role_name, request),
                }
            }
        }
        None => Response::Denied {
            reason: "User not in any BPF RBAC group".to_string(),
        },
    };

    // For success with FD, send via SCM_RIGHTS with response embedded
    // For other responses, just write normally
    match &response {
        Response::Success { fd: Some(fd) } => {
            let response_bytes = bincode::serialize(&response)?;
            send_fd_with_data(&stream, *fd, &response_bytes)?;
        }
        _ => {
            let response_bytes = bincode::serialize(&response)?;
            stream.write_all(&response_bytes).await?;
        }
    }

    Ok(())
}

fn get_user_groups(uid: Uid) -> Result<Vec<String>> {
    let user = User::from_uid(uid)?.ok_or_else(|| anyhow::anyhow!("User not found"))?;

    let mut groups = Vec::new();

    // Primary group
    if let Ok(Some(g)) = Group::from_gid(user.gid) {
        groups.push(g.name);
    }

    // Supplementary groups
    let username = CString::new(user.name.as_str())?;
    if let Ok(group_list) = nix::unistd::getgrouplist(&username, user.gid) {
        for gid in group_list {
            if let Ok(Some(group)) = Group::from_gid(gid) {
                if !groups.contains(&group.name) {
                    groups.push(group.name);
                }
            }
        }
    }

    Ok(groups)
}

fn execute_bpf(request: &Request) -> Result<RawFd> {
    match request {
        Request::CreateMap {
            map_type,
            name,
            key_size,
            value_size,
            max_entries,
        } => create_bpf_map(map_type, name, *key_size, *value_size, *max_entries),
        Request::LoadProgram { .. } => {
            anyhow::bail!("Program loading not implemented in demo")
        }
        Request::Attach { .. } => {
            anyhow::bail!("Attach not implemented in demo")
        }
    }
}

fn create_bpf_map(
    map_type: &str,
    name: &str,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> Result<RawFd> {
    let map_type_num: u32 = match map_type {
        "hash" => 1,
        "array" => 2,
        "perf_event_array" => 4,
        "lru_hash" => 9,
        "ringbuf" => 27,
        _ => anyhow::bail!("Unsupported map type: {}", map_type),
    };

    let mut name_bytes = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    name_bytes[..len].copy_from_slice(&bytes[..len]);

    #[repr(C)]
    struct BpfAttr {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        inner_map_fd: u32,
        numa_node: u32,
        map_name: [u8; 16],
        map_ifindex: u32,
        btf_fd: u32,
        btf_key_type_id: u32,
        btf_value_type_id: u32,
        btf_vmlinux_value_type_id: u32,
        map_extra: u64,
    }

    let attr = BpfAttr {
        map_type: map_type_num,
        key_size,
        value_size,
        max_entries,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: name_bytes,
        map_ifindex: 0,
        btf_fd: 0,
        btf_key_type_id: 0,
        btf_value_type_id: 0,
        btf_vmlinux_value_type_id: 0,
        map_extra: 0,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            0i32, // BPF_MAP_CREATE
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfAttr>(),
        )
    };

    if fd < 0 {
        anyhow::bail!("BPF_MAP_CREATE failed: {}", std::io::Error::last_os_error());
    }

    Ok(fd as RawFd)
}

fn send_fd_with_data(stream: &tokio::net::UnixStream, fd: RawFd, data: &[u8]) -> Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;

    let raw = stream.as_raw_fd();
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let iov = [IoSlice::new(data)];

    sendmsg::<()>(raw, &iov, &cmsg, MsgFlags::empty(), None)?;
    Ok(())
}
