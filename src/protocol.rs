//! Protocol definitions for client-daemon communication

use serde::{Deserialize, Serialize};
use std::os::unix::io::RawFd;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    LoadProgram {
        prog_type: String,
        object_path: String,
        program_name: String,
    },
    CreateMap {
        map_type: String,
        name: String,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    },
    Attach {
        attach_type: String,
        prog_fd: RawFd,
        target: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Success { fd: Option<RawFd> },
    Denied { reason: String },
    Error { message: String },
}

pub mod client {
    use super::*;
    use anyhow::Result;
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    use std::io::{IoSliceMut, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    const SOCKET_PATH: &str = "/run/bpf-rbac.sock";

    pub struct BpfRbacClient {
        stream: UnixStream,
    }

    impl BpfRbacClient {
        pub fn connect() -> Result<Self> {
            let stream = UnixStream::connect(SOCKET_PATH)?;
            Ok(Self { stream })
        }

        pub fn create_map(
            &mut self,
            map_type: &str,
            name: &str,
            key_size: u32,
            value_size: u32,
            max_entries: u32,
        ) -> Result<RawFd> {
            let request = Request::CreateMap {
                map_type: map_type.to_string(),
                name: name.to_string(),
                key_size,
                value_size,
                max_entries,
            };

            // Send request
            let bytes = bincode::serialize(&request)?;
            self.stream.write_all(&bytes)?;

            // Receive response with potential FD
            let (response, fd) = self.recv_response_with_fd()?;

            match response {
                Response::Success { fd: Some(_) } => {
                    fd.ok_or_else(|| anyhow::anyhow!("Expected FD but none received"))
                }
                Response::Success { fd: None } => {
                    anyhow::bail!("No FD in response")
                }
                Response::Denied { reason } => {
                    anyhow::bail!("Denied: {}", reason)
                }
                Response::Error { message } => {
                    anyhow::bail!("Error: {}", message)
                }
            }
        }

        fn recv_response_with_fd(&self) -> Result<(Response, Option<RawFd>)> {
            let raw_fd = self.stream.as_raw_fd();

            let mut buf = [0u8; 4096];
            let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);

            let (bytes_received, received_fd) = {
                let mut iov = [IoSliceMut::new(&mut buf)];
                let msg = recvmsg::<()>(raw_fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())?;

                let mut fd = None;
                for cmsg in msg.cmsgs() {
                    if let ControlMessageOwned::ScmRights(fds) = cmsg {
                        if let Some(&f) = fds.first() {
                            fd = Some(f);
                        }
                    }
                }
                (msg.bytes, fd)
            };

            let response: Response = bincode::deserialize(&buf[..bytes_received])?;
            Ok((response, received_fd))
        }
    }
}
