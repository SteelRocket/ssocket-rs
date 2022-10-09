use crate::{InetAddress, Protocol, Shutdown, Socket, SocketType, AF};
use libc;

macro_rules! errno {
    () => {
        *libc::__errno_location().as_ref().unwrap()
    };
}

pub fn init() -> Result<(), i32> {
    Ok(())
}

pub fn cleanup() -> Result<(), i32> {
    Ok(())
}

/// Unix only
impl AF {
    pub const AF_ALG: AF = AF(libc::AF_ALG as i32);
    pub const AF_ASH: AF = AF(libc::AF_ASH as i32);
    pub const AF_ATMPVC: AF = AF(libc::AF_ATMPVC as i32);
    pub const AF_ATMSVC: AF = AF(libc::AF_ATMSVC as i32);
    pub const AF_AX25: AF = AF(libc::AF_AX25 as i32);
    pub const AF_BLUETOOTH: AF = AF(libc::AF_BLUETOOTH as i32);
    pub const AF_BRIDGE: AF = AF(libc::AF_BRIDGE as i32);
    pub const AF_CAIF: AF = AF(libc::AF_CAIF as i32);
    pub const AF_CAN: AF = AF(libc::AF_CAN as i32);
    pub const AF_ECONET: AF = AF(libc::AF_ECONET as i32);
    pub const AF_IB: AF = AF(libc::AF_IB as i32);
    pub const AF_IEEE802154: AF = AF(libc::AF_IEEE802154 as i32);
    pub const AF_ISDN: AF = AF(libc::AF_ISDN as i32);
    pub const AF_IUCV: AF = AF(libc::AF_IUCV as i32);
    pub const AF_KEY: AF = AF(libc::AF_KEY as i32);
    pub const AF_LLC: AF = AF(libc::AF_LLC as i32);
    pub const AF_LOCAL: AF = AF(libc::AF_LOCAL as i32);
    pub const AF_MPLS: AF = AF(libc::AF_MPLS as i32);
    pub const AF_NETBEUI: AF = AF(libc::AF_NETBEUI as i32);
    pub const AF_NETLINK: AF = AF(libc::AF_NETLINK as i32);
    pub const AF_NETROM: AF = AF(libc::AF_NETROM as i32);
    pub const AF_NFC: AF = AF(libc::AF_NFC as i32);
    pub const AF_PACKET: AF = AF(libc::AF_PACKET as i32);
    pub const AF_PHONET: AF = AF(libc::AF_PHONET as i32);
    pub const AF_PPPOX: AF = AF(libc::AF_PPPOX as i32);
    pub const AF_RDS: AF = AF(libc::AF_RDS as i32);
    pub const AF_ROSE: AF = AF(libc::AF_ROSE as i32);
    pub const AF_ROUTE: AF = AF(libc::AF_ROUTE as i32);
    pub const AF_RXRPC: AF = AF(libc::AF_RXRPC as i32);
    pub const AF_SECURITY: AF = AF(libc::AF_SECURITY as i32);
    pub const AF_TIPC: AF = AF(libc::AF_TIPC as i32);
    pub const AF_VSOCK: AF = AF(libc::AF_VSOCK as i32);
    pub const AF_WANPIPE: AF = AF(libc::AF_WANPIPE as i32);
    pub const AF_X25: AF = AF(libc::AF_X25 as i32);
    pub const AF_XDP: AF = AF(libc::AF_XDP as i32);
}

/// Unix only
impl SocketType {
    pub const SOCK_CLOEXEC: SocketType = SocketType(libc::SOCK_CLOEXEC);
    pub const SOCK_DCCP: SocketType = SocketType(libc::SOCK_DCCP);
    pub const SOCK_NONBLOCK: SocketType = SocketType(libc::SOCK_NONBLOCK);
    pub const SOCK_PACKET: SocketType = SocketType(libc::SOCK_PACKET);
}

/// Unix only
impl Protocol {
    pub const IPPROTO_BEETPH: Protocol = Protocol(libc::IPPROTO_BEETPH);
    pub const IPPROTO_COMP: Protocol = Protocol(libc::IPPROTO_COMP);
    pub const IPPROTO_DCCP: Protocol = Protocol(libc::IPPROTO_DCCP);
    pub const IPPROTO_ENCAP: Protocol = Protocol(libc::IPPROTO_ENCAP);
    pub const IPPROTO_GRE: Protocol = Protocol(libc::IPPROTO_GRE);
    pub const IPPROTO_IPIP: Protocol = Protocol(libc::IPPROTO_IPIP);
    pub const IPPROTO_MH: Protocol = Protocol(libc::IPPROTO_MH);
    pub const IPPROTO_MPLS: Protocol = Protocol(libc::IPPROTO_MPLS);
    pub const IPPROTO_MPTCP: Protocol = Protocol(libc::IPPROTO_MPTCP);
    pub const IPPROTO_MTP: Protocol = Protocol(libc::IPPROTO_MTP);
    pub const IPPROTO_RSVP: Protocol = Protocol(libc::IPPROTO_RSVP);
    pub const IPPROTO_TP: Protocol = Protocol(libc::IPPROTO_TP);
    pub const IPPROTO_UDPLITE: Protocol = Protocol(libc::IPPROTO_UDPLITE);
}

impl InetAddress {
    pub fn new(address: &str) -> Result<Self, u32> {
        if address.matches('.').count() != 3 {
            return Err(4294967295u32);
        }
        if !address.split('.').all(|x| x.parse::<u8>().is_ok()) {
            return Err(4294967295u32);
        }
        let mut parsed = address.split('.').map(|x| x.parse::<u8>().unwrap());
        let parsed_arr: [u8; 4] = core::array::from_fn(|_| parsed.next().unwrap());

        Ok(Self(u32::from_le_bytes(parsed_arr)))
    }
}

impl Socket {
    /// More info on [socket](https://man7.org/linux/man-pages/man2/socket.2.html)
    pub fn new(af: AF, socket_type: SocketType, protocol: Protocol) -> Result<Self, i32> {
        unsafe {
            let socket = libc::socket(af.0, socket_type.0, protocol.0);
            if socket == -1 {
                return Err(errno!());
            }
            Ok(Self {
                raw_handle: socket as usize,
            })
        }
    }

    /// More info on [bind](https://man7.org/linux/man-pages/man2/bind.2.html)
    pub fn bind(&self, af: AF, port: u16, addr: InetAddress) -> Result<(), i32> {
        unsafe {
            let addr = libc::sockaddr_in {
                sin_family: af.0 as u16,
                sin_port: port,
                sin_addr: libc::in_addr { s_addr: addr.0 },
                sin_zero: [0; 8],
            };
            let r = libc::bind(
                self.raw_handle as i32,
                &core::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(addr) as *const _,
                core::mem::size_of::<libc::sockaddr>() as u32,
            );
            if r == -1 {
                return Err(errno!());
            }
            Ok(())
        }
    }

    /// More info on [close](https://man7.org/linux/man-pages/man2/close.2.html)
    pub fn close(&self) -> Result<(), i32> {
        unsafe {
            if libc::close(self.raw_handle as i32) == -1 {
                return Err(errno!());
            }
            Ok(())
        }
    }

    /// More info on [connect](https://man7.org/linux/man-pages/man2/connect.2.html)
    pub fn connect(&self, af: AF, port: u16, addr: InetAddress) -> Result<(), i32> {
        unsafe {
            let addr = libc::sockaddr_in {
                sin_family: af.0 as u16,
                sin_port: port,
                sin_addr: libc::in_addr { s_addr: addr.0 },
                sin_zero: [0; 8],
            };

            let res = libc::connect(
                self.raw_handle as i32,
                &core::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(addr) as *const _,
                core::mem::size_of::<libc::sockaddr>() as u32,
            );
            if res == -1 {
                return Err(errno!());
            }
            Ok(())
        }
    }

    /// More info on [listen](https://man7.org/linux/man-pages/man2/listen.2.html)
    pub fn listen(&self, backlog: i32) -> Result<(), i32> {
        unsafe {
            if libc::listen(self.raw_handle as i32, backlog) == -1 {
                return Err(errno!());
            }
            Ok(())
        }
    }

    /// More info on [accept](https://man7.org/linux/man-pages/man2/accept.2.html)
    pub fn accept(&self) -> Result<Socket, &i32> {
        unsafe {
            let ret = libc::accept(
                self.raw_handle as i32,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            if ret == -1 {
                return Err(libc::__errno_location().as_ref().unwrap());
            }

            Ok(Self {
                raw_handle: ret as usize,
            })
        }
    }

    /// More info on [send](https://man7.org/linux/man-pages/man2/send.2.html)
    pub fn send(&self, message: &str, flags: i32) -> Result<isize, i32> {
        unsafe {
            let res = libc::send(
                self.raw_handle as i32,
                message.as_ptr() as *const libc::c_void,
                message.len(),
                flags,
            );

            if res == -1 {
                return Err(errno!());
            }
            Ok(res)
        }
    }

    /// More info on [recv](https://man7.org/linux/man-pages/man2/recv.2.html)
    pub fn recv(&self, buffer: &mut [u8], flags: i32) -> Result<i32, i32> {
        let buffer_ptr = buffer.as_mut_ptr();
        unsafe {
            let res = libc::recv(
                self.raw_handle as i32,
                buffer_ptr as *mut libc::c_void,
                buffer.len(),
                flags,
            );
            if res == -1 {
                return Err(res as i32);
            }
            Ok(res as i32)
        }
    }

    /// More info on [shutdown](https://man7.org/linux/man-pages/man2/shutdown.2.html)
    pub fn shutdown(&self, how: Shutdown) -> Result<(), i32> {
        unsafe {
            let res = libc::shutdown(self.raw_handle as i32, how.0);
            if res == -1 {
                return Err(res);
            }
            Ok(())
        }
    }

    /// More info on [setsockopt](https://man7.org/linux/man-pages/man2/setsockopt.2.html)
    pub fn setsockopt(&self, level: i32, optname: i32, optval: &str) -> Result<(), i32> {
        unsafe {
            let res = libc::setsockopt(
                self.raw_handle as i32,
                level,
                optname,
                optval.as_ptr() as *const libc::c_void,
                optval.len() as u32,
            );
            if res == -1 {
                return Err(res);
            }
            Ok(())
        }
    }
}
