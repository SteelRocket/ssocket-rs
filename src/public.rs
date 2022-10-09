#[derive(Debug, Clone)]
pub struct Socket {
    pub raw_handle: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct AF(pub i32);

#[derive(Debug, Clone, Copy)]
pub struct SocketType(pub i32);

#[derive(Debug, Clone, Copy)]
pub struct Protocol(pub i32);

#[derive(Debug, Clone, Copy)]
pub struct InetAddress(pub u32);

#[derive(Debug, Clone, Copy)]
pub struct Shutdown(pub i32);

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock as sock;

#[cfg(unix)]
use libc as sock;

/// Common for both windows and unix
impl Shutdown {
    pub const RECEIVE: Shutdown = Shutdown(0);
    pub const SEND: Shutdown = Shutdown(1);
    pub const BOTH: Shutdown = Shutdown(2);
}

/// Common for both windows and unix
impl AF {
    pub const AF_APPLETALK: AF = AF(sock::AF_APPLETALK as i32);
    pub const AF_DECNET: AF = AF(sock::AF_DECnet as i32);
    pub const AF_INET: AF = AF(sock::AF_INET as i32);
    pub const AF_INET6: AF = AF(sock::AF_INET6 as i32);
    pub const AF_IPX: AF = AF(sock::AF_IPX as i32);
    pub const AF_IRDA: AF = AF(sock::AF_IRDA as i32);
    pub const AF_SNA: AF = AF(sock::AF_SNA as i32);
    pub const AF_UNIX: AF = AF(sock::AF_UNIX as i32);
    pub const AF_UNSPEC: AF = AF(sock::AF_UNSPEC as i32);
}

/// Common for both windows and unix
impl SocketType {
    pub const SOCK_DGRAM: SocketType = SocketType(sock::SOCK_DGRAM as i32);
    pub const SOCK_RAW: SocketType = SocketType(sock::SOCK_RAW as i32);
    pub const SOCK_RDM: SocketType = SocketType(sock::SOCK_RDM as i32);
    pub const SOCK_SEQPACKET: SocketType = SocketType(sock::SOCK_SEQPACKET as i32);
    pub const SOCK_STREAM: SocketType = SocketType(sock::SOCK_STREAM as i32);
}

/// Common for both windows and unix
impl Protocol {
    pub const DEFAULT: Protocol = Protocol(0);
    pub const IPPROTO_AH: Protocol = Protocol(sock::IPPROTO_AH);
    pub const IPPROTO_DSTOPTS: Protocol = Protocol(sock::IPPROTO_DSTOPTS);
    pub const IPPROTO_EGP: Protocol = Protocol(sock::IPPROTO_EGP);
    pub const IPPROTO_ESP: Protocol = Protocol(sock::IPPROTO_ESP);
    pub const IPPROTO_FRAGMENT: Protocol = Protocol(sock::IPPROTO_FRAGMENT);
    pub const IPPROTO_HOPOPTS: Protocol = Protocol(sock::IPPROTO_HOPOPTS);
    pub const IPPROTO_ICMP: Protocol = Protocol(sock::IPPROTO_ICMP);
    pub const IPPROTO_ICMPV6: Protocol = Protocol(sock::IPPROTO_ICMPV6);
    pub const IPPROTO_IDP: Protocol = Protocol(sock::IPPROTO_IDP);
    pub const IPPROTO_IGMP: Protocol = Protocol(sock::IPPROTO_IGMP);
    pub const IPPROTO_IP: Protocol = Protocol(sock::IPPROTO_IP as i32);
    pub const IPPROTO_IPV6: Protocol = Protocol(sock::IPPROTO_IPV6);
    pub const IPPROTO_NONE: Protocol = Protocol(sock::IPPROTO_NONE);
    pub const IPPROTO_PIM: Protocol = Protocol(sock::IPPROTO_PIM);
    pub const IPPROTO_PUP: Protocol = Protocol(sock::IPPROTO_PUP);
    pub const IPPROTO_RAW: Protocol = Protocol(sock::IPPROTO_RAW);
    pub const IPPROTO_ROUTING: Protocol = Protocol(sock::IPPROTO_ROUTING);
    pub const IPPROTO_SCTP: Protocol = Protocol(sock::IPPROTO_SCTP);
    pub const IPPROTO_TCP: Protocol = Protocol(sock::IPPROTO_TCP);
    pub const IPPROTO_UDP: Protocol = Protocol(sock::IPPROTO_UDP);
}
