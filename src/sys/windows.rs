use crate::{InetAddress, Protocol, Shutdown, Socket, SocketType, AF};
use windows_sys::Win32::Networking::WinSock;

/// Starts Winsock. Required on windows.
pub fn init() -> Result<(), i32> {
    unsafe {
        let mut wsa_data = core::mem::MaybeUninit::<WinSock::WSADATA>::uninit();

        let error = WinSock::WSAStartup(514, wsa_data.as_mut_ptr());

        if error != 0 {
            return Err(WinSock::WSAGetLastError());
        }
        Ok(())
    }
}

/// Closes Winsock. Required on windows.
pub fn cleanup() -> Result<(), i32> {
    unsafe {
        let res = WinSock::WSACleanup();
        if res == WinSock::SOCKET_ERROR {
            return Err(WinSock::WSAGetLastError());
        }
        Ok(())
    }
}

/// Windows only
impl AF {
    pub const AF_12844: AF = AF(WinSock::AF_12844 as i32);
    pub const AF_ATM: AF = AF(WinSock::AF_ATM as i32);
    pub const AF_BAN: AF = AF(WinSock::AF_BAN as i32);
    pub const AF_CCITT: AF = AF(WinSock::AF_CCITT as i32);
    pub const AF_CHAOS: AF = AF(WinSock::AF_CHAOS as i32);
    pub const AF_CLUSTER: AF = AF(WinSock::AF_CLUSTER as i32);
    pub const AF_DATAKIT: AF = AF(WinSock::AF_DATAKIT as i32);
    pub const AF_DLI: AF = AF(WinSock::AF_DLI as i32);
    pub const AF_ECMA: AF = AF(WinSock::AF_ECMA as i32);
    pub const AF_FIREFOX: AF = AF(WinSock::AF_FIREFOX as i32);
    pub const AF_HYLINK: AF = AF(WinSock::AF_HYLINK as i32);
    pub const AF_HYPERV: AF = AF(WinSock::AF_HYPERV as i32);
    pub const AF_ICLFXBM: AF = AF(WinSock::AF_ICLFXBM as i32);
    pub const AF_IMPLINK: AF = AF(WinSock::AF_IMPLINK as i32);
    pub const AF_ISO: AF = AF(WinSock::AF_ISO as i32);
    pub const AF_LAT: AF = AF(WinSock::AF_LAT as i32);
    pub const AF_LINK: AF = AF(WinSock::AF_LINK as i32);
    pub const AF_MAX: AF = AF(WinSock::AF_MAX as i32);
    pub const AF_NETBIOS: AF = AF(WinSock::AF_NETBIOS as i32);
    pub const AF_NETDES: AF = AF(WinSock::AF_NETDES as i32);
    pub const AF_NS: AF = AF(WinSock::AF_NS as i32);
    pub const AF_OSI: AF = AF(WinSock::AF_OSI as i32);
    pub const AF_PUP: AF = AF(WinSock::AF_PUP as i32);
    pub const AF_TCNMESSAGE: AF = AF(WinSock::AF_TCNMESSAGE as i32);
    pub const AF_TCNPROCESS: AF = AF(WinSock::AF_TCNPROCESS as i32);
    pub const AF_UNKNOWN1: AF = AF(WinSock::AF_UNKNOWN1 as i32);
    pub const AF_VOICEVIEW: AF = AF(WinSock::AF_VOICEVIEW as i32);
}

/// Windows only
impl Protocol {
    pub const IPPROTO_CBT: Protocol = Protocol(WinSock::IPPROTO_CBT);
    pub const IPPROTO_GGP: Protocol = Protocol(WinSock::IPPROTO_GGP);
    pub const IPPROTO_ICLFXBM: Protocol = Protocol(WinSock::IPPROTO_ICLFXBM);
    pub const IPPROTO_IGP: Protocol = Protocol(WinSock::IPPROTO_IGP);
    pub const IPPROTO_IPV4: Protocol = Protocol(WinSock::IPPROTO_IPV4);
    pub const IPPROTO_L2TP: Protocol = Protocol(WinSock::IPPROTO_L2TP);
    pub const IPPROTO_MAX: Protocol = Protocol(WinSock::IPPROTO_MAX);
    pub const IPPROTO_ND: Protocol = Protocol(WinSock::IPPROTO_ND);
    pub const IPPROTO_PGM: Protocol = Protocol(WinSock::IPPROTO_PGM);
    pub const IPPROTO_RDP: Protocol = Protocol(WinSock::IPPROTO_RDP);
    pub const IPPROTO_RESERVED_IPSEC: Protocol = Protocol(WinSock::IPPROTO_RESERVED_IPSEC);
    pub const IPPROTO_RESERVED_IPSECOFFLOAD: Protocol =
        Protocol(WinSock::IPPROTO_RESERVED_IPSECOFFLOAD);
    pub const IPPROTO_RESERVED_MAX: Protocol = Protocol(WinSock::IPPROTO_RESERVED_MAX);
    pub const IPPROTO_RESERVED_RAW: Protocol = Protocol(WinSock::IPPROTO_RESERVED_RAW);
    pub const IPPROTO_RESERVED_WNV: Protocol = Protocol(WinSock::IPPROTO_RESERVED_WNV);
    pub const IPPROTO_RM: Protocol = Protocol(WinSock::IPPROTO_RM as i32);
    pub const IPPROTO_ST: Protocol = Protocol(WinSock::IPPROTO_ST);
}

impl InetAddress {
    pub fn new(address: &str) -> Result<Self, u32> {
        unsafe {
            let ret = WinSock::inet_addr(address.as_ptr() as *mut _);
            if ret == WinSock::INADDR_NONE {
                return Err(ret);
            }
            Ok(Self(ret))
        }
    }
}

impl Socket {
    /// More info on [socket](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket)
    pub fn new(af: AF, socket_type: SocketType, protocol: Protocol) -> Result<Self, i32> {
        unsafe {
            let socket = WinSock::socket(af.0, socket_type.0, protocol.0);
            if socket == WinSock::INVALID_SOCKET {
                return Err(WinSock::WSAGetLastError());
            }
            Ok(Self { raw_handle: socket })
        }
    }

    /// More info on [bind](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-bind)
    pub fn bind(&self, af: AF, port: u16, addr: InetAddress) -> Result<(), i32> {
        unsafe {
            let addr = WinSock::SOCKADDR_IN {
                sin_family: af.0 as u16,
                sin_port: WinSock::htons(port),
                sin_addr: WinSock::IN_ADDR {
                    S_un: WinSock::IN_ADDR_0 { S_addr: addr.0 },
                },
                sin_zero: [0; 8],
            };

            let r = WinSock::bind(
                self.raw_handle,
                &mut core::mem::transmute::<WinSock::SOCKADDR_IN, WinSock::SOCKADDR>(addr)
                    as *mut _,
                core::mem::size_of::<WinSock::SOCKADDR>() as i32,
            );

            if r == WinSock::SOCKET_ERROR {
                return Err(WinSock::WSAGetLastError());
            }
            Ok(())
        }
    }

    /// More info on [close](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-closesocket)
    pub fn close(&self) -> Result<(), i32> {
        unsafe {
            if WinSock::closesocket(self.raw_handle) == WinSock::SOCKET_ERROR {
                return Err(WinSock::SOCKET_ERROR);
            }
            Ok(())
        }
    }

    /// More info on [connect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect)
    pub fn connect(&self, af: AF, port: u16, addr: InetAddress) -> Result<(), i32> {
        unsafe {
            let addr = WinSock::SOCKADDR_IN {
                sin_family: af.0 as u16,
                sin_port: WinSock::htons(port),
                sin_addr: WinSock::IN_ADDR {
                    S_un: WinSock::IN_ADDR_0 { S_addr: addr.0 },
                },
                sin_zero: [0; 8],
            };
            let res = WinSock::connect(
                self.raw_handle,
                &mut core::mem::transmute::<WinSock::SOCKADDR_IN, WinSock::SOCKADDR>(addr)
                    as *mut _,
                core::mem::size_of::<WinSock::SOCKADDR>() as i32,
            );
            if res == WinSock::SOCKET_ERROR {
                return Err(WinSock::WSAGetLastError());
            }
            Ok(())
        }
    }

    /// More info on [listen](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen)
    pub fn listen(&self, backlog: i32) -> Result<(), i32> {
        unsafe {
            if WinSock::listen(self.raw_handle, backlog) == WinSock::SOCKET_ERROR {
                return Err(WinSock::WSAGetLastError());
            }
            Ok(())
        }
    }

    /// More info on [accept](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept)
    pub fn accept(&self) -> Result<Socket, i32> {
        unsafe {
            let ret = WinSock::accept(
                self.raw_handle,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            if ret == WinSock::INVALID_SOCKET {
                return Err(WinSock::WSAGetLastError());
            }

            Ok(Self { raw_handle: ret })
        }
    }

    /// More info on [send](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send)
    pub fn send(&self, message: &str, flags: i32) -> Result<isize, i32> {
        unsafe {
            let res = WinSock::send(
                self.raw_handle,
                message.as_ptr() as *const _,
                message.len() as i32,
                flags,
            );
            if res == WinSock::SOCKET_ERROR {
                return Err(WinSock::WSAGetLastError());
            }
            Ok(res as isize)
        }
    }

    /// More info on [recv](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recv)
    pub fn recv(&self, buffer: &mut [u8], flags: i32) -> Result<i32, i32> {
        unsafe {
            let res = WinSock::recv(
                self.raw_handle,
                buffer.as_mut_ptr(),
                buffer.len() as i32,
                flags,
            );
            if res == WinSock::SOCKET_ERROR {
                return Err(WinSock::WSAGetLastError());
            }
            Ok(res)
        }
    }

    /// More info on [shutdown](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-shutdown)
    pub fn shutdown(&self, how: Shutdown) -> Result<(), i32> {
        unsafe {
            let res = WinSock::shutdown(self.raw_handle, how.0);
            if res == WinSock::SOCKET_ERROR {
                return Err(WinSock::WSAGetLastError());
            }
            Ok(())
        }
    }

    /// More info on [setsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-setsockopt)
    pub fn setsockopt(&self, level: i32, optname: i32, optval: &str) -> Result<(), i32> {
        unsafe {
            let res = WinSock::setsockopt(
                self.raw_handle,
                level,
                optname,
                optval.as_ptr() as *const _,
                optval.len() as i32,
            );
            if res == WinSock::SOCKET_ERROR {
                return Err(WinSock::WSAGetLastError());
            }
            Ok(())
        }
    }
}
