use ssocket::{self, InetAddress, Protocol, SocketType, AF};

fn main() {
    ssocket::init().unwrap();

    let ss = ssocket::Socket::new(AF::AF_INET, SocketType::SOCK_STREAM, Protocol::DEFAULT).unwrap();
    ss.bind(AF::AF_INET, 5000, InetAddress::new("127.0.0.1").unwrap())
        .unwrap();
    ss.listen(0).unwrap();

    loop {
        let sock = ss.accept().unwrap();
        sock.send("ping!", 0).unwrap();
        sock.close().unwrap();
    }

    ssocket::cleanup().unwrap();
}
