use ssocket::{self, InetAddress, Protocol, Socket, SocketType, AF};

fn main() {
    ssocket::init().unwrap();

    let sock = Socket::new(AF::AF_INET, SocketType::SOCK_STREAM, Protocol::DEFAULT).unwrap();
    sock.connect(AF::AF_INET, 5000, InetAddress::new("127.0.0.1").unwrap())
        .unwrap();

    let mut buffer = [0; 1024];
    sock.recv(&mut buffer, 0).unwrap();

    println!(
        "{}",
        core::str::from_utf8(&buffer).unwrap().trim_matches('\0') // Convert to string and remove null termination
    );

    ssocket::cleanup().unwrap();
}
