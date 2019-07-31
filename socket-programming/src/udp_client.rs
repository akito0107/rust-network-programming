use std::net::UdpSocket;
use std::{io, str};

pub fn communicate(address: &str) -> Result<(), failure::Error> {
    let socket = UdpSocket::bind(address)?;
    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        socket.send_to(input.as_bytes(), address)?;

        let mut buffer = [0u8; 1024];
        print!(
            "{}",
            socket
                .recv_from(&buffer)
                .expect("failed to convert to String")
        );
    }
}
