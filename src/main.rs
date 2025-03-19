use std::{error::Error, fmt::Display};
use clap::{Parser, ValueEnum};
use pnet::{
    packet::tcp,
    transport::tcp_packet_iter,
};

#[derive(Debug, Clone, ValueEnum)]
enum ScanType {
    Syn,
    Connect,
}

impl Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Syn => write!(f, "SYN"),
            ScanType::Connect => write!(f, "Connect"),
        }
    }
}

// Rust port scanner
#[derive(Parser)]
struct Cli {
    // Ip address to scan
    #[clap(short, long)]
    ip: std::net::Ipv4Addr,
    // Port to scan
    #[clap(short, long, default_value = "80")]
    port: u16,

    // Scan type
    #[clap(short, long, default_value = "syn")]
    scan_type: ScanType,
}

fn scan_syn(ip: std::net::Ipv4Addr, port: u16) -> Result<bool, Box<dyn std::error::Error>> {
    let protocol = pnet::transport::TransportChannelType::Layer4(
        pnet::transport::TransportProtocol::Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Tcp),
    );
    let (mut tx, mut rx) = pnet::transport::transport_channel(1024, protocol)?;

    let mut buf = [0u8; tcp::TcpPacket::minimum_packet_size()];
    let mut packet = tcp::MutableTcpPacket::new(&mut buf).unwrap();

    let src_port = rand::random::<u16>();

    packet.set_destination(port);
    packet.set_source(src_port);
    packet.set_sequence(rand::random::<u32>());
    packet.set_acknowledgement(0);
    packet.set_reserved(0);
    packet.set_options(&[]);
    packet.set_data_offset(5);
    packet.set_flags(tcp::TcpFlags::SYN);
    packet.set_window(64240);

    let checksum = tcp::ipv4_checksum(&packet.to_immutable(), &ip, &ip);
    packet.set_checksum(checksum);

    tx.send_to(packet.to_immutable(), ip.into())
        .expect("Could not send packet");

    loop {
        let mut res = tcp_packet_iter(&mut rx);
        let result = res
            .next_with_timeout(std::time::Duration::from_secs(1))
            .expect("Failed to receive packet");
        match result {
            Some(p) => {
                let packet = p.0;
                if packet.get_destination() == src_port && packet.get_source() == port {
                    if packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK {
                        println!("Port {} is open", port);
                        return Ok(true);
                    } else {
                        println!("Port {} is closed", port);
                        return Ok(false);
                    }
                }
            }
            None => {
                println!("Port {} is filtered", port);
                return Ok(false);
            }
        }
    }
}

fn scan_connect(ip: std::net::Ipv4Addr, port: u16) -> bool {
    let socket_addr = std::net::SocketAddr::new(ip.into(), port);
    let socket =
        std::net::TcpStream::connect_timeout(&socket_addr, std::time::Duration::from_secs(1));
    match socket {
        Ok(_) => {
            println!("Port {} is open", port);
            true
        }
        Err(_) => {
            println!("Port {} is closed", port);
            false
        }
    }
}

fn scan(ip: std::net::Ipv4Addr, port: u16, scan_type: ScanType) -> Result<bool, Box<dyn Error>> {
    match scan_type {
        ScanType::Syn => scan_syn(ip, port),
        ScanType::Connect => Ok(scan_connect(ip, port)),
    }
}

fn main() {
    let args = Cli::parse();
    println!(
        "Scanning {} on port {} using method {}",
        args.ip, args.port, args.scan_type
    );
    match scan(args.ip, args.port, args.scan_type)
    {
        Ok(_) => {}
        Err(e) => eprintln!("Error: {}", e),
    }
}
