use cidr::{Ipv4Cidr, Ipv6Cidr};
use clap::{Parser, ValueEnum};
use pnet::{
    packet::{ip::IpNextHeaderProtocols, tcp::{self, TcpOption}},
    transport::{tcp_packet_iter, TransportChannelType, TransportProtocol},
};
use std::{
    error::Error, fmt::Display, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs}, vec::IntoIter
};

#[derive(Debug, Clone, ValueEnum, PartialEq, Copy)]
enum ScanType {
    Syn,
    Connect,
    Fin,
}

impl Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Syn => write!(f, "SYN"),
            ScanType::Connect => write!(f, "Connect"),
            ScanType::Fin => write!(f, "FIN"),
        }
    }
}

// Rust port scanner
#[derive(Parser)]
struct Cli {
    // IP address, hostname, or CIDR range to scan
    #[clap(short = 'H', long)]
    host: String,

    // Port to scan
    #[clap(short, long, default_value = "80")]
    port: u16,

    // Scan type
    #[clap(short, long, default_value = "syn")]
    scan_type: ScanType,

    // Timeout in seconds (max 255)
    #[clap(short, long, default_value = "1")]
    timeout: u8,
}

fn scan_raw(
    ip: IpAddr,
    port: u16,
    timeout: u8,
    st: ScanType,
) -> Result<bool, Box<dyn std::error::Error>> {
    match ip {
        IpAddr::V4(ipv4) => scan_raw_ipv4(ipv4, port, timeout, st),
        IpAddr::V6(ipv6) => scan_raw_ipv6(ipv6, port, timeout, st),
    }
}

fn scan_raw_ipv4(
    ip: Ipv4Addr,
    port: u16,
    timeout: u8,
    scan_type: ScanType,
) -> Result<bool, Box<dyn std::error::Error>> {
    let protocol =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = pnet::transport::transport_channel(1024, protocol)?;

    let mut buf = [0u8; 60];
    let mut packet = tcp::MutableTcpPacket::new(&mut buf).unwrap();

    let src_ip = match get_source_ip_for_target(&ip.into()) {
        Ok(src) => {
            match src {
                IpAddr::V4(ip) => ip,
                _ => return Err("Could not get source IP address".into()),
            }
        },
        Err(_) => return Err("Could not get source IP address".into()),
    };
    let src_port = rand::random_range(49152..65534); // ephemeral ports

    packet.set_destination(port);
    packet.set_source(src_port);
    packet.set_sequence(rand::random::<u32>());
    packet.set_acknowledgement(0);
    packet.set_reserved(0);
    let tcp_options = [
        TcpOption::mss(65495),
        TcpOption::sack_perm(),
        TcpOption::timestamp(rand::random::<u32>(), 0),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(7),
    ];
    packet.set_data_offset(12); // at least 5
    packet.set_options(&tcp_options);
    packet.set_window(65495);

    if scan_type == ScanType::Fin {
        packet.set_flags(tcp::TcpFlags::FIN);
    } else if scan_type == ScanType::Syn {
        packet.set_flags(tcp::TcpFlags::SYN);
    } else {
        return Err("Connect scan not supported for raw packets".into());
    }
    
    let checksum = tcp::ipv4_checksum(&packet.to_immutable(), &src_ip, &ip);
    packet.set_checksum(checksum);

    tx.send_to(packet.to_immutable(), ip.into())
        .expect("Could not send packet");

    loop {
        let mut res = tcp_packet_iter(&mut rx);
        let result = res
            .next_with_timeout(std::time::Duration::from_secs(timeout.into()))
            .expect("Failed to receive packet");
        match result {
            Some(p) => {
                let packet = p.0;
                if packet.get_destination() == src_port && packet.get_source() == port {
                    if scan_type == ScanType::Syn {
                        if packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK {
                            println!("Port {} is open", port);
                            return Ok(true);
                        } else {
                            println!("Port {} is closed", port);
                            return Ok(false);
                        }
                    } else {
                        if packet.get_flags() == tcp::TcpFlags::RST | tcp::TcpFlags::ACK {
                            println!("Port {} is closed", port);
                            return Ok(false);
                        } else {
                            println!("Port {} is unknown. Received unexpected packet", port);
                            return Ok(false);
                        }
                    }
                }
            }
            None => {
                if scan_type == ScanType::Syn {
                    println!("Port {} is filtered", port);
                    return Ok(false);
                } 
                println!("Port {} is open", port); // No response to FIN packet means port is open
                return Ok(true);
            }
        }
    }
}

fn get_source_ip_for_target(target: &IpAddr) -> Result<IpAddr, Box<dyn std::error::Error>> {
    if target.is_loopback() {
        if target.is_ipv6() {
            return Ok(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        }
        return Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }
    let bind = match target.is_ipv4() {
        true => "0.0.0.0:0",
        false => "[::]:0",
    };
    match std::net::UdpSocket::bind(bind) {
        Ok(socket) => {
            match socket.connect(SocketAddr::new(target.clone().into(), 53)) {
                Ok(_) => {
                    return Ok(socket.local_addr()?.ip());
                }
                Err(_) => {
                    return Err("Could not connect to target".into());
                }
            }
        }
        Err(_) => {
            return Err("Could not bind to local address".into());
        }
    }
}


fn scan_raw_ipv6(
    ip: Ipv6Addr,
    port: u16,
    timeout: u8,
    scan_type: ScanType,
) -> Result<bool, Box<dyn std::error::Error>> {
    let protocol =
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = pnet::transport::transport_channel(1024, protocol)?;

    let mut buf = [0u8; 60];
    let mut packet = tcp::MutableTcpPacket::new(&mut buf).unwrap();

    let src_ip = match get_source_ip_for_target(&ip.into()) {
        Ok(src) => {
            match src {
                IpAddr::V6(ip) => ip,
                _ => return Err("Could not get source IP address".into()),
            }
        },
        Err(_) => return Err("Could not get source IP address".into()),
    };
    let src_port = rand::random_range(49152..65534); // ephemeral ports

    packet.set_destination(port);
    packet.set_source(src_port);
    packet.set_sequence(rand::random::<u32>());
    packet.set_acknowledgement(0);
    packet.set_reserved(0);
    let tcp_options = [
        TcpOption::mss(65495),
        TcpOption::sack_perm(),
        TcpOption::timestamp(rand::random::<u32>(), 0),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(7),
    ];
    packet.set_data_offset(12); // at least 5
    packet.set_options(&tcp_options);
    packet.set_window(65495);
    if scan_type == ScanType::Fin {
        packet.set_flags(tcp::TcpFlags::FIN);
    } else if scan_type == ScanType::Syn {
        packet.set_flags(tcp::TcpFlags::SYN);
    } else {
        return Err("Connect scan not supported for raw packets".into());
    }

    let checksum = tcp::ipv6_checksum(&packet.to_immutable(), &src_ip, &ip);
    packet.set_checksum(checksum);

    tx.send_to(packet.to_immutable(), ip.into())
        .expect("Could not send packet");

    loop {
        let mut res = tcp_packet_iter(&mut rx);
        let result = res
            .next_with_timeout(std::time::Duration::from_secs(timeout.into()))
            .expect("Failed to receive packet");
        match result {
            Some(p) => {
                let packet = p.0;
                if packet.get_destination() == src_port && packet.get_source() == port {
                    if scan_type == ScanType::Syn {
                        if packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK {
                            println!("Port {} is open", port);
                            return Ok(true);
                        } else {
                            println!("Port {} is closed", port);
                            return Ok(false);
                        }
                    } else {
                        if packet.get_flags() == tcp::TcpFlags::RST | tcp::TcpFlags::ACK {
                            println!("Port {} is closed", port);
                            return Ok(false);
                        } else {
                            println!("Port {} is unknown. Received unexpected packet", port);
                            return Ok(false);
                        }
                    }
                }
            }
            None => {
                if scan_type == ScanType::Syn {
                    println!("Port {} is filtered", port);
                    return Ok(false);
                } 
                println!("Port {} is open", port); // No response to FIN packet means port is open
                return Ok(true);
            }
        }
    }
}

fn scan_connect(ip: IpAddr, port: u16, timeout: u8) -> bool {
    let socket_addr = std::net::SocketAddr::new(ip, port);
    let socket = std::net::TcpStream::connect_timeout(
        &socket_addr,
        std::time::Duration::from_secs(timeout.into()),
    );
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

fn scan(ip: IpAddr, port: u16, scan_type: ScanType, timeout: u8) -> Result<bool, Box<dyn Error>> {
    match scan_type {
        ScanType::Syn => scan_raw(ip, port, timeout, scan_type),
        ScanType::Connect => Ok(scan_connect(ip, port, timeout)),
        ScanType::Fin => scan_raw(ip, port, timeout, scan_type),
    }
}

/// Expands a CIDR range into individual IP addresses
fn expand_cidr(cidr_str: &str) -> Result<Vec<IpAddr>, Box<dyn Error>> {
    // Try parsing as IPv4 CIDR first
    if let Ok(ipv4_cidr) = cidr_str.parse::<Ipv4Cidr>() {
        let hosts: Vec<IpAddr> = ipv4_cidr
            .iter()
            .map(|ip| ip.address().into())
            .collect();
        return Ok(hosts);
    }

    // If not IPv4, try parsing as IPv6 CIDR
    if let Ok(ipv6_cidr) = cidr_str.parse::<Ipv6Cidr>() {
        // Limit the number of IPv6 addresses to avoid too many scans
        let prefix_len = ipv6_cidr.network_length();
        if prefix_len < 120 {
            return Err(format!("IPv6 CIDR with prefix length < 120 not supported to avoid too many scans (got /{})", prefix_len).into());
        }

        let hosts: Vec<IpAddr> = ipv6_cidr
            .iter()
            .map(|ip| ip.address().into())
            .collect();
        return Ok(hosts);
    }

    Err(format!("Invalid CIDR notation: {}", cidr_str).into())
}

/// Checks if the input is a CIDR notation
fn is_cidr(input: &str) -> bool {
    input.contains("/")
}

/// Parses a hostname, IP address, or CIDR range into a list of IP addresses
fn parse_target(target: &str) -> Result<Vec<IpAddr>, Box<dyn Error>> {
    if is_cidr(target) {
        expand_cidr(target)
    } else {
        // Try to parse as a single IP address or hostname
        match hostname_to_ip(&target.to_string()) {
            Ok(ip) => Ok(vec![ip]),
            Err(e) => Err(e),
        }
    }
}

fn hostname_to_ip(hostname: &String) -> Result<IpAddr, Box<dyn Error>> {
    // Try to parse as IP address first
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Otherwise resolve hostname
    let mut ip_iter: IntoIter<std::net::SocketAddr>;
    if !hostname.contains(":") {
        ip_iter = format!("{}:0", hostname).to_socket_addrs()?;
    } else {
        ip_iter = hostname.to_socket_addrs()?;
    }

    if let Some(addr) = ip_iter.next() {
        return Ok(addr.ip());
    }

    Err("Could not resolve hostname to IP address".into())
}

fn main() {
    let args = Cli::parse();
    
    let target_ips = match parse_target(&args.host) {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("Error parsing target: {}", e);
            return;
        }
    };
    
    let total_ips = target_ips.len();
    if total_ips > 1 {
        println!("Scanning {} IP addresses in range {}", total_ips, args.host);
    }
    
    for (idx, ip) in target_ips.iter().enumerate() {
        if total_ips > 1 {
            println!("[{}/{}] Scanning {} on port {} using method {} with timeout {} seconds",
                idx + 1, total_ips, ip, args.port, args.scan_type, args.timeout);
        } else {
            println!("Scanning {} on port {} using method {} with timeout {} seconds",
                ip, args.port, args.scan_type, args.timeout);
        }
        
        match scan(*ip, args.port, args.scan_type, args.timeout) {
            Ok(_) => {},
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}
