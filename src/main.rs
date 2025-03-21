use cidr::{Ipv4Cidr, Ipv6Cidr};
use clap::{Parser, ValueEnum};
use colored::Colorize;
use pnet::{
    packet::{
        ip::IpNextHeaderProtocols,
        tcp::{self, TcpOption},
    },
    transport::{tcp_packet_iter, TransportChannelType, TransportProtocol},
};
use std::{
    error::Error,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    vec::IntoIter,
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

/// Simple port scanner written in rust. Supports SYN, Connect, and FIN scans.
#[derive(Parser)]
struct Cli {
    #[clap(short = 'H', long)]
    /// IP address, hostname, or CIDR range to scan
    host: String,

    /// Port to scan
    #[clap(short, long, default_value = "80")]
    port_range: Option<String>,

    /// Scan type
    #[clap(short, long, default_value = "syn")]
    scan_type: ScanType,

    /// Timeout in seconds (max 255)
    #[clap(short, long, default_value = "1")]
    timeout: u8,

    /// Number of threads to use (4)
    #[clap(short, long, default_value = "4")]
    threads: u8,
}

fn scan_raw(
    ip: IpAddr,
    port: u16,
    timeout: u8,
    st: ScanType,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
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
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let protocol =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = pnet::transport::transport_channel(1024, protocol)?;

    let mut buf = [0u8; 60];
    let mut packet = tcp::MutableTcpPacket::new(&mut buf).unwrap();

    let src_ip = match get_source_ip_for_target(&ip.into()) {
        Ok(src) => match src {
            IpAddr::V4(ip) => ip,
            _ => return Err("Could not get source IP address".into()),
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
                    let flags = packet.get_flags();
                    if flags == (tcp::TcpFlags::SYN | tcp::TcpFlags::ACK) {
                        println!("Port {} is {} (Received SYN/ACK)", port, "open".green());
                        return Ok(true);
                    } else if flags == (tcp::TcpFlags::RST | tcp::TcpFlags::ACK) {
                        println!("Port {} is {} (Received RST/ACK)", port, "closed".red());
                        return Ok(false);
                    } else {
                        println!(
                            "Port {} is unknown. Received unexpected packet with flags {}",
                            port,
                            packet.get_flags()
                        );
                        return Ok(false);
                    }
                }
            }
            None => {
                if scan_type == ScanType::Syn {
                    println!("Port {} is filtered (Received no response)", port);
                    return Ok(false);
                }
                println!(
                    "Port {} is {} (Received nothing after FIN)",
                    port,
                    "open".green()
                ); // No response to FIN packet means port is open
                return Ok(true);
            }
        }
    }
}

fn parse_port_range(range_str: &str) -> Result<Vec<u16>, Box<dyn Error + Send + Sync>> {
    let mut ports = Vec::new();

    for part in range_str.split(',') {
        if part.contains('-') {
            // Handle range like "1000-2000"
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(format!("Invalid port range: {}", part).into());
            }

            let start: u16 = range_parts[0].parse()?;
            let end: u16 = range_parts[1].parse()?;

            if start > end {
                return Err(format!("Invalid port range (start > end): {}", part).into());
            }

            if end - start > 1000 {
                return Err(
                    format!("Port range too large (max 1000 ports per range): {}", part).into(),
                );
            }

            for port in start..=end {
                ports.push(port);
            }
        } else {
            // Handle single port like "80"
            let port: u16 = part.parse()?;
            ports.push(port);
        }
    }

    if ports.is_empty() {
        return Err("No valid ports specified".into());
    }

    Ok(ports)
}

fn get_source_ip_for_target(
    target: &IpAddr,
) -> Result<IpAddr, Box<dyn std::error::Error + Send + Sync>> {
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
        Ok(socket) => match socket.connect(SocketAddr::new(target.clone().into(), 53)) {
            Ok(_) => {
                return Ok(socket.local_addr()?.ip());
            }
            Err(_) => {
                return Err("Could not connect to target".into());
            }
        },
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
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let protocol =
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = pnet::transport::transport_channel(1024, protocol)?;

    let mut buf = [0u8; 60];
    let mut packet = tcp::MutableTcpPacket::new(&mut buf).unwrap();

    let src_ip = match get_source_ip_for_target(&ip.into()) {
        Ok(src) => match src {
            IpAddr::V6(ip) => ip,
            _ => return Err("Could not get source IP address".into()),
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
                    let flags = packet.get_flags();
                    if flags == (tcp::TcpFlags::SYN | tcp::TcpFlags::ACK) {
                        println!("Port {} is {} (Received SYN/ACK)", port, "open".green());
                        return Ok(true);
                    } else if flags == (tcp::TcpFlags::RST | tcp::TcpFlags::ACK) {
                        println!("Port {} is {} (Received RST/ACK)", port, "closed".red());
                        return Ok(false);
                    } else {
                        println!(
                            "Port {} is unknown. Received unexpected packet with flags {}",
                            port,
                            packet.get_flags()
                        );
                        return Ok(false);
                    }
                }
            }
            None => {
                if scan_type == ScanType::Syn {
                    println!("Port {} is filtered (Received no response)", port);
                    return Ok(false);
                }
                println!(
                    "Port {} is {} (Received nothing after FIN)",
                    port,
                    "open".green()
                ); // No response to FIN packet means port is open
                return Ok(true);
            }
        }
    }
}

fn scan_connect(
    ip: IpAddr,
    port: u16,
    timeout: u8,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let socket_addr = std::net::SocketAddr::new(ip, port);
    let socket = std::net::TcpStream::connect_timeout(
        &socket_addr,
        std::time::Duration::from_secs(timeout.into()),
    );
    match socket {
        Ok(_) => {
            println!("Port {} is open", port);
            Ok(true)
        }
        Err(e) => {
            println!("Port {} is closed", port);
            Err(Box::new(e))
        }
    }
}

fn scan(
    ip: IpAddr,
    port: u16,
    scan_type: ScanType,
    timeout: u8,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    match scan_type {
        ScanType::Syn => scan_raw(ip, port, timeout, scan_type),
        ScanType::Connect => scan_connect(ip, port, timeout),
        ScanType::Fin => scan_raw(ip, port, timeout, scan_type),
    }
}

/// Expands a CIDR range into individual IP addresses
fn expand_cidr(cidr_str: &str) -> Result<Vec<IpAddr>, Box<dyn Error + Send + Sync>> {
    // Try parsing as IPv4 CIDR first
    if let Ok(ipv4_cidr) = cidr_str.parse::<Ipv4Cidr>() {
        let hosts: Vec<IpAddr> = ipv4_cidr.iter().map(|ip| ip.address().into()).collect();
        return Ok(hosts);
    }

    // If not IPv4, try parsing as IPv6 CIDR
    if let Ok(ipv6_cidr) = cidr_str.parse::<Ipv6Cidr>() {
        // Limit the number of IPv6 addresses to avoid too many scans
        let prefix_len = ipv6_cidr.network_length();
        if prefix_len < 120 {
            return Err(format!("IPv6 CIDR with prefix length < 120 not supported to avoid too many scans (got /{})", prefix_len).into());
        }

        let hosts: Vec<IpAddr> = ipv6_cidr.iter().map(|ip| ip.address().into()).collect();
        return Ok(hosts);
    }

    Err(format!("Invalid CIDR notation: {}", cidr_str).into())
}

/// Checks if the input is a CIDR notation
fn is_cidr(input: &str) -> bool {
    input.contains("/")
}

/// Parses a hostname, IP address, or CIDR range into a list of IP addresses
fn parse_target(target: &str) -> Result<Vec<IpAddr>, Box<dyn Error + Send + Sync>> {
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

fn hostname_to_ip(hostname: &String) -> Result<IpAddr, Box<dyn Error + Send + Sync>> {
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

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let target_ips = match parse_target(&args.host) {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("Error parsing target: {}", e);
            return;
        }
    };
    let port_range = args.port_range.unwrap();
    let ports = match parse_port_range(&port_range) {
        Ok(ports) => ports,
        Err(e) => {
            eprintln!("Error parsing port range: {}", e);
            return;
        }
    };

    let total_ips = target_ips.len();
    let total_ports = ports.len();
    let total_scans = total_ips * total_ports;

    println!("{}", "NScan v1.0 - Network scanner".blue().bold());
    println!("------------------------------");
    println!("Scan configuration:");
    println!("  Target(s): {} ({} addresses)", args.host, total_ips);
    println!("  Port(s): {} ({} ports)", port_range, total_ports);
    println!("  Method: {}", args.scan_type);
    println!("  Timeout: {} seconds", args.timeout);
    println!("  Threads: {}", args.threads);
    println!("  Total scans: {}", total_scans);
    println!("------------------------------");

    let semaphore = Arc::new(tokio::sync::Semaphore::new(args.threads as usize));
    let mut tasks = Vec::new();
    let mut open_ports = 0;
    let start_time = std::time::Instant::now();

    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for ip in target_ips {
        for port in &ports {
            let sem_clone = semaphore.clone();
            let completed_clone = completed.clone();
            let scan_type = args.scan_type;
            let timeout = args.timeout;
            let port_val = *port;

            let task = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();

                // Run the scan
                let result = scan(ip, port_val, scan_type, timeout);

                // Update progress counter
                let current = completed_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if total_scans > 100 && current % (total_scans / 100) == 0 {
                    eprint!(
                        "\rProgress: {:.1}% ({}/{})",
                        (current as f64 / total_scans as f64) * 100.0,
                        current,
                        total_scans
                    );
                }

                // Return the result
                (ip, port_val, result)
            });

            tasks.push(task);
        }
    }

    println!(
        "Scan started at {}",
        chrono::Local::now().format("%H:%M:%S")
    );
    println!("Running...");

    // Collect results
    let mut open_ports_list = Vec::new();

    for task in tasks {
        let (ip, port, result) = task.await.unwrap();
        match result {
            Ok(true) => {
                open_ports += 1;
                open_ports_list.push((ip, port));
            }
            Ok(false) => {}
            Err(e) => {
                eprintln!("Error scanning {}: {}", ip, e);
            }
        }
    }
    let elapsed = start_time.elapsed();
    println!("\r                                                     ");
    println!("------------------------------");
    println!("Scan completed in {:.2} seconds", elapsed.as_secs_f64());
    println!("Found {} open ports", open_ports);

    if !open_ports_list.is_empty() {
        println!("\nOpen ports:");
        // Sort results by IP then port
        open_ports_list.sort_by(|a, b| {
            if a.0 == b.0 {
                a.1.cmp(&b.1)
            } else {
                a.0.to_string().cmp(&b.0.to_string())
            }
        });

        for (ip, port) in open_ports_list {
            println!("  {}:{} - {}", ip, port, "OPEN".green());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};
    use tokio::task;

    use super::*;

    #[test]
    fn test_expand_cidr_ipv4() {
        let cidr = "1.1.1.0/30";
        let result = expand_cidr(cidr).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 0)));
        assert_eq!(result[1], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(result[2], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)));
        assert_eq!(result[3], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3)));
    }

    #[test]
    fn test_expand_cidr_ipv6() {
        let cidr = "2001:db8::0/126";
        let result = expand_cidr(cidr).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(
            result[0],
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0))
        );
        assert_eq!(
            result[1],
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(
            result[2],
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2))
        );
        assert_eq!(
            result[3],
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 3))
        );
    }

    #[test]
    fn test_parse_target_ip_1() {
        let target = "1.1.1.1";
        let result = parse_target(target).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_parse_target_ip_2() {
        let target = "1.1.1.1:80";
        let result = parse_target(target).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_parse_target_hostname() {
        let target = "one.one.one.one";
        let result = parse_target(target).unwrap();
        let expected = [
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::from_str("2606:4700:4700::1111").unwrap()),
            IpAddr::V6(Ipv6Addr::from_str("2606:4700:4700::1001").unwrap()),
        ];
        assert_eq!(result.len(), 1);
        if !expected.contains(&result[0]) {
            panic!(
                "Expected 1.1.1.1/1.0.0.1/2606:4700:4700::1111/2606:4700:4700::1001, got {:?}",
                result[0]
            );
        }
        assert!(true);
    }

    #[test]
    fn test_parse_target_localhost_ip() {
        let target = "127.0.0.1";
        let result = parse_target(target).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    }

    async fn bind(addr: SocketAddr, notify: Arc<tokio::sync::Notify>) {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        notify.notify_one();
        let (_socket, _) = listener.accept().await.unwrap();
        drop(listener);
    }

    #[tokio::test]
    async fn test_localhost_syn() {
        let port = rand::random_range(49152..65534);
        let started = Arc::new(tokio::sync::Notify::new());
        let started2 = started.clone();
        let task = task::spawn(async move {
            let addr = SocketAddr::new(parse_target("localhost").unwrap()[0], port);
            bind(addr, started2).await;
        });
        started.notified().await;
        let target = parse_target("localhost").expect("Couldn't parse target localhost")[0];
        let res = scan(target, port, ScanType::Syn, 1);
        task.abort();
        if res.is_err() && res
            .as_ref()
            .unwrap_err()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind()
            == std::io::ErrorKind::PermissionDenied
        {
            eprintln!("Permission denied, skipping test");
            return;
        }
        assert_eq!(res.unwrap(), true);
    }

    #[tokio::test]
    async fn test_localhost_fin() {
        let port = rand::random_range(49152..65534);
        let started = Arc::new(tokio::sync::Notify::new());
        let started2 = started.clone();
        let task = task::spawn(async move {
            let addr = SocketAddr::new(parse_target("localhost").unwrap()[0], port);
            bind(addr, started2).await;
        });
        started.notified().await;
        let target = parse_target("localhost").expect("Couldn't parse target localhost")[0];
        let res = scan(target, port, ScanType::Fin, 1);
        task.abort();
        if res.is_err() && res
            .as_ref()
            .unwrap_err()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind()
            == std::io::ErrorKind::PermissionDenied
        {
            eprintln!("Permission denied, skipping test");
            return;
        }
        assert_eq!(res.unwrap(), true);
    }

    #[tokio::test]
    async fn test_localhost_connect() {
        let port = rand::random_range(49152..65534);
        let started = Arc::new(tokio::sync::Notify::new());
        let started2 = started.clone();
        let task = task::spawn(async move {
            let addr = SocketAddr::new(parse_target("localhost").unwrap()[0], port);
            bind(addr, started2).await;
        });
        started.notified().await;
        let target = parse_target("localhost").expect("Couldn't parse target localhost")[0];
        let res = scan(target, port, ScanType::Connect, 1);
        task.abort();
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_ipv4_syn() {
        let target = parse_target("1.1.1.1").unwrap();
        let res = scan(target[0], 80, ScanType::Syn, 1);
        if res.is_err() && res
            .as_ref()
            .unwrap_err()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind()
            == std::io::ErrorKind::PermissionDenied
        {
            eprintln!("Permission denied, skipping test");
            return;
        }
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_ipv4_fin() {
        let target = parse_target("1.1.1.1").unwrap();
        let res = scan(target[0], 80, ScanType::Fin, 1);
        if res.is_err() && res
            .as_ref()
            .unwrap_err()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind()
            == std::io::ErrorKind::PermissionDenied
        {
            eprintln!("Permission denied, skipping test");
            return;
        }
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_ipv4_connect() {
        let target = parse_target("1.1.1.1").unwrap();
        let res = scan(target[0], 80, ScanType::Connect, 1);
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_ipv6_syn() {
        let target = parse_target("2600::").unwrap();
        let res = scan(target[0], 80, ScanType::Syn, 1);
        if res.is_err()
            && res.as_ref().unwrap_err().to_string() == "Could not get source IP address"
        {
            eprintln!("Couldn't source address for IPv6. Do you support it? Ignoring test..");
            return;
        }
        if res
            .as_ref()
            .unwrap_err()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind()
            == std::io::ErrorKind::PermissionDenied
        {
            eprintln!("Permission denied, skipping test");
            return;
        }
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_ipv6_fin() {
        let target = parse_target("2600::").unwrap();
        let res = scan(target[0], 80, ScanType::Fin, 1);
        if res.is_err()
            && res.as_ref().unwrap_err().to_string() == "Could not get source IP address"
        {
            eprintln!("Couldn't source address for IPv6. Do you support it? Ignoring test..");
            return;
        }
        if res
            .as_ref()
            .unwrap_err()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind()
            == std::io::ErrorKind::PermissionDenied
        {
            eprintln!("Permission denied, skipping test");
            return;
        }
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_ipv6_connect() {
        let target = parse_target("2600::").unwrap();
        let res = scan(target[0], 80, ScanType::Connect, 1);
        if res.is_err() {
            let err_kind = res
                .as_ref()
                .unwrap_err()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind();
            if err_kind == std::io::ErrorKind::NetworkUnreachable {
                eprintln!("IPv6 appears to be unreachable, ignoring test");
            }
            return;
        }
        assert_eq!(res.unwrap(), true);
    }

    #[test]
    fn test_parse_port_range_single() {
        let range = "80";
        let result = parse_port_range(range).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 80);
    }

    #[test]
    fn test_parse_port_range_multiple() {
        let range = "22,80,443";
        let result = parse_port_range(range).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_port_range_range() {
        let range = "1000-1005";
        let result = parse_port_range(range).unwrap();
        assert_eq!(result.len(), 6);
        assert_eq!(result, vec![1000, 1001, 1002, 1003, 1004, 1005]);
    }

    #[test]
    fn test_parse_port_range_mixed() {
        let range = "22,80-82,443";
        let result = parse_port_range(range).unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_parse_port_range_invalid_format() {
        let range = "80-";
        let result = parse_port_range(range);
        assert!(result.is_err());

        let range = "-80";
        let result = parse_port_range(range);
        assert!(result.is_err());

        let range = "a-b";
        let result = parse_port_range(range);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_range_invalid_range() {
        let range = "100-50"; // start > end
        let result = parse_port_range(range);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_range_too_large() {
        let range = "1-3000"; // more than 1000 ports
        let result = parse_port_range(range);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_scan_multiple_ports_localhost() {
        // Create listeners on multiple random ports
        let port1 = rand::random_range(49152..60000);
        let port2 = rand::random_range(60001..65000);

        let started1 = Arc::new(tokio::sync::Notify::new());
        let started2 = Arc::new(tokio::sync::Notify::new());

        let s1 = started1.clone();
        let s2 = started2.clone();

        // Spawn two listeners on different ports
        let task1 = task::spawn(async move {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port1);
            bind(addr, s1).await;
        });

        let task2 = task::spawn(async move {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port2);
            bind(addr, s2).await;
        });

        // Wait for both listeners to be ready
        started1.notified().await;
        started2.notified().await;

        // Test with SYN scan on both ports
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let port_range = format!("{},{}", port1, port2);

        // Parse port range
        let ports = parse_port_range(&port_range).unwrap();
        assert_eq!(ports.len(), 2);

        // Scan each port individually and collect results
        let mut open_ports = Vec::new();
        for port in ports {
            match scan(target, port, ScanType::Syn, 1) {
                Ok(is_open) => {
                    if is_open {
                        open_ports.push(port);
                    }
                }
                Err(e) => {
                    if e.downcast_ref::<std::io::Error>().unwrap().kind()
                        == std::io::ErrorKind::PermissionDenied
                    {
                        eprintln!("Permission denied, skipping test");
                        task1.abort();
                        task2.abort();
                        return;
                    }
                }
            }
        }

        // Both ports should be open
        assert_eq!(open_ports.len(), 2, "Expected both ports to be open");
        assert!(open_ports.contains(&port1), "Port {} should be open", port1);
        assert!(open_ports.contains(&port2), "Port {} should be open", port2);

        // Clean up
        task1.abort();
        task2.abort();
    }

    #[tokio::test]
    async fn test_scan_port_range_localhost() {
        // Test with a range of ports - create listeners on 3 consecutive ports
        let base_port = rand::random_range(50000..60000);
        let port_range = format!("{}-{}", base_port, base_port + 2); // 3 ports

        // Create notifiers for each listener
        let started = vec![
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        ];

        // Spawn three listeners
        let mut tasks = Vec::new();
        for i in 0..3 {
            let port = base_port + i as u16;
            let s = started[i].clone();

            let task = task::spawn(async move {
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
                bind(addr, s).await;
            });

            tasks.push(task);
        }

        // Wait for all listeners to be ready
        for s in &started {
            s.notified().await;
        }

        // Parse the port range
        let ports = parse_port_range(&port_range).unwrap();
        assert_eq!(ports.len(), 3);

        // Test with Connect scan (works without root)
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Scan each port
        let mut open_ports = Vec::new();
        for port in ports {
            if let Ok(is_open) = scan(target, port, ScanType::Connect, 1) {
                if is_open {
                    open_ports.push(port);
                }
            }
        }

        // All ports should be open
        assert_eq!(open_ports.len(), 3, "Expected all 3 ports to be open");
        for i in 0..3 {
            assert!(
                open_ports.contains(&(base_port + i as u16)),
                "Port {} should be open",
                base_port + i as u16
            );
        }

        // Clean up
        for task in tasks {
            task.abort();
        }
    }

    #[test]
    fn test_mixed_open_closed_ports() {
        let target = parse_target("one.one.one.one").unwrap();

        // First verify port 80 is open
        match scan(target[0], 80, ScanType::Connect, 2) {
            Ok(is_open) => {
                if !is_open {
                    println!("Port 80 on one.one.one.one appears to be closed, skipping test");
                    return;
                }
            }
            Err(_) => {
                println!("Could not connect to one.one.one.one, skipping test");
                return;
            }
        }
        let res = scan(target[0], 81, ScanType::Connect, 2);
        assert!(res.is_err() || res.unwrap() == false);
    }

    #[test]
    fn test_scan_invalid_ip() {
        let target = parse_target("999.999.999.999");
        assert!(target.is_err(), "Expected error for invalid IP address");
    }

    #[test]
    fn test_scan_invalid_hostname() {
        let target = parse_target("invalid.hostname");
        assert!(target.is_err(), "Expected error for invalid hostname");
    }

    #[test]
    fn test_scan_empty_port_range() {
        let range = "";
        let result = parse_port_range(range);
        assert!(result.is_err(), "Expected error for empty port range");
    }

    #[test]
    fn test_scan_large_port_range() {
        let range = "1-10000";
        let result = parse_port_range(range);
        assert!(result.is_err(), "Expected error for too large port range");
    }

    #[test]
    fn test_scan_ipv6_invalid_range() {
        let cidr = "2001:db8::0/64";
        let result = expand_cidr(cidr);
        assert!(
            result.is_err(),
            "Expected error for unsupported IPv6 CIDR range"
        );
    }

    #[test]
    fn test_scan_ipv4_invalid_range() {
        let cidr = "1.1.1.0/33";
        let result = expand_cidr(cidr);
        assert!(
            result.is_err(),
            "Expected error for invalid IPv4 CIDR range"
        );
    }

    #[test]
    fn test_can_open_raw_socket() {
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
        let res = pnet::transport::transport_channel(1024, protocol);
        assert!(res.is_ok(), "Couldn't open raw socket. Are you root?");
        assert!(res.is_ok(), "Couldn't open raw socket. Are you root?");
    }
}
