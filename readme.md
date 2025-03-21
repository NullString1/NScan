<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]

<!-- PROJECT LOGO -->
<div align="center">

<h3 align="center">NScan</h3>

  <p align="center">
    Simple & fast rust port scanner
    <br />
    <br />
    <a href="https://github.com/NullString1/VWCDC/issues">Report Bug</a>
    ·
    <a href="https://github.com/NullString1/VWCDC/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
### Table of Contents
<ol>
  <li>
    <a href="#about-the-project">About The Project</a>
  </li>
  <li><a href="#usage">Usage</a></li>
  <li><a href="#contributing">Contributing</a></li>
  <li><a href="#contact">Contact</a></li>
</ol>



<!-- ABOUT THE PROJECT -->
## About The Project
NScan is a simple cross-platform IPv4 and IPv6 port scanner written in Rust, supporting SYN, FIN and Connect scans.

You can scan one address such as `example.com` or `1.1.1.1`, or a CIDR range such as `127.0.0.0/8`. 

You can select just one port to scan `-p 20`, a selection of ports `-p 20,80`, a range of ports `-p 20-25` or any mix of the three `-p 20,80-90,25`.

<!-- USAGE -->
## Usage
Download the lastest release or compile yourself with `cargo build --release`.

Run `NScan -h` to view the help message
```
Simple port scanner written in rust. Supports SYN, Connect, and FIN scans

Usage: NScan [OPTIONS] --host <HOST>

Options:
  -H, --host <HOST>              IP address, hostname, or CIDR range to scan
  -p, --port-range <PORT_RANGE>  Port to scan [default: 80]
  -s, --scan-type <SCAN_TYPE>    Scan type [default: syn] [possible values: syn, connect, fin]
  -t, --timeout <TIMEOUT>        Timeout in seconds (max 255) [default: 1]
  -T, --threads <THREADS>        Number of threads to use (4) [default: 4]
  -h, --help                     Print help
```

Run `sudo NScan -H 127.0.0.1` to run a `SYN` scan on `127.0.0.1:80` (Ensure you use sudo or run as root on linux due to use of raw sockets)
```
NScan v1.0 - Network scanner
------------------------------
Scan configuration:
  Target(s): 127.0.0.1 (1 addresses)
  Port(s): 80 (1 ports)
  Method: SYN
  Timeout: 1 seconds
  Threads: 4
  Total scans: 1
------------------------------
Scan started at 12:21:03
Running...
Port 80 is closed (Received RST/ACK)

------------------------------
Scan completed in 0.00 seconds
Found 0 open ports
```

Run `sudo NScan -H ::1 -p 443` to run a `SYN` scan on `::1` (IPv6 loopback) port `443` (Ensure you use sudo or run as root on linux due to use of raw sockets)
```
NScan v1.0 - Network scanner
------------------------------
Scan configuration:
  Target(s): ::1 (1 addresses)
  Port(s): 443 (1 ports)
  Method: SYN
  Timeout: 1 seconds
  Threads: 4
  Total scans: 1
------------------------------
Scan started at 12:23:38
Running...
Port 443 is closed (Received RST/ACK)

------------------------------
Scan completed in 0.00 seconds
Found 0 open ports
```

Run `NScan -H 1.1.1.1 -p 80 -s connect` to run a `Connect` scan on `1.1.1.1` port 80. (No root required due to use of unpriviledged socket)
```
NScan v1.0 - Network scanner
------------------------------
Scan configuration:
  Target(s): 1.1.1.1 (1 addresses)
  Port(s): 80 (1 ports)
  Method: Connect
  Timeout: 1 seconds
  Threads: 4
  Total scans: 1
------------------------------
Scan started at 12:24:38
Running...
Port 80 is open

------------------------------
Scan completed in 0.02 seconds
Found 1 open ports

Open ports:
  1.1.1.1:80 - OPEN
```

Run `sudo NScan -H ::1 -t 10` to run a `SYN` scan on `::1` port 80 with timeout set at `10 seconds` (Ensure you use sudo or run as root on linux due to use of raw sockets)
```
NScan v1.0 - Network scanner
------------------------------
Scan configuration:
  Target(s): ::1 (1 addresses)
  Port(s): 80 (1 ports)
  Method: SYN
  Timeout: 10 seconds
  Threads: 4
  Total scans: 1
------------------------------
Scan started at 12:28:56
Running...
Port 80 is closed (Received RST/ACK)

------------------------------
Scan completed in 0.00 seconds
Found 0 open ports
```

Run `sudo NScan -H 127.0.0.0/24 -p 22 -t 1 -s syn -T 8` to run a `SYN` scan on `127.0.0.0/24` port 22 with timeout `1 second` on `8 threads` (Ensure you use sudo or run as root on linux due to use of raw sockets)
```
NScan v1.0 - Network scanner
------------------------------
Scan configuration:
  Target(s): 127.0.0.0/24 (256 addresses)
  Port(s): 22 (1 ports)
  Method: SYN
  Timeout: 1 seconds
  Threads: 2
  Total scans: 256
------------------------------
Scan started at 12:32:21
Running...
Port 22 is closed (Received RST/ACK)
Port 22 is closed (Received RST/ACK)
Port 22 is closed (Received RST/ACK)
Port 22 is closed (Received RST/ACK)
Port 22 is closed (Received RST/ACK)
Port 22 is closed (Received RST/ACK)
Port 22 is closed (Received RST/ACK)
Port 22 is closed (Received RST/ACK)
...... (output trimmed)
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

Daniel Kern (NullString1) - [@nullstring1_](https://twitter.com/nullstring1_) - daniel@nullstring.one

Website: [https://nullstring.one](https://nullstring.one)
Project Link: [https://github.com/NullString1/NScan](https://github.com/NullString1/NScan)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/NullString1/NScan.svg?style=for-the-badge
[contributors-url]: https://github.com/NullString1/NScan/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/NullString1/NScan.svg?style=for-the-badge
[forks-url]: https://github.com/NullString1/NScan/network/members
[stars-shield]: https://img.shields.io/github/stars/NullString1/NScan.svg?style=for-the-badge
[stars-url]: https://github.com/NullString1/NScan/stargazers
[issues-shield]: https://img.shields.io/github/issues/NullString1/NScan.svg?style=for-the-badge
[issues-url]: https://github.com/NullString1/NScan/issues
[license-shield]: https://img.shields.io/github/license/NullString1/NScan.svg?style=for-the-badge
[license-url]: https://github.com/NullString1/NScan/blob/master/LICENSE
