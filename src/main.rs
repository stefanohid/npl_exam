use clap::Parser;
use std::time::{Duration, Instant};
use pcap::Capture;
use std::net::{UdpSocket, SocketAddr};
use etherparse;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Msg {
    udp_sent: i32,
    icmp_received: i32,
    map: HashMap<u16, Vec<Duration>>
}

#[derive(Parser, Debug)]
struct Cli {
    /// Target host to probe
    #[arg(long)]
    host: String,

    /// Number of probes to send
    #[arg(short = 'n', long, default_value_t = 5)]
    numprobes: u16,
    
    /// Network interface to read from
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() {
    let cli = Cli::parse();
    let iname = cli.interface.unwrap_or_else(|| {"eth0".to_string()});
    let srv_addr = format!("0.0.0.0:10000");
    let srv_sock: SocketAddr = srv_addr.parse().unwrap();
    let sock = UdpSocket::bind(srv_sock).expect("Could not bind!");

    let capture = Capture::from_device(iname.as_str())
                .expect("Cannot create capture from device")
                .promisc(true)
                .snaplen(5000)
                .timeout(100)
                .open()
                .unwrap();
    let mut cap: Capture<pcap::Active> = capture.setnonblock().unwrap();
    cap.filter(&format!("(dst host {} and udp and dst portrange 33000-34000) or (icmp and src host {})", cli.host, cli.host), true).expect("Could not apply filter");

    let mut ports: Vec<u16> = Vec::new();
    for i in 0..cli.numprobes {
        let dst_port = 33434 + i;
        ports.push(dst_port);
    }
    let reference_ports = ports.clone();
    
    let (tx, rx) = std::sync::mpsc::channel();

    let mut udp_sent: i32 = 0;
    let mut icmp_received: i32 = 0;
    let capture_thread = std::thread::spawn(move || {
        let mut map: HashMap<u16, Vec<Duration>> = HashMap::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let packet = match cap.next_packet() {
                Ok(packet) => packet,
                Err(pcap::Error::TimeoutExpired) => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                },
                Err(error) => {
                    eprintln!("Could not parse packet: {error}");
                    continue;
                }
            };
            let h = etherparse::PacketHeaders::from_ethernet_slice(&packet.data).unwrap();

            let timestamp = packet_timestamp_to_duration(packet.header);
            match h.transport {
                Some(etherparse::TransportHeader::Udp(udp)) => {
                    let source_port = udp.source_port;
                    let destination_port = udp.destination_port;
                    
                    if source_port == 10000 
                        && reference_ports.contains(&destination_port) {
                        println!("Hey! Just captured a send packet.");

                        map.entry(destination_port)
                            .or_insert_with(Vec::new)
                            .push(timestamp);
                        udp_sent += 1;
                    }
                }

                Some(etherparse::TransportHeader::Icmpv4(_icmp)) => {
                    let original_packet = h.payload.slice();

                    // Minimo 28 perché original ip header = 20 e 8 di original
                    if original_packet.len() >= 28 {
                        let ip_header_len = ((original_packet[0] & 0x0f) * 4) as usize;

                        if original_packet.len() >= ip_header_len + 8 {
                            let destination_port = u16::from_be_bytes([
                                original_packet[ip_header_len + 2],
                                original_packet[ip_header_len + 3],
                            ]);

                            if reference_ports.contains(&destination_port) {
                                    let icmp_probe_port = destination_port;
                                    map.entry(icmp_probe_port)
                                        .or_insert_with(Vec::new)
                                        .push(timestamp);
                                    println!("Hey! Just captured an ICMP return packet.");
                                    icmp_received += 1;
                            }
                        }
                    }

                    continue;
                }

                _ => {}
            };

        }

        let msg = Msg {icmp_received: icmp_received, udp_sent: udp_sent, map: map};
        tx.send(msg).unwrap();
    });

    std::thread::sleep(Duration::from_millis(1000));
    for i in 0..cli.numprobes {
        let port = ports.get(i as usize);
        let addr: SocketAddr = format!("{}:{:?}", cli.host, port.unwrap()).parse().unwrap();
        println!("Trying to ping {addr}");

        sock.send_to("ping".as_bytes(), addr)
            .expect(&format!("Could not ping! Port: {:?}", port.unwrap()));
        println!("Just sent a packet");
    }

    capture_thread.join().unwrap(); // valutare se serve

    match rx.recv() {
        Ok(msg) => {
            // Output
            println!("\nUDP Probing Report");
            println!("Destination: {}", cli.host);
            println!("Probes sent: {}", cli.numprobes);
            println!("UDP packets captured: {}", msg.udp_sent);
            println!("ICMP port unreachable received: {}", msg.icmp_received);
            println!("Lost replies: {}", msg.udp_sent - msg.icmp_received);

            println!("\nPer probe results:");
            println!("ID    Port Number      RTT(ms)");

            let mut id = 1;
            for (key, value) in msg.map.into_iter() {
                if value.len() > 1 {
                    let rtt = value.get(1).unwrap().to_owned() - value.get(0).unwrap().to_owned();
                    println!("{}     {}            {:?}", id, key, rtt);
                    id += 1;
                }
            }
        }
        Err(std::sync::mpsc::RecvError) => {},
    }

}

pub fn packet_timestamp_to_duration(pcap_hdr: &pcap::PacketHeader) -> Duration {
    let ts = pcap_hdr.ts;
    Duration::new(ts.tv_sec as u64, (ts.tv_usec as u32) * 1_000)
}