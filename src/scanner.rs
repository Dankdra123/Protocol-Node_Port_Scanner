use crate::{
    cli::Args, inspection::inspect_open_port, models::ScanResult, progress::create_progress_bar,
    services::identify_service,
};
use colored::Colorize;
use std::{
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

pub struct ScanOutput {
    pub results: Vec<ScanResult>,
    pub requested_ports: usize,
    pub scanned_ports: usize,
    pub elapsed: Duration,
    pub was_cancelled: bool,
}

pub fn resolve_target(target: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    let addresses = (target, 0)
        .to_socket_addrs()
        .map_err(|error| format!("Failed to resolve '{target}': {error}"))?;

    addresses
        .filter(|address| address.is_ipv4())
        .map(|address| address.ip())
        .next()
        .ok_or_else(|| format!("No IPv4 address found for '{target}'"))
}

fn scan_port(
    ip: IpAddr,
    port: u16,
    hostname: &str,
    connect_timeout: Duration,
    inspection_timeout: Duration,
    banners_enabled: bool,
    inspection_enabled: bool,
) -> Option<ScanResult> {
    let address = SocketAddr::new(ip, port);

    if TcpStream::connect_timeout(&address, connect_timeout).is_err() {
        return None;
    }

    let inspection = inspect_open_port(
        ip,
        port,
        hostname,
        connect_timeout,
        inspection_timeout,
        banners_enabled,
        inspection_enabled,
    );

    Some(ScanResult {
        port,
        service: identify_service(port),
        banner: inspection.banner,
        http: inspection.http,
        tls: inspection.tls,
    })
}

pub fn run_scan(args: &Args, ip: IpAddr, ports: Vec<u16>) -> ScanOutput {
    let total_ports = ports.len();
    let worker_count = args.threads.min(total_ports);
    let connect_timeout = Duration::from_millis(args.timeout);
    let inspection_timeout = Duration::from_millis(args.banner_timeout);

    let started = Instant::now();
    let ports = Arc::new(ports);
    let next_index = Arc::new(AtomicUsize::new(0));
    let completed_ports = Arc::new(AtomicUsize::new(0));
    let cancelled = Arc::new(AtomicBool::new(false));

    let progress_bar = create_progress_bar(total_ports as u64);

    {
        let cancelled = Arc::clone(&cancelled);
        let progress_bar = progress_bar.clone();

        ctrlc::set_handler(move || {
            if !cancelled.swap(true, Ordering::SeqCst) {
                progress_bar.abandon_with_message(
                    "Cancellation requested — finishing active connections...",
                );
            }
        })
        .unwrap_or_else(|error| {
            eprintln!(
                "{} Could not install Ctrl+C handler: {error}",
                "Warning:".yellow().bold()
            );
        });
    }

    let (result_sender, result_receiver) = mpsc::channel::<ScanResult>();
    let mut worker_handles = Vec::with_capacity(worker_count);
    let hostname = Arc::new(args.target.clone());

    for _ in 0..worker_count {
        let ports = Arc::clone(&ports);
        let next_index = Arc::clone(&next_index);
        let completed_ports = Arc::clone(&completed_ports);
        let cancelled = Arc::clone(&cancelled);
        let result_sender = result_sender.clone();
        let progress_bar = progress_bar.clone();
        let hostname = Arc::clone(&hostname);

        let banners_enabled = args.banners;
        let inspection_enabled = args.inspect;

        let handle = thread::spawn(move || {
            loop {
                if cancelled.load(Ordering::Relaxed) {
                    break;
                }

                let index = next_index.fetch_add(1, Ordering::Relaxed);

                let Some(&port) = ports.get(index) else {
                    break;
                };

                if cancelled.load(Ordering::Relaxed) {
                    break;
                }

                let result = scan_port(
                    ip,
                    port,
                    hostname.as_str(),
                    connect_timeout,
                    inspection_timeout,
                    banners_enabled,
                    inspection_enabled,
                );

                completed_ports.fetch_add(1, Ordering::Relaxed);
                progress_bar.inc(1);

                if let Some(result) = result {
                    if result_sender.send(result).is_err() {
                        break;
                    }
                }
            }
        });

        worker_handles.push(handle);
    }

    drop(result_sender);

    let mut results: Vec<ScanResult> = result_receiver.iter().collect();

    for handle in worker_handles {
        if handle.join().is_err() {
            progress_bar.println(format!(
                "{} A worker thread terminated unexpectedly.",
                "Warning:".yellow().bold()
            ));
        }
    }

    let was_cancelled = cancelled.load(Ordering::Relaxed);

    if !was_cancelled {
        progress_bar.finish_with_message("Scan complete");
    }

    results.sort_unstable_by_key(|result| result.port);

    ScanOutput {
        results,
        requested_ports: total_ports,
        scanned_ports: completed_ports.load(Ordering::Relaxed),
        elapsed: started.elapsed(),
        was_cancelled,
    }
}
