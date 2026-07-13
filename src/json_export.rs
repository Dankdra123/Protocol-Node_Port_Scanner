use crate::{
    cli::{Args, port_selection_description},
    models::ScanResult,
    scanner::ScanOutput,
};
use serde::Serialize;
use std::{
    fs::File,
    io::{BufWriter, Write},
    net::IpAddr,
    path::Path,
};

#[derive(Serialize)]
struct JsonReport<'a> {
    scanner: &'static str,
    version: &'static str,
    target: &'a str,
    resolved_ip: String,
    scan: JsonScanDetails,
    results: &'a [ScanResult],
}

#[derive(Serialize)]
struct JsonScanDetails {
    port_selection: String,
    requested_ports: usize,
    scanned_ports: usize,
    open_ports: usize,
    workers: usize,
    connect_timeout_ms: u64,
    banner_grabbing: bool,
    service_inspection: bool,
    inspection_timeout_ms: Option<u64>,
    elapsed_seconds: f64,
    ports_per_second: f64,
    cancelled: bool,
}

pub fn export_json(
    path: &Path,
    args: &Args,
    ip: IpAddr,
    output: &ScanOutput,
) -> Result<(), String> {
    let elapsed_seconds = output.elapsed.as_secs_f64();

    let ports_per_second = if elapsed_seconds > 0.0 {
        output.scanned_ports as f64 / elapsed_seconds
    } else {
        output.scanned_ports as f64
    };

    let report = JsonReport {
        scanner: "Sentinel Scan",
        version: env!("CARGO_PKG_VERSION"),
        target: &args.target,
        resolved_ip: ip.to_string(),

        scan: JsonScanDetails {
            port_selection: port_selection_description(args),
            requested_ports: output.requested_ports,
            scanned_ports: output.scanned_ports,
            open_ports: output.results.len(),
            workers: args.threads.min(output.requested_ports),
            connect_timeout_ms: args.timeout,
            banner_grabbing: args.banners,
            service_inspection: args.inspect,

            inspection_timeout_ms: if args.banners || args.inspect {
                Some(args.banner_timeout)
            } else {
                None
            },

            elapsed_seconds,
            ports_per_second,
            cancelled: output.was_cancelled,
        },

        results: &output.results,
    };

    let file = File::create(path)
        .map_err(|error| format!("could not create '{}': {error}", path.display()))?;

    let mut writer = BufWriter::new(file);

    serde_json::to_writer_pretty(&mut writer, &report)
        .map_err(|error| format!("could not serialize JSON: {error}"))?;

    writer
        .write_all(b"\n")
        .map_err(|error| format!("could not finish JSON output: {error}"))?;

    writer
        .flush()
        .map_err(|error| format!("could not save '{}': {error}", path.display()))
}
