use crate::{
    cli::{Args, port_selection_description},
    scanner::ScanOutput,
};
use colored::Colorize;
use std::net::IpAddr;

pub fn print_scan_header(args: &Args, ip: IpAddr, port_count: usize) {
    let workers = args.threads.min(port_count);

    println!(
        "{}",
        "┌──────────────────────────────────────────────┐".magenta()
    );
    println!(
        "{}",
        "│ PROTOCOL NODE // PORT SCANNER                │"
            .magenta()
            .bold()
    );
    println!(
        "{}",
        "└──────────────────────────────────────────────┘".magenta()
    );

    println!();
    println!("TARGET NODE       {}", args.target);
    println!("NODE ADDRESS      {ip}");
    println!(
        "PORT SELECTION    {} ({port_count} total)",
        port_selection_description(args)
    );
    println!("SCANNER THREADS   {workers}");
    println!("CONNECT TIMEOUT   {} ms", args.timeout);

    println!("BANNER CAPTURE    {}", enabled_text(args.banners));

    println!("DEEP INSPECTION   {}", enabled_text(args.inspect));

    if args.banners || args.inspect {
        println!("INSPECT TIMEOUT   {} ms", args.banner_timeout);
    }

    println!();
    println!("{} Establishing target link...", ">".magenta().bold());
    println!("{} Mapping exposed protocols...", ">".magenta().bold());

    if args.banners {
        println!("{} Reading service signatures...", ">".magenta().bold());
    }

    if args.inspect {
        println!("{} Inspecting encrypted channels...", ">".magenta().bold());
    }

    println!();
}

pub fn print_scan_output(args: &Args, output: &ScanOutput) {
    println!();

    if output.was_cancelled {
        println!("{}", "Scan cancelled by user.".yellow().bold());
        println!("Displaying partial results.");
        println!();
    }

    if output.results.is_empty() {
        println!("{}", "No open TCP ports found.".yellow());
    }

    for result in &output.results {
        println!(
            "{}  {}  {}",
            format!("{}/tcp", result.port).green().bold(),
            "open".green().bold(),
            result.service.green()
        );

        if let Some(banner) = &result.banner {
            println!("  Banner: {banner}");
        }

        if let Some(http) = &result.http {
            let status = match (http.status_code, &http.reason) {
                (Some(code), Some(reason)) => format!("{code} {reason}"),
                (Some(code), None) => code.to_string(),
                _ => "unknown".to_string(),
            };

            println!("  HTTP status: {status}");

            if let Some(server) = &http.server {
                println!("  HTTP server: {server}");
            }

            if let Some(title) = &http.title {
                println!("  Page title:  {title}");
            }
        }

        if let Some(tls) = &result.tls {
            println!("  TLS subject: {}", tls.subject);
            println!("  TLS issuer:  {}", tls.issuer);
            println!("  Valid from:  {}", tls.not_before);
            println!("  Valid until: {}", tls.not_after);
            println!("  Validation:  {}", tls.validation);

            if !tls.dns_names.is_empty() {
                println!("  DNS names:   {}", tls.dns_names.join(", "));
            }
        }

        println!();
    }

    let elapsed_seconds = output.elapsed.as_secs_f64();

    let ports_per_second = if elapsed_seconds > 0.0 {
        output.scanned_ports as f64 / elapsed_seconds
    } else {
        output.scanned_ports as f64
    };

    println!("{}", "Scan summary".cyan().bold());
    println!("{}", "------------".cyan());
    println!("Requested:  {} ports", output.requested_ports);
    println!("Scanned:    {} ports", output.scanned_ports);
    println!(
        "Open:       {}",
        output.results.len().to_string().green().bold()
    );
    println!("Elapsed:    {:.2?}", output.elapsed);
    println!("Speed:      {ports_per_second:.0} ports/second");

    if args.inspect {
        println!("Inspection: HTTP and TLS metadata enabled");
    }
}

fn enabled_text(enabled: bool) -> String {
    if enabled {
        "enabled".green().to_string()
    } else {
        "disabled".yellow().to_string()
    }
}
