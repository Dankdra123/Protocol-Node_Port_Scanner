use clap::{Parser, ValueEnum};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ScanProfile {
    Quick,
    Web,
    Database,
    Remote,
    Full,
}

#[derive(Parser, Debug)]
#[command(
    name = "sentinel-scan",
    version,
    about = "A fast multithreaded TCP scanner with service inspection"
)]
pub struct Args {
    /// IPv4 address or hostname to scan
    pub target: String,

    /// First port in a continuous range
    #[arg(
        short = 's',
        long,
        requires = "end_port",
        conflicts_with_all = ["ports", "profile"]
    )]
    pub start_port: Option<u16>,

    /// Last port in a continuous range
    #[arg(
        short = 'e',
        long,
        requires = "start_port",
        conflicts_with_all = ["ports", "profile"]
    )]
    pub end_port: Option<u16>,

    /// Specific ports and ranges, for example 22,80,443,8000-8010
    #[arg(
        short = 'p',
        long,
        value_name = "PORTS",
        conflicts_with_all = ["start_port", "end_port", "profile"]
    )]
    pub ports: Option<String>,

    /// Use a predefined port profile
    #[arg(
        long,
        value_enum,
        conflicts_with_all = ["start_port", "end_port", "ports"]
    )]
    pub profile: Option<ScanProfile>,

    /// Number of scanning worker threads
    #[arg(short = 't', long, default_value_t = 100)]
    pub threads: usize,

    /// TCP connection timeout in milliseconds
    #[arg(long, default_value_t = 300)]
    pub timeout: u64,

    /// Attempt basic banner retrieval
    #[arg(short = 'b', long)]
    pub banners: bool,

    /// Perform HTTP and TLS inspection on supported services
    #[arg(long)]
    pub inspect: bool,

    /// Service inspection timeout in milliseconds
    #[arg(long, default_value_t = 1000)]
    pub banner_timeout: u64,

    /// Save scan results as JSON
    #[arg(long, value_name = "FILE")]
    pub json: Option<PathBuf>,
}

pub fn validate_args(args: &Args) -> Result<(), String> {
    if args.threads == 0 {
        return Err("thread count must be at least 1".to_string());
    }

    if args.timeout == 0 {
        return Err("connection timeout must be greater than 0 ms".to_string());
    }

    if args.banner_timeout == 0 {
        return Err("inspection timeout must be greater than 0 ms".to_string());
    }

    if let (Some(start), Some(end)) = (args.start_port, args.end_port) {
        if start > end {
            return Err("start port cannot be greater than end port".to_string());
        }
    }

    Ok(())
}

pub fn resolve_ports(args: &Args) -> Result<Vec<u16>, String> {
    if let Some(specification) = &args.ports {
        return parse_port_specification(specification);
    }

    if let Some(profile) = args.profile {
        return Ok(profile_ports(profile));
    }

    if let (Some(start), Some(end)) = (args.start_port, args.end_port) {
        return Ok((start..=end).collect());
    }

    // Preserve the original default behaviour.
    Ok((1..=1024).collect())
}

pub fn port_selection_description(args: &Args) -> String {
    if let Some(specification) = &args.ports {
        return specification.clone();
    }

    if let Some(profile) = args.profile {
        return format!("profile:{profile:?}").to_lowercase();
    }

    if let (Some(start), Some(end)) = (args.start_port, args.end_port) {
        return format!("{start}-{end}");
    }

    "1-1024".to_string()
}

fn parse_port_specification(specification: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();

    for part in specification.split(',') {
        let part = part.trim();

        if part.is_empty() {
            return Err("port list contains an empty value".to_string());
        }

        if let Some((start, end)) = part.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;

            if start > end {
                return Err(format!("invalid port range '{part}': start exceeds end"));
            }

            ports.extend(start..=end);
        } else {
            ports.insert(parse_port(part)?);
        }
    }

    if ports.is_empty() {
        return Err("at least one port must be supplied".to_string());
    }

    Ok(ports.into_iter().collect())
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("'{value}' is not a valid TCP port"))?;

    if port == 0 {
        return Err("port 0 is not supported".to_string());
    }

    Ok(port)
}

fn profile_ports(profile: ScanProfile) -> Vec<u16> {
    match profile {
        ScanProfile::Quick => vec![
            20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993,
            995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
        ],

        ScanProfile::Web => {
            vec![80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9200]
        }

        ScanProfile::Database => {
            vec![1433, 1521, 3306, 5432, 6379, 9200, 27017]
        }

        ScanProfile::Remote => vec![22, 23, 3389, 5900],

        ScanProfile::Full => (1..=u16::MAX).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_port_specification;

    #[test]
    fn parses_mixed_port_specification() {
        let ports = parse_port_specification("22,80,443,8000-8002").unwrap();

        assert_eq!(ports, vec![22, 80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn removes_duplicate_ports() {
        let ports = parse_port_specification("80,80,79-81").unwrap();

        assert_eq!(ports, vec![79, 80, 81]);
    }

    #[test]
    fn rejects_reversed_range() {
        assert!(parse_port_specification("100-20").is_err());
    }
}
