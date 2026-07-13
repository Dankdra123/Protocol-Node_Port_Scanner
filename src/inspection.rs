use crate::{
    models::{HttpInfo, TlsInfo},
    services::{is_https_port, is_plain_http_port, is_tls_port},
};
use native_tls::{TlsConnector, TlsStream};
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    time::Duration,
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

const MAX_RESPONSE_BYTES: usize = 32 * 1024;
const MAX_TITLE_LENGTH: usize = 200;

#[derive(Debug, Default)]
pub struct InspectionResult {
    pub banner: Option<String>,
    pub http: Option<HttpInfo>,
    pub tls: Option<TlsInfo>,
}

pub fn inspect_open_port(
    ip: IpAddr,
    port: u16,
    hostname: &str,
    connect_timeout: Duration,
    inspection_timeout: Duration,
    banners_enabled: bool,
    inspection_enabled: bool,
) -> InspectionResult {
    if inspection_enabled && is_tls_port(port) {
        return inspect_tls_service(ip, port, hostname, connect_timeout, inspection_timeout);
    }

    if inspection_enabled && is_plain_http_port(port) {
        return inspect_plain_http(ip, port, hostname, connect_timeout, inspection_timeout);
    }

    if banners_enabled {
        return InspectionResult {
            banner: grab_passive_banner(ip, port, connect_timeout, inspection_timeout),
            ..InspectionResult::default()
        };
    }

    InspectionResult::default()
}

fn connect(
    ip: IpAddr,
    port: u16,
    connect_timeout: Duration,
    io_timeout: Duration,
) -> Option<TcpStream> {
    let address = SocketAddr::new(ip, port);
    let stream = TcpStream::connect_timeout(&address, connect_timeout).ok()?;

    stream.set_read_timeout(Some(io_timeout)).ok()?;
    stream.set_write_timeout(Some(io_timeout)).ok()?;

    Some(stream)
}

fn inspect_plain_http(
    ip: IpAddr,
    port: u16,
    hostname: &str,
    connect_timeout: Duration,
    inspection_timeout: Duration,
) -> InspectionResult {
    let Some(mut stream) = connect(ip, port, connect_timeout, inspection_timeout) else {
        return InspectionResult::default();
    };

    let response = request_http(&mut stream, hostname);

    InspectionResult {
        banner: response.as_deref().and_then(first_response_line),
        http: response.as_deref().and_then(parse_http_response),
        tls: None,
    }
}

fn inspect_tls_service(
    ip: IpAddr,
    port: u16,
    hostname: &str,
    connect_timeout: Duration,
    inspection_timeout: Duration,
) -> InspectionResult {
    let Some(stream) = connect(ip, port, connect_timeout, inspection_timeout) else {
        return InspectionResult::default();
    };

    /*
     * Inspection mode accepts invalid or self-signed certificates so that
     * their metadata can still be displayed. This does not mean the
     * certificate has been verified as trusted.
     */
    let connector = match TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
    {
        Ok(connector) => connector,
        Err(_) => return InspectionResult::default(),
    };

    let mut tls_stream = match connector.connect(hostname, stream) {
        Ok(stream) => stream,
        Err(_) => return InspectionResult::default(),
    };

    let tls = extract_certificate_info(&tls_stream);

    let response = if is_https_port(port) {
        request_http(&mut tls_stream, hostname)
    } else {
        None
    };

    InspectionResult {
        banner: response
            .as_deref()
            .and_then(first_response_line)
            .or_else(|| Some("TLS service".to_string())),

        http: response.as_deref().and_then(parse_http_response),
        tls,
    }
}

fn extract_certificate_info(stream: &TlsStream<TcpStream>) -> Option<TlsInfo> {
    let certificate = stream.peer_certificate().ok()??;
    let der = certificate.to_der().ok()?;
    let (_, certificate) = parse_x509_certificate(&der).ok()?;

    let dns_names = certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(name) => Some((*name).to_string()),
                    _ => None,
                })
                .take(20)
                .collect()
        })
        .unwrap_or_default();

    Some(TlsInfo {
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        not_before: certificate.validity().not_before.to_string(),
        not_after: certificate.validity().not_after.to_string(),
        dns_names,
        validation: "not performed",
    })
}

fn request_http<S: Read + Write>(stream: &mut S, hostname: &str) -> Option<Vec<u8>> {
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {hostname}\r\n\
         User-Agent: Sentinel-Scan/{}\r\n\
         Accept: text/html,*/*;q=0.8\r\n\
         Connection: close\r\n\
         \r\n",
        env!("CARGO_PKG_VERSION")
    );

    stream.write_all(request.as_bytes()).ok()?;
    stream.flush().ok()?;

    read_limited(stream)
}

fn grab_passive_banner(
    ip: IpAddr,
    port: u16,
    connect_timeout: Duration,
    inspection_timeout: Duration,
) -> Option<String> {
    let mut stream = connect(ip, port, connect_timeout, inspection_timeout)?;

    let bytes = read_limited(&mut stream)?;
    clean_text(&bytes)
}

fn read_limited<S: Read>(stream: &mut S) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer = [0_u8; 4096];

    while result.len() < MAX_RESPONSE_BYTES {
        match stream.read(&mut buffer) {
            Ok(0) => break,

            Ok(bytes_read) => {
                let remaining = MAX_RESPONSE_BYTES - result.len();
                let amount = bytes_read.min(remaining);
                result.extend_from_slice(&buffer[..amount]);

                if amount < bytes_read {
                    break;
                }
            }

            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }

            Err(_) => return None,
        }
    }

    (!result.is_empty()).then_some(result)
}

fn parse_http_response(bytes: &[u8]) -> Option<HttpInfo> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);

    response.parse(bytes).ok()?;

    let server = response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("server"))
        .map(|header| String::from_utf8_lossy(header.value).trim().to_string())
        .filter(|value| !value.is_empty());

    Some(HttpInfo {
        status_code: response.code,
        reason: response.reason.map(str::to_string),
        server,
        title: extract_html_title(bytes),
    })
}

fn extract_html_title(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let lowercase = text.to_lowercase();

    let title_start = lowercase.find("<title")?;
    let opening_end = lowercase[title_start..].find('>')? + title_start + 1;
    let closing_start = lowercase[opening_end..].find("</title>")? + opening_end;

    let title = text[opening_end..closing_start]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    if title.is_empty() {
        return None;
    }

    Some(title.chars().take(MAX_TITLE_LENGTH).collect())
}

fn first_response_line(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);

    text.lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
}

fn clean_text(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);

    let cleaned = text
        .replace('\0', "")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(6)
        .collect::<Vec<_>>()
        .join(" | ")
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>();

    (!cleaned.is_empty()).then_some(cleaned)
}
