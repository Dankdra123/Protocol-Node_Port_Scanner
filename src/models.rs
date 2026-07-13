use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HttpInfo {
    pub status_code: Option<u16>,
    pub reason: Option<String>,
    pub server: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TlsInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub dns_names: Vec<String>,

    // Certificate parsing does not by itself prove trust.
    pub validation: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub port: u16,
    pub service: &'static str,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
}
