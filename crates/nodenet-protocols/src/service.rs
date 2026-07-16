//! Bounded, syscall-free service conversation response codecs and registry.

pub const MAX_SERVICE_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_SERVICE_FIELDS: usize = 64;
pub const MAX_SERVICE_TEXT_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRisk {
    ServerFirst,
    ClientNegotiation,
    StatefulHandshake,
    SensitiveRead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceDisposition {
    Implemented,
    OptIn,
    NoGo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceDescriptor {
    pub id: &'static str,
    pub default_ports: &'static [u16],
    pub disposition: ServiceDisposition,
    pub risk: ServiceRisk,
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: usize,
}

pub const SERVICE_REGISTRY_VERSION: &str = "1.0.0";
pub const SERVICE_REGISTRY: &[ServiceDescriptor] = &[
    descriptor(
        "ssh-identification",
        &[22],
        ServiceDisposition::Implemented,
        ServiceRisk::ServerFirst,
        0,
        255,
    ),
    descriptor(
        "ftp-greeting",
        &[21],
        ServiceDisposition::Implemented,
        ServiceRisk::ServerFirst,
        0,
        4096,
    ),
    descriptor(
        "smtp-greeting",
        &[25, 587],
        ServiceDisposition::Implemented,
        ServiceRisk::ServerFirst,
        0,
        4096,
    ),
    descriptor(
        "pop3-greeting",
        &[110],
        ServiceDisposition::Implemented,
        ServiceRisk::ServerFirst,
        0,
        4096,
    ),
    descriptor(
        "imap-greeting",
        &[143],
        ServiceDisposition::Implemented,
        ServiceRisk::ServerFirst,
        0,
        4096,
    ),
    descriptor(
        "mysql-initial-handshake",
        &[3306],
        ServiceDisposition::Implemented,
        ServiceRisk::ServerFirst,
        0,
        65536,
    ),
    descriptor(
        "tls-client-hello",
        &[443, 465, 636, 853, 993, 995, 8443],
        ServiceDisposition::NoGo,
        ServiceRisk::StatefulHandshake,
        0,
        0,
    ),
    descriptor(
        "http-head",
        &[80, 8000, 8080, 8888],
        ServiceDisposition::OptIn,
        ServiceRisk::ClientNegotiation,
        4096,
        65536,
    ),
    descriptor(
        "smb2-negotiate",
        &[445],
        ServiceDisposition::NoGo,
        ServiceRisk::StatefulHandshake,
        0,
        0,
    ),
    descriptor(
        "rdp-negotiation",
        &[3389],
        ServiceDisposition::NoGo,
        ServiceRisk::StatefulHandshake,
        0,
        0,
    ),
    descriptor(
        "postgresql-ssl-request",
        &[5432],
        ServiceDisposition::OptIn,
        ServiceRisk::ClientNegotiation,
        8,
        1,
    ),
    descriptor(
        "redis-ping",
        &[6379],
        ServiceDisposition::OptIn,
        ServiceRisk::ClientNegotiation,
        14,
        4096,
    ),
    descriptor(
        "mongodb-hello",
        &[27017],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "ldap-root-dse",
        &[389, 636],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "ipp-identity",
        &[631],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "rtsp-options",
        &[554, 8554],
        ServiceDisposition::NoGo,
        ServiceRisk::ClientNegotiation,
        0,
        0,
    ),
    descriptor(
        "onvif-metadata",
        &[80, 8000],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "bacnet-read-property",
        &[47808],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "ethernet-ip-identity",
        &[44818],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "modbus-device-identification",
        &[502],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "opc-ua-get-endpoints",
        &[4840],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "s7-identity",
        &[102],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "dnp3-identity",
        &[20000],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
    descriptor(
        "snmp-system-read",
        &[161],
        ServiceDisposition::NoGo,
        ServiceRisk::SensitiveRead,
        0,
        0,
    ),
];

const fn descriptor(
    id: &'static str,
    default_ports: &'static [u16],
    disposition: ServiceDisposition,
    risk: ServiceRisk,
    maximum_request_bytes: usize,
    maximum_response_bytes: usize,
) -> ServiceDescriptor {
    ServiceDescriptor {
        id,
        default_ports,
        disposition,
        risk,
        maximum_request_bytes,
        maximum_response_bytes,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceCodecError {
    Truncated,
    Malformed,
    Unsupported,
    LimitExceeded,
}

impl std::fmt::Display for ServiceCodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "service response is {self:?}")
    }
}

impl std::error::Error for ServiceCodecError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceIdentity {
    pub protocol: &'static str,
    pub confidence: &'static str,
    pub fields: Vec<(&'static str, Vec<u8>)>,
}

/// Parses one server-first or bounded negotiated service response.
///
/// # Errors
///
/// Rejects oversized, malformed, truncated, or unsupported responses.
pub fn parse_service_response(
    protocol: &str,
    bytes: &[u8],
) -> Result<ServiceIdentity, ServiceCodecError> {
    if bytes.len() > MAX_SERVICE_RESPONSE_BYTES {
        return Err(ServiceCodecError::LimitExceeded);
    }
    match protocol {
        "ssh-identification" => ssh(bytes),
        "ftp-greeting" => greeting("ftp", bytes, |line| line.starts_with(b"220")),
        "smtp-greeting" => greeting("smtp", bytes, |line| line.starts_with(b"220")),
        "pop3-greeting" => greeting("pop3", bytes, |line| line.starts_with(b"+OK")),
        "imap-greeting" => greeting("imap", bytes, |line| line.starts_with(b"* OK")),
        "mysql-initial-handshake" => mysql(bytes),
        "tls-client-hello" => tls(bytes),
        "http-head" => http(bytes),
        "smb2-negotiate" => signature("smb2", bytes, &[0xfe, b'S', b'M', b'B']),
        "rdp-negotiation" => rdp(bytes),
        "postgresql-ssl-request" => postgres_ssl(bytes),
        "redis-ping" => greeting("redis", bytes, |line| {
            line == b"+PONG" || line.starts_with(b"-NOAUTH")
        }),
        "mongodb-hello" => mongo(bytes),
        _ => Err(ServiceCodecError::Unsupported),
    }
}

fn ssh(bytes: &[u8]) -> Result<ServiceIdentity, ServiceCodecError> {
    let line = first_line(bytes)?;
    if line.len() > 255 || !line.starts_with(b"SSH-2.0-") {
        return Err(ServiceCodecError::Malformed);
    }
    Ok(identity(
        "ssh",
        "syntacticallyValidHandshake",
        vec![("identification", line.to_vec())],
    ))
}

fn greeting(
    protocol: &'static str,
    bytes: &[u8],
    valid: impl FnOnce(&[u8]) -> bool,
) -> Result<ServiceIdentity, ServiceCodecError> {
    let line = first_line(bytes)?;
    if line.len() > MAX_SERVICE_TEXT_BYTES || !line.is_ascii() || !valid(line) {
        return Err(ServiceCodecError::Malformed);
    }
    Ok(identity(
        protocol,
        "banner",
        vec![("greeting", line.to_vec())],
    ))
}

fn mysql(bytes: &[u8]) -> Result<ServiceIdentity, ServiceCodecError> {
    if bytes.len() < 4 {
        return Err(ServiceCodecError::Truncated);
    }
    let length =
        usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16);
    let packet_end = length
        .checked_add(4)
        .ok_or(ServiceCodecError::LimitExceeded)?;
    if packet_end > bytes.len() {
        return Err(ServiceCodecError::Truncated);
    }
    if length < 6 || bytes[3] != 0 || bytes[4] != 10 {
        return Err(ServiceCodecError::Malformed);
    }
    let version_end = bytes[5..packet_end]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ServiceCodecError::Malformed)?
        .saturating_add(5);
    let version = &bytes[5..version_end];
    if version.is_empty()
        || version.len() > 255
        || !version.is_ascii()
        || version_end.saturating_add(5) > packet_end
    {
        return Err(ServiceCodecError::Malformed);
    }
    Ok(identity(
        "mysql",
        "syntacticallyValidHandshake",
        vec![
            ("serverVersion", version.to_vec()),
            (
                "connectionId",
                bytes[version_end + 1..version_end + 5].to_vec(),
            ),
        ],
    ))
}

fn tls(bytes: &[u8]) -> Result<ServiceIdentity, ServiceCodecError> {
    if bytes.len() < 5 {
        return Err(ServiceCodecError::Truncated);
    }
    if !matches!(bytes[0], 21 | 22) {
        return Err(ServiceCodecError::Malformed);
    }
    let length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if length.saturating_add(5) > bytes.len() {
        return Err(ServiceCodecError::Truncated);
    }
    let kind = if bytes[0] == 21 { "alert" } else { "handshake" };
    Ok(identity(
        "tls",
        "record",
        vec![
            ("recordKind", kind.as_bytes().to_vec()),
            ("recordVersion", bytes[1..3].to_vec()),
        ],
    ))
}

fn http(bytes: &[u8]) -> Result<ServiceIdentity, ServiceCodecError> {
    if bytes.len() > MAX_SERVICE_RESPONSE_BYTES {
        return Err(ServiceCodecError::LimitExceeded);
    }
    let terminator = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ServiceCodecError::Truncated)?;
    let headers = &bytes[..terminator];
    let mut lines = headers.split(|byte| *byte == b'\n');
    let status = lines.next().ok_or(ServiceCodecError::Malformed)?;
    let status = status.strip_suffix(b"\r").unwrap_or(status);
    if status.len() < 12
        || status.len() > MAX_SERVICE_TEXT_BYTES
        || !status.is_ascii()
        || !(status.starts_with(b"HTTP/1.0 ") || status.starts_with(b"HTTP/1.1 "))
        || !status[9..12].iter().all(u8::is_ascii_digit)
        || status.get(12).is_some_and(|byte| *byte != b' ')
    {
        return Err(ServiceCodecError::Malformed);
    }
    let mut fields = vec![("statusLine", status.to_vec())];
    for line in lines.take(MAX_SERVICE_FIELDS - 1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            return Err(ServiceCodecError::Malformed);
        };
        let name = &line[..separator];
        let value = trim_ascii(&line[separator + 1..]);
        if name.is_empty()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            || value.len() > MAX_SERVICE_TEXT_BYTES
            || !value.is_ascii()
        {
            return Err(ServiceCodecError::Malformed);
        }
        if name.eq_ignore_ascii_case(b"server") {
            fields.push(("server", value.to_vec()));
        } else if name.eq_ignore_ascii_case(b"content-type") {
            fields.push(("contentType", value.to_vec()));
        }
    }
    Ok(identity("http", "syntacticallyValidResponse", fields))
}

fn signature(
    protocol: &'static str,
    bytes: &[u8],
    signature: &[u8],
) -> Result<ServiceIdentity, ServiceCodecError> {
    if bytes
        .windows(signature.len())
        .any(|window| window == signature)
    {
        Ok(identity(
            protocol,
            "syntacticallyValidHandshake",
            Vec::new(),
        ))
    } else {
        Err(ServiceCodecError::Malformed)
    }
}

fn rdp(bytes: &[u8]) -> Result<ServiceIdentity, ServiceCodecError> {
    if bytes.len() < 7
        || bytes[0] != 3
        || usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) > bytes.len()
    {
        return Err(ServiceCodecError::Malformed);
    }
    Ok(identity("rdp", "syntacticallyValidHandshake", Vec::new()))
}

fn postgres_ssl(bytes: &[u8]) -> Result<ServiceIdentity, ServiceCodecError> {
    match bytes.first() {
        Some(b'S') => Ok(identity("postgresql", "tlsSupported", Vec::new())),
        Some(b'N') => Ok(identity("postgresql", "tlsUnsupported", Vec::new())),
        Some(_) => Err(ServiceCodecError::Malformed),
        None => Err(ServiceCodecError::Truncated),
    }
}

fn mongo(bytes: &[u8]) -> Result<ServiceIdentity, ServiceCodecError> {
    if bytes.len() < 16 {
        return Err(ServiceCodecError::Truncated);
    }
    let length = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let opcode = i32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    if length < 16
        || usize::try_from(length).unwrap_or(usize::MAX) > bytes.len()
        || !matches!(opcode, 1 | 2013)
    {
        return Err(ServiceCodecError::Malformed);
    }
    Ok(identity(
        "mongodb",
        "syntacticallyValidHandshake",
        vec![("opcode", opcode.to_le_bytes().to_vec())],
    ))
}

fn first_line(bytes: &[u8]) -> Result<&[u8], ServiceCodecError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(ServiceCodecError::Truncated)?;
    Ok(bytes[..end].strip_suffix(b"\r").unwrap_or(&bytes[..end]))
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn identity(
    protocol: &'static str,
    confidence: &'static str,
    fields: Vec<(&'static str, Vec<u8>)>,
) -> ServiceIdentity {
    ServiceIdentity {
        protocol,
        confidence,
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_first_protocols() {
        assert_eq!(
            parse_service_response("ssh-identification", b"SSH-2.0-OpenSSH_9.9\r\n")
                .expect("ssh")
                .protocol,
            "ssh"
        );
        assert_eq!(
            parse_service_response("smtp-greeting", b"220 mail.example ESMTP\r\n")
                .expect("smtp")
                .protocol,
            "smtp"
        );
    }

    #[test]
    fn http_never_follows_redirects_or_returns_a_body() {
        let result = parse_service_response(
            "http-head",
            b"HTTP/1.1 302 Found\r\nLocation: http://elsewhere/\r\nServer: fixture\r\n\r\nbody",
        )
        .expect("http");
        assert!(result.fields.iter().all(|(name, _)| *name != "location"));
        assert!(result.fields.iter().all(|(_, value)| value != b"body"));
    }

    #[test]
    fn segmented_mysql_is_truncated_until_the_declared_packet_arrives() {
        let mut packet = vec![0_u8; 4];
        let body = b"\x0a8.4.0\0\x01\0\0\0";
        packet[..3].copy_from_slice(&[u8::try_from(body.len()).unwrap(), 0, 0]);
        packet.extend_from_slice(body);
        assert_eq!(
            parse_service_response("mysql-initial-handshake", &packet[..6]),
            Err(ServiceCodecError::Truncated)
        );
        assert_eq!(
            parse_service_response("mysql-initial-handshake", &packet)
                .expect("complete handshake")
                .protocol,
            "mysql"
        );
    }

    #[test]
    fn http_requires_a_numeric_status_and_bounded_selected_headers() {
        assert_eq!(
            parse_service_response("http-head", b"HTTP/1.1 OK nope\r\n\r\n"),
            Err(ServiceCodecError::Malformed)
        );
        let mut response = b"HTTP/1.1 200 OK\r\nServer: ".to_vec();
        response.extend(std::iter::repeat_n(b'a', MAX_SERVICE_TEXT_BYTES + 1));
        response.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            parse_service_response("http-head", &response),
            Err(ServiceCodecError::Malformed)
        );
    }
}
