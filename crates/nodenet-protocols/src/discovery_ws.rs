//! Bounded WS-Discovery and LLMNR request/response primitives.

use core::fmt;

use quick_xml::events::Event;
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;

use crate::{
    DiscoveryDnsError, DiscoveryDnsMessage, build_discovery_dns_query, parse_discovery_dns_message,
};

const SOAP_NAMESPACE: &[u8] = b"http://www.w3.org/2003/05/soap-envelope";
const ADDRESSING_NAMESPACE: &[u8] = b"http://www.w3.org/2005/08/addressing";
const DISCOVERY_NAMESPACE: &[u8] = b"http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01";
const PROBE_MATCHES_ACTION: &str =
    "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/ProbeMatches";
const ANONYMOUS_TO: &str = "http://www.w3.org/2005/08/addressing/anonymous";

pub const MAX_WS_DISCOVERY_ENVELOPE_BYTES: usize = 4_096;
pub const MAX_WS_DISCOVERY_XML_DEPTH: usize = 32;
pub const MAX_WS_DISCOVERY_XML_TOKENS: usize = 4_096;
pub const MAX_WS_DISCOVERY_MATCHES: usize = 256;
pub const MAX_WS_DISCOVERY_VALUES: usize = 128;
pub const MAX_WS_DISCOVERY_TEXT_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WsDiscoveryError {
    EnvelopeTooLarge,
    InvalidMessageId,
    MalformedXml,
    UnsupportedXml,
    UnknownNamespacePrefix,
    TooDeep,
    TooManyTokens,
    TooManyValues,
    TextTooLarge,
    MissingHeader,
    UnrelatedResponse,
    InvalidProbeMatch,
}

impl fmt::Display for WsDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid WS-Discovery envelope: {self:?}")
    }
}

impl std::error::Error for WsDiscoveryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WsDiscoveryAppSequence {
    pub instance_id: u64,
    pub message_number: u64,
    pub sequence_id: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WsDiscoveryProbeMatch {
    pub endpoint_address: String,
    pub types: Vec<String>,
    pub scopes: Vec<String>,
    pub xaddrs: Vec<String>,
    pub metadata_version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WsDiscoveryProbeMatches {
    pub message_id: String,
    pub relates_to: String,
    pub app_sequence: WsDiscoveryAppSequence,
    pub matches: Vec<WsDiscoveryProbeMatch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LlmnrResponse {
    pub message: DiscoveryDnsMessage,
    pub conflict: bool,
    pub tentative: bool,
}

/// Builds one standards-framed SOAP-over-UDP Probe envelope.
///
/// # Errors
///
/// Rejects an all-zero message ID or an envelope beyond the frozen bound.
pub fn build_ws_discovery_probe(message_id: [u8; 16]) -> Result<Vec<u8>, WsDiscoveryError> {
    if message_id.iter().all(|byte| *byte == 0) {
        return Err(WsDiscoveryError::InvalidMessageId);
    }
    let id = uuid_urn(message_id);
    let envelope = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:d=\"http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01\">\
<s:Header><a:Action>http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/Probe</a:Action><a:MessageID>{id}</a:MessageID><a:To>urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01</a:To></s:Header>\
<s:Body><d:Probe/></s:Body></s:Envelope>"
    );
    if envelope.len() > MAX_WS_DISCOVERY_ENVELOPE_BYTES {
        return Err(WsDiscoveryError::EnvelopeTooLarge);
    }
    Ok(envelope.into_bytes())
}

/// Strictly parses a complete `ProbeMatches` envelope related to `request_id`.
///
/// # Errors
///
/// Rejects unsupported XML, malformed namespaces/structure, unrelated IDs,
/// and every configured depth, token, text, attribute, or match overflow.
#[allow(
    clippy::too_many_lines,
    reason = "one streaming state machine keeps complete envelope ownership visible"
)]
pub fn parse_ws_discovery_probe_matches(
    input: &[u8],
    request_id: &str,
) -> Result<WsDiscoveryProbeMatches, WsDiscoveryError> {
    if input.len() > MAX_WS_DISCOVERY_ENVELOPE_BYTES {
        return Err(WsDiscoveryError::EnvelopeTooLarge);
    }
    let mut reader = NsReader::from_reader(input);
    reader.config_mut().enable_all_checks(true);
    reader.config_mut().expand_empty_elements = true;
    let mut depth = 0_usize;
    let mut tokens = 0_usize;
    let mut stack: Vec<ElementKey> = Vec::new();
    let mut action = None;
    let mut message_id = None;
    let mut relates_to = None;
    let mut to = None;
    let mut app_sequence = None;
    let mut current_match = None;
    let mut matches = Vec::new();
    let mut saw_envelope = false;
    let mut saw_body = false;
    let mut saw_probe_matches = false;

    loop {
        let (resolution, event) = reader
            .read_resolved_event()
            .map_err(|_| WsDiscoveryError::MalformedXml)?;
        tokens += 1;
        if tokens > MAX_WS_DISCOVERY_XML_TOKENS {
            return Err(WsDiscoveryError::TooManyTokens);
        }
        match event {
            Event::Start(start) => {
                depth += 1;
                if depth > MAX_WS_DISCOVERY_XML_DEPTH {
                    return Err(WsDiscoveryError::TooDeep);
                }
                let key = element_key(resolution, start.local_name().as_ref())?;
                if key.matches(SOAP_NAMESPACE, b"Envelope") {
                    saw_envelope = true;
                } else if key.matches(SOAP_NAMESPACE, b"Body") {
                    saw_body = true;
                } else if key.matches(DISCOVERY_NAMESPACE, b"ProbeMatches") {
                    saw_probe_matches = true;
                }
                if key.matches(DISCOVERY_NAMESPACE, b"ProbeMatch") {
                    if current_match.is_some() {
                        return Err(WsDiscoveryError::InvalidProbeMatch);
                    }
                    current_match = Some(WsDiscoveryProbeMatch::default());
                }
                if key.matches(DISCOVERY_NAMESPACE, b"AppSequence") {
                    app_sequence = Some(parse_app_sequence(&start)?);
                }
                stack.push(key);
            }
            Event::End(end) => {
                let key = element_key(resolution, end.local_name().as_ref())?;
                let Some(open) = stack.pop() else {
                    return Err(WsDiscoveryError::MalformedXml);
                };
                if open != key {
                    return Err(WsDiscoveryError::MalformedXml);
                }
                if key.matches(DISCOVERY_NAMESPACE, b"ProbeMatch") {
                    let value = current_match
                        .take()
                        .ok_or(WsDiscoveryError::InvalidProbeMatch)?;
                    if value.endpoint_address.is_empty() || value.metadata_version == 0 {
                        return Err(WsDiscoveryError::InvalidProbeMatch);
                    }
                    if matches.len() >= MAX_WS_DISCOVERY_MATCHES {
                        return Err(WsDiscoveryError::TooManyValues);
                    }
                    matches.push(value);
                }
                depth = depth.checked_sub(1).ok_or(WsDiscoveryError::MalformedXml)?;
            }
            Event::Text(text) => {
                let decoded = text.decode().map_err(|_| WsDiscoveryError::MalformedXml)?;
                let value = quick_xml::escape::unescape(&decoded)
                    .map_err(|_| WsDiscoveryError::MalformedXml)?;
                let value = value.trim();
                if value.is_empty() {
                    continue;
                }
                if value.len() > MAX_WS_DISCOVERY_TEXT_BYTES {
                    return Err(WsDiscoveryError::TextTooLarge);
                }
                let Some(key) = stack.last() else {
                    return Err(WsDiscoveryError::MalformedXml);
                };
                if key.matches(ADDRESSING_NAMESPACE, b"Action") {
                    set_once(&mut action, value)?;
                } else if key.matches(ADDRESSING_NAMESPACE, b"MessageID") {
                    set_once(&mut message_id, value)?;
                } else if key.matches(ADDRESSING_NAMESPACE, b"RelatesTo") {
                    set_once(&mut relates_to, value)?;
                } else if key.matches(ADDRESSING_NAMESPACE, b"To") {
                    set_once(&mut to, value)?;
                } else if let Some(result) = current_match.as_mut() {
                    if key.matches(ADDRESSING_NAMESPACE, b"Address") {
                        if !result.endpoint_address.is_empty() {
                            return Err(WsDiscoveryError::InvalidProbeMatch);
                        }
                        value.clone_into(&mut result.endpoint_address);
                    } else if key.matches(DISCOVERY_NAMESPACE, b"Types") {
                        append_words(&mut result.types, value)?;
                    } else if key.matches(DISCOVERY_NAMESPACE, b"Scopes") {
                        append_words(&mut result.scopes, value)?;
                    } else if key.matches(DISCOVERY_NAMESPACE, b"XAddrs") {
                        append_words(&mut result.xaddrs, value)?;
                    } else if key.matches(DISCOVERY_NAMESPACE, b"MetadataVersion") {
                        result.metadata_version = value
                            .parse()
                            .map_err(|_| WsDiscoveryError::InvalidProbeMatch)?;
                    }
                }
            }
            Event::CData(cdata) => {
                let value = cdata.decode().map_err(|_| WsDiscoveryError::MalformedXml)?;
                if !value.trim().is_empty() {
                    return Err(WsDiscoveryError::UnsupportedXml);
                }
            }
            Event::Decl(declaration) => {
                if let Some(encoding) = declaration.encoding() {
                    let encoding = encoding.map_err(|_| WsDiscoveryError::MalformedXml)?;
                    if !encoding.eq_ignore_ascii_case(b"utf-8") {
                        return Err(WsDiscoveryError::UnsupportedXml);
                    }
                }
            }
            Event::DocType(_) | Event::GeneralRef(_) | Event::PI(_) => {
                return Err(WsDiscoveryError::UnsupportedXml);
            }
            Event::Comment(_) => {}
            Event::Empty(_) => return Err(WsDiscoveryError::MalformedXml),
            Event::Eof => break,
        }
    }
    if !stack.is_empty()
        || depth != 0
        || current_match.is_some()
        || !saw_envelope
        || !saw_body
        || !saw_probe_matches
    {
        return Err(WsDiscoveryError::MalformedXml);
    }
    let action = action.ok_or(WsDiscoveryError::MissingHeader)?;
    let message_id = message_id.ok_or(WsDiscoveryError::MissingHeader)?;
    let relates_to = relates_to.ok_or(WsDiscoveryError::MissingHeader)?;
    let to = to.ok_or(WsDiscoveryError::MissingHeader)?;
    let app_sequence = app_sequence.ok_or(WsDiscoveryError::MissingHeader)?;
    if action != PROBE_MATCHES_ACTION || relates_to != request_id || to != ANONYMOUS_TO {
        return Err(WsDiscoveryError::UnrelatedResponse);
    }
    Ok(WsDiscoveryProbeMatches {
        message_id,
        relates_to,
        app_sequence,
        matches,
    })
}

/// Builds one explicitly named LLMNR query using the bounded DNS encoder.
///
/// # Errors
///
/// Rejects invalid names and oversized DNS wire messages.
pub fn build_llmnr_query(
    id: u16,
    name: &str,
    query_type: u16,
) -> Result<Vec<u8>, DiscoveryDnsError> {
    build_discovery_dns_query(id, name, query_type, false)
}

/// Parses a complete LLMNR response related by transaction ID.
///
/// # Errors
///
/// Rejects malformed DNS wire data, non-responses, unrelated IDs, and nonzero response codes.
pub fn parse_llmnr_response(
    input: &[u8],
    expected_id: u16,
) -> Result<LlmnrResponse, DiscoveryDnsError> {
    let message = parse_discovery_dns_message(input)?;
    if !message.is_response() || message.id != expected_id || message.flags & 0x000f != 0 {
        return Err(DiscoveryDnsError::InvalidRecordLength);
    }
    Ok(LlmnrResponse {
        conflict: message.flags & 0x0400 != 0,
        tentative: message.flags & 0x0100 != 0,
        message,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ElementKey {
    namespace: Vec<u8>,
    local: Vec<u8>,
}

impl ElementKey {
    fn matches(&self, namespace: &[u8], local: &[u8]) -> bool {
        self.namespace == namespace && self.local == local
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "quick-xml returns namespace resolution by value with the event"
)]
fn element_key(
    resolution: ResolveResult<'_>,
    local: &[u8],
) -> Result<ElementKey, WsDiscoveryError> {
    let namespace = match resolution {
        ResolveResult::Bound(Namespace(value)) => value.to_vec(),
        ResolveResult::Unbound => Vec::new(),
        ResolveResult::Unknown(_) => return Err(WsDiscoveryError::UnknownNamespacePrefix),
    };
    Ok(ElementKey {
        namespace,
        local: local.to_vec(),
    })
}

fn parse_app_sequence(
    start: &quick_xml::events::BytesStart<'_>,
) -> Result<WsDiscoveryAppSequence, WsDiscoveryError> {
    let mut instance_id = None;
    let mut message_number = None;
    let mut sequence_id = None;
    let mut count = 0;
    for attribute in start.attributes().with_checks(true) {
        count += 1;
        if count > MAX_WS_DISCOVERY_VALUES {
            return Err(WsDiscoveryError::TooManyValues);
        }
        let attribute = attribute.map_err(|_| WsDiscoveryError::MalformedXml)?;
        let local = attribute.key.local_name();
        let value = attribute
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|_| WsDiscoveryError::MalformedXml)?;
        if value.len() > MAX_WS_DISCOVERY_TEXT_BYTES {
            return Err(WsDiscoveryError::TextTooLarge);
        }
        match local.as_ref() {
            b"InstanceId" => {
                instance_id = Some(value.parse().map_err(|_| WsDiscoveryError::MissingHeader)?);
            }
            b"MessageNumber" => {
                message_number = Some(value.parse().map_err(|_| WsDiscoveryError::MissingHeader)?);
            }
            b"SequenceId" => sequence_id = Some(value.into_owned()),
            _ if !attribute.key.as_ref().starts_with(b"xmlns") => {
                return Err(WsDiscoveryError::UnsupportedXml);
            }
            _ => {}
        }
    }
    Ok(WsDiscoveryAppSequence {
        instance_id: instance_id.ok_or(WsDiscoveryError::MissingHeader)?,
        message_number: message_number.ok_or(WsDiscoveryError::MissingHeader)?,
        sequence_id,
    })
}

fn set_once(target: &mut Option<String>, value: &str) -> Result<(), WsDiscoveryError> {
    if target.is_some() {
        return Err(WsDiscoveryError::MissingHeader);
    }
    *target = Some(value.to_owned());
    Ok(())
}

fn append_words(target: &mut Vec<String>, value: &str) -> Result<(), WsDiscoveryError> {
    for word in value.split_ascii_whitespace() {
        if target.len() >= MAX_WS_DISCOVERY_VALUES || word.len() > MAX_WS_DISCOVERY_TEXT_BYTES {
            return Err(WsDiscoveryError::TooManyValues);
        }
        target.push(word.to_owned());
    }
    Ok(())
}

fn uuid_urn(value: [u8; 16]) -> String {
    format!(
        "urn:uuid:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
        value[6],
        value[7],
        value[8],
        value[9],
        value[10],
        value[11],
        value[12],
        value[13],
        value[14],
        value[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_probe_and_correlated_matches_are_strict() {
        let request = build_ws_discovery_probe([1; 16]).unwrap();
        let request_text = core::str::from_utf8(&request).unwrap();
        let request_id = request_text
            .split("<a:MessageID>")
            .nth(1)
            .unwrap()
            .split("</a:MessageID>")
            .next()
            .unwrap();
        let response = format!(
            "<s:Envelope xmlns:s=\"{soap}\" xmlns:a=\"{addressing}\" xmlns:d=\"{discovery}\"><s:Header><a:Action>{action}</a:Action><a:MessageID>urn:uuid:response</a:MessageID><a:RelatesTo>{request_id}</a:RelatesTo><a:To>{to}</a:To><d:AppSequence InstanceId=\"1\" MessageNumber=\"2\"/></s:Header><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:device</a:Address></a:EndpointReference><d:Types>dn:Device</d:Types><d:Scopes>onvif://scope</d:Scopes><d:XAddrs>http://192.0.2.1/device</d:XAddrs><d:MetadataVersion>1</d:MetadataVersion></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>",
            soap = core::str::from_utf8(SOAP_NAMESPACE).unwrap(),
            addressing = core::str::from_utf8(ADDRESSING_NAMESPACE).unwrap(),
            discovery = core::str::from_utf8(DISCOVERY_NAMESPACE).unwrap(),
            action = PROBE_MATCHES_ACTION,
            to = ANONYMOUS_TO,
        );
        let parsed = parse_ws_discovery_probe_matches(response.as_bytes(), request_id).unwrap();
        assert_eq!(parsed.matches[0].endpoint_address, "urn:uuid:device");
        assert_eq!(parsed.matches[0].metadata_version, 1);
        assert_eq!(
            parse_ws_discovery_probe_matches(response.as_bytes(), "urn:uuid:wrong"),
            Err(WsDiscoveryError::UnrelatedResponse)
        );
    }

    #[test]
    fn hostile_xml_and_llmnr_relationships_fail_closed() {
        assert_eq!(
            parse_ws_discovery_probe_matches(
                b"<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///etc/passwd'>]><x>&y;</x>",
                "x"
            ),
            Err(WsDiscoveryError::UnsupportedXml)
        );
        let query = build_llmnr_query(9, "host.", 1).unwrap();
        assert!(parse_llmnr_response(&query, 9).is_err());
        for length in 0..query.len() {
            let _ = parse_llmnr_response(&query[..length], 9);
        }
    }
}
