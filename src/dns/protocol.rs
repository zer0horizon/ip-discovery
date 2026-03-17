//! Minimal DNS protocol implementation
//!
//! This module implements just enough of the DNS protocol to query
//! A, AAAA, and TXT records from specific nameservers.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DNS record types supported by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    /// A record — IPv4 address (RFC 1035)
    A = 1,
    /// AAAA record — IPv6 address (RFC 3596)
    Aaaa = 28,
    /// TXT record — arbitrary text (RFC 1035)
    Txt = 16,
}

/// DNS class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum DnsClass {
    /// Internet (default)
    #[default]
    In = 1,
    /// CSNET (Computer Science Network)
    Cs = 2,
    /// Chaos (used by Cloudflare whoami)
    Ch = 3,
    /// Hesiod
    Hs = 4,
}

/// Error returned when building a DNS query packet.
#[derive(Debug)]
pub enum DnsQueryError {
    /// A single DNS label exceeds the 63-byte limit.
    LabelTooLong(usize),
    /// An empty label was found (e.g. `"example..com"`).
    EmptyLabel,
    /// The total encoded domain name exceeds the 253-byte limit.
    DomainTooLong(usize),
}

impl fmt::Display for DnsQueryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::LabelTooLong(len) => write!(f, "Label too long: {} bytes (max 63)", len),
            Self::EmptyLabel => write!(f, "Empty label in domain name"),
            Self::DomainTooLong(len) => write!(f, "Domain too long: {} bytes (max 253)", len),
        }
    }
}

impl Error for DnsQueryError {}

/// Build a DNS query packet for the given domain, record type, and class.
///
/// Returns the raw bytes of a standard DNS query with recursion desired.
/// The transaction ID is randomly generated.
pub fn build_query(
    domain: &str,
    record_type: RecordType,
    class: DnsClass,
) -> Result<Vec<u8>, DnsQueryError> {
    let mut packet = Vec::with_capacity(512);

    // Transaction ID (random, best-effort)
    let mut id_bytes = [0u8; 2];
    let _ = getrandom::getrandom(&mut id_bytes);
    packet.extend_from_slice(&id_bytes);

    // Flags: standard query, recursion desired
    packet.extend_from_slice(&[0x01, 0x00]);

    // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode domain name with validation
    let domain = domain.trim_end_matches('.');
    let mut total_len = 0;

    for label in domain.split('.') {
        if label.is_empty() {
            return Err(DnsQueryError::EmptyLabel);
        }

        let len = label.len();
        if len > 63 {
            return Err(DnsQueryError::LabelTooLong(len));
        }

        total_len += len + 1; // +1 for length byte

        packet.push(len as u8);
        packet.extend_from_slice(label.as_bytes());
    }

    total_len += 1; // +1 for null terminator
    if total_len > 253 {
        return Err(DnsQueryError::DomainTooLong(total_len));
    }

    packet.push(0x00); // Null terminator

    // QTYPE and QCLASS
    packet.extend_from_slice(&(record_type as u16).to_be_bytes());
    packet.extend_from_slice(&(class as u16).to_be_bytes());

    Ok(packet)
}

/// Parse DNS response and extract IP addresses or TXT records
pub fn parse_response(data: &[u8], record_type: RecordType) -> Result<Vec<String>, &'static str> {
    if data.len() < 12 {
        return Err("response too short");
    }

    // Check response code (RCODE in byte 3, lower 4 bits)
    let rcode = data[3] & 0x0F;
    if rcode != 0 {
        return Err("DNS error response");
    }

    // Get answer count
    let ancount = u16::from_be_bytes([data[4], data[5]]);
    if ancount == 0 {
        return Err("no answers in response");
    }

    // Skip header (12 bytes) and question section
    let mut pos = 12;

    // Skip question section (find the null terminator, then skip QTYPE and QCLASS)
    while pos < data.len() && data[pos] != 0 {
        let label_len = data[pos] as usize;
        pos += 1 + label_len;
        if pos > data.len() {
            return Err("malformed question section");
        }
    }
    if pos >= data.len() {
        return Err("truncated question section");
    }
    pos += 1 + 4; // Skip null terminator + QTYPE (2) + QCLASS (2)

    let mut results = Vec::new();

    // Parse answer records
    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }

        // Skip name (may be compressed with pointer)
        pos = skip_name(data, pos)?;

        if pos + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            break;
        }

        // Only process records of the type we asked for
        if rtype == record_type as u16 {
            match record_type {
                RecordType::A if rdlength == 4 => {
                    let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
                    results.push(IpAddr::V4(ip).to_string());
                }
                RecordType::Aaaa if rdlength == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[pos..pos + 16]);
                    let ip = Ipv6Addr::from(octets);
                    results.push(IpAddr::V6(ip).to_string());
                }
                RecordType::Txt => {
                    // TXT records have length-prefixed strings
                    let mut txt_pos = pos;
                    let end = pos + rdlength;
                    let mut txt = String::new();
                    while txt_pos < end {
                        let len = data[txt_pos] as usize;
                        txt_pos += 1;
                        if txt_pos + len <= end {
                            if let Ok(s) = std::str::from_utf8(&data[txt_pos..txt_pos + len]) {
                                txt.push_str(s);
                            }
                            txt_pos += len;
                        }
                    }
                    if !txt.is_empty() {
                        results.push(txt);
                    }
                }
                _ => {}
            }
        }

        pos += rdlength;
    }

    if results.is_empty() {
        Err("no matching records found")
    } else {
        Ok(results)
    }
}

/// Skip a DNS name (handles compression pointers)
fn skip_name(data: &[u8], mut pos: usize) -> Result<usize, &'static str> {
    if pos >= data.len() {
        return Err("invalid name position");
    }

    loop {
        if pos >= data.len() {
            return Err("unexpected end of name");
        }

        let len = data[pos];

        // Check for compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }

        if len == 0 {
            return Ok(pos + 1);
        }

        pos += 1 + len as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query_a_record() {
        let query = build_query("example.com", RecordType::A, DnsClass::In).unwrap();
        assert!(query.len() > 12);
        // Check question count = 1
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);
        // Check answer/ns/ar counts = 0
        assert_eq!(query[6], 0x00);
        assert_eq!(query[7], 0x00);
    }

    #[test]
    fn test_build_query_txt_record() {
        let query = build_query("whoami.cloudflare", RecordType::Txt, DnsClass::Ch).unwrap();
        assert!(query.len() > 12);
        // QCLASS should be CH (3)
        let len = query.len();
        let qclass = u16::from_be_bytes([query[len - 2], query[len - 1]]);
        assert_eq!(qclass, 3);
    }

    #[test]
    fn test_build_query_domain_encoding() {
        let query = build_query("a.b.c", RecordType::A, DnsClass::In).unwrap();
        // After 12-byte header: 1 'a' 1 'b' 1 'c' 0
        assert_eq!(query[12], 1); // label length
        assert_eq!(query[13], b'a');
        assert_eq!(query[14], 1);
        assert_eq!(query[15], b'b');
        assert_eq!(query[16], 1);
        assert_eq!(query[17], b'c');
        assert_eq!(query[18], 0); // null terminator
    }

    #[test]
    fn test_build_query_trailing_dot() {
        // Trailing dot should be stripped
        let q1 = build_query("example.com.", RecordType::A, DnsClass::In).unwrap();
        let q2 = build_query("example.com", RecordType::A, DnsClass::In).unwrap();
        // Same domain encoding (skip first 2 bytes which are random TX ID)
        assert_eq!(q1[2..], q2[2..]);
    }

    #[test]
    fn test_build_query_empty_label() {
        let result = build_query("example..com", RecordType::A, DnsClass::In);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_query_label_too_long() {
        let long_label = "a".repeat(64);
        let domain = format!("{}.com", long_label);
        let result = build_query(&domain, RecordType::A, DnsClass::In);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_a_response() {
        // Construct a minimal DNS response with A record 1.2.3.4
        let response = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: response, no error
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question: example.com A IN
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // null terminator
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Answer: compressed name pointer
            0xC0, 0x0C, // pointer to offset 12
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x01, 0x00, // TTL
            0x00, 0x04, // RDLENGTH = 4
            1, 2, 3, 4, // RDATA = 1.2.3.4
        ];

        let results = parse_response(&response, RecordType::A).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "1.2.3.4");
    }

    #[test]
    fn test_parse_response_too_short() {
        let short = [0u8; 5];
        assert!(parse_response(&short, RecordType::A).is_err());
    }

    #[test]
    fn test_parse_response_error_rcode() {
        let mut response = [0u8; 12];
        response[3] = 0x03; // NXDOMAIN
        assert!(parse_response(&response, RecordType::A).is_err());
    }

    #[test]
    fn test_parse_response_no_answers() {
        let response = [
            0x00, 0x01, // TX ID
            0x81, 0x80, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse_response(&response, RecordType::A).is_err());
    }

    #[test]
    fn test_skip_name_compression_pointer() {
        let data = [0xC0, 0x0C, 0x00]; // compression pointer
        let pos = skip_name(&data, 0).unwrap();
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_skip_name_regular() {
        let data = [
            0x03, b'c', b'o', b'm', // "com"
            0x00, // null terminator
        ];
        let pos = skip_name(&data, 0).unwrap();
        assert_eq!(pos, 5);
    }
}
