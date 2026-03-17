//! STUN message encoding/decoding
//!
//! Implements minimal RFC 5389 STUN message format for binding requests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// STUN magic cookie (RFC 5389)
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message types (RFC 5389)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMethod {
    /// Binding request
    Request,
    /// Binding success response
    Response,
    /// Binding error response
    Error,
}

impl StunMethod {
    fn to_u16(self) -> u16 {
        match self {
            StunMethod::Request => 0x0001,
            StunMethod::Response => 0x0101,
            StunMethod::Error => 0x0111,
        }
    }

    fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(StunMethod::Request),
            0x0101 => Some(StunMethod::Response),
            0x0111 => Some(StunMethod::Error),
            _ => None,
        }
    }
}

/// STUN attribute types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttributeType {
    MappedAddress,
    XorMappedAddress,
    Unknown(u16),
}

impl AttributeType {
    fn from_u16(value: u16) -> Self {
        match value {
            0x0001 => AttributeType::MappedAddress,
            0x0020 => AttributeType::XorMappedAddress,
            other => AttributeType::Unknown(other),
        }
    }
}

/// A STUN protocol message (RFC 5389).
///
/// Supports encoding binding requests and decoding binding responses
/// to extract the mapped (public) IP address.
#[derive(Debug)]
pub struct StunMessage {
    msg_type: StunMethod,
    transaction_id: [u8; 12],
    attributes: Vec<(AttributeType, Vec<u8>)>,
}

impl StunMessage {
    /// Create a new STUN message
    pub fn new(msg_type: StunMethod) -> Self {
        let mut transaction_id = [0u8; 12];
        // Best-effort randomness; a zeroed ID still produces a valid STUN message
        let _ = getrandom::getrandom(&mut transaction_id);

        Self {
            msg_type,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Get transaction ID
    pub fn transaction_id(&self) -> &[u8; 12] {
        &self.transaction_id
    }

    /// Encode this message to its wire format (20 bytes for a binding request).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);

        // Message type (2 bytes)
        buf.extend_from_slice(&self.msg_type.to_u16().to_be_bytes());

        // Message length (2 bytes) - 0 for binding request with no attributes
        buf.extend_from_slice(&0u16.to_be_bytes());

        // Magic cookie (4 bytes)
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (12 bytes)
        buf.extend_from_slice(&self.transaction_id);

        buf
    }

    /// Decode a STUN message from its wire format.
    ///
    /// Returns an error if the data is too short, has an invalid magic cookie,
    /// or contains an unrecognized message type.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 20 {
            return Err("message too short");
        }

        // Parse header
        let msg_type_raw = u16::from_be_bytes([data[0], data[1]]);
        let msg_type = StunMethod::from_u16(msg_type_raw).ok_or("unknown message type")?;

        let msg_length = u16::from_be_bytes([data[2], data[3]]) as usize;

        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic != MAGIC_COOKIE {
            return Err("invalid magic cookie");
        }

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = 20;
        let end = 20 + msg_length;

        while offset + 4 <= end && offset + 4 <= data.len() {
            let attr_type_raw = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

            offset += 4;

            if offset + attr_len > data.len() {
                break;
            }

            let attr_type = AttributeType::from_u16(attr_type_raw);
            let attr_value = data[offset..offset + attr_len].to_vec();
            attributes.push((attr_type, attr_value));

            // Padding to 4-byte boundary
            offset += attr_len;
            if attr_len % 4 != 0 {
                offset += 4 - (attr_len % 4);
            }
        }

        Ok(Self {
            msg_type,
            transaction_id,
            attributes,
        })
    }

    /// Extract the mapped (public) IP address from the response.
    ///
    /// Prefers XOR-MAPPED-ADDRESS over MAPPED-ADDRESS per RFC 5389 recommendation.
    pub fn get_mapped_address(&self) -> Option<IpAddr> {
        // Try XOR-MAPPED-ADDRESS first (preferred)
        for (attr_type, value) in &self.attributes {
            if *attr_type == AttributeType::XorMappedAddress {
                return self.parse_xor_mapped_address(value);
            }
        }

        // Fall back to MAPPED-ADDRESS
        for (attr_type, value) in &self.attributes {
            if *attr_type == AttributeType::MappedAddress {
                return self.parse_mapped_address(value);
            }
        }

        None
    }

    fn parse_mapped_address(&self, data: &[u8]) -> Option<IpAddr> {
        if data.len() < 4 {
            return None;
        }

        let family = data[1];

        match family {
            0x01 => {
                // IPv4
                if data.len() < 8 {
                    return None;
                }
                let addr = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                Some(IpAddr::V4(addr))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }

    fn parse_xor_mapped_address(&self, data: &[u8]) -> Option<IpAddr> {
        if data.len() < 4 {
            return None;
        }

        let family = data[1];

        match family {
            0x01 => {
                // IPv4 - XOR with magic cookie
                if data.len() < 8 {
                    return None;
                }
                let xor_addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let addr = xor_addr ^ MAGIC_COOKIE;
                Some(IpAddr::V4(Ipv4Addr::from(addr)))
            }
            0x02 => {
                // IPv6 - XOR with magic cookie + transaction ID
                if data.len() < 20 {
                    return None;
                }

                let mut xor_key = [0u8; 16];
                xor_key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                xor_key[4..16].copy_from_slice(&self.transaction_id);

                let mut octets = [0u8; 16];
                for i in 0..16 {
                    octets[i] = data[4 + i] ^ xor_key[i];
                }

                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_binding_request() {
        let msg = StunMessage::new(StunMethod::Request);
        let encoded = msg.encode();

        assert_eq!(encoded.len(), 20);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x01); // Binding Request
        assert_eq!(encoded[2], 0x00);
        assert_eq!(encoded[3], 0x00); // Length = 0
        assert_eq!(encoded[4], 0x21);
        assert_eq!(encoded[5], 0x12);
        assert_eq!(encoded[6], 0xA4);
        assert_eq!(encoded[7], 0x42); // Magic Cookie
    }

    #[test]
    fn test_decode_binding_response() {
        // Minimal binding response with XOR-MAPPED-ADDRESS
        let response = [
            0x01,
            0x01, // Binding Response
            0x00,
            0x0C, // Length = 12
            0x21,
            0x12,
            0xA4,
            0x42, // Magic Cookie
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B, // Transaction ID
            // XOR-MAPPED-ADDRESS attribute
            0x00,
            0x20, // Type
            0x00,
            0x08, // Length
            0x00,
            0x01, // Family (IPv4)
            0x21,
            0x12, // XOR'd Port
            0x21 ^ 192,
            0x12 ^ 168,
            0xA4 ^ 1,
            0x42 ^ 100, // XOR'd Address (192.168.1.100)
        ];

        let msg = StunMessage::decode(&response).unwrap();
        let addr = msg.get_mapped_address().unwrap();

        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    }
}
