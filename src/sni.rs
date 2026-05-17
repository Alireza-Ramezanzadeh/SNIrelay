// sni.rs — Zero-copy TLS ClientHello SNI extraction

/// Result of a peek at the first bytes of a TCP stream.
#[derive(Debug, Clone, PartialEq)]
pub enum PeekResult {
    /// TLS ClientHello with SNI hostname
    Tls(String),
    /// TLS ClientHello without SNI (IP-literal or very old clients)
    TlsNoSni,
    /// Plain HTTP — caller should read the Host header instead
    PlainHttp,
    /// Not enough data yet — need more bytes
    NeedMore,
    /// Definitely not TLS or HTTP
    Unknown,
}

/// Parse TLS SNI from the first bytes of a TCP connection.
/// Skips leading TLS middlebox compatibility records (e.g. legacy CCS) before ClientHello.
pub fn parse_sni(buf: &[u8]) -> PeekResult {
    parse_sni_with_replay(buf).0
}

/// Like [`parse_sni`], but also returns how many leading bytes form the ClientHello
/// flight (leading CCS + ClientHello record). Only those bytes may be replayed first;
/// any further bytes in the buffer must be sent separately (not appended to CH).
pub fn parse_sni_with_replay(buf: &[u8]) -> (PeekResult, usize) {
    if buf.len() < 5 {
        return (PeekResult::NeedMore, 0);
    }

    let prefix = &buf[..std::cmp::min(8, buf.len())];
    if is_plain_http(prefix) {
        return (PeekResult::PlainHttp, 0);
    }

    let mut offset = 0;
    while offset + 5 <= buf.len() {
        let record_type = buf[offset];
        if record_type != 0x14 && record_type != 0x16 {
            return (PeekResult::Unknown, 0);
        }

        let record_len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        let record_end = offset.saturating_add(5).saturating_add(record_len);

        if record_end > buf.len() {
            return (PeekResult::NeedMore, 0);
        }

        match record_type {
            0x16 => {
                let result = parse_tls_handshake_record(&buf[offset..record_end]);
                return (result, record_end);
            }
            0x14 => {
                offset = record_end;
                continue;
            }
            _ => return (PeekResult::Unknown, 0),
        }
    }

    (PeekResult::NeedMore, 0)
}

fn parse_tls_handshake_record(record: &[u8]) -> PeekResult {
    if record.len() < 5 || record[0] != 0x16 {
        return PeekResult::Unknown;
    }
    if record[1] != 0x03 || record[2] > 0x04 {
        return PeekResult::Unknown;
    }
    let handshake = &record[5..];
    parse_client_hello(handshake)
}

fn parse_client_hello(data: &[u8]) -> PeekResult {
    let mut pos = 0;

    // Handshake type: 0x01 = ClientHello
    if pos >= data.len() || data[pos] != 0x01 {
        return PeekResult::TlsNoSni;
    }
    pos += 1;

    // Handshake length (3 bytes)
    if pos + 3 > data.len() { return PeekResult::TlsNoSni; }
    let _hs_len = u24_be(&data[pos..pos + 3]);
    pos += 3;

    // Client version (2 bytes)
    if pos + 2 > data.len() { return PeekResult::TlsNoSni; }
    pos += 2;

    // Random (32 bytes)
    if pos + 32 > data.len() { return PeekResult::TlsNoSni; }
    pos += 32;

    // Session ID length (1 byte) + session ID
    if pos >= data.len() { return PeekResult::TlsNoSni; }
    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;

    // Cipher suites length (2 bytes) + cipher suites
    if pos + 2 > data.len() { return PeekResult::TlsNoSni; }
    let cs_len = u16_be(&data[pos..pos + 2]) as usize;
    pos += 2 + cs_len;

    // Compression methods length (1 byte) + compression methods
    if pos >= data.len() { return PeekResult::TlsNoSni; }
    let cm_len = data[pos] as usize;
    pos += 1 + cm_len;

    // Extensions length (2 bytes)
    if pos + 2 > data.len() { return PeekResult::TlsNoSni; }
    let ext_total = u16_be(&data[pos..pos + 2]) as usize;
    pos += 2;

    let ext_end = pos + ext_total;
    if ext_end > data.len() { return PeekResult::TlsNoSni; }

    // Walk extensions
    while pos + 4 <= ext_end {
        let ext_type = u16_be(&data[pos..pos + 2]);
        let ext_len  = u16_be(&data[pos + 2..pos + 4]) as usize;
        pos += 4;

        if pos + ext_len > ext_end { break; }

        // Extension type 0x0000 = server_name
        if ext_type == 0x0000 {
            if let Some(name) = parse_sni_extension(&data[pos..pos + ext_len]) {
                return PeekResult::Tls(name);
            }
            return PeekResult::TlsNoSni;
        }

        pos += ext_len;
    }

    PeekResult::TlsNoSni
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // server_name_list length (2 bytes)
    if data.len() < 2 { return None; }
    let list_len = u16_be(&data[0..2]) as usize;
    if data.len() < 2 + list_len { return None; }

    let mut pos = 2;
    let list_end = 2 + list_len;

    while pos + 3 <= list_end {
        let name_type = data[pos];
        let name_len  = u16_be(&data[pos + 1..pos + 3]) as usize;
        pos += 3;

        if pos + name_len > list_end { break; }

        // NameType 0 = host_name
        if name_type == 0 {
            return std::str::from_utf8(&data[pos..pos + name_len])
                .ok()
                .map(|s| s.to_lowercase());
        }

        pos += name_len;
    }

    None
}

fn is_plain_http(prefix: &[u8]) -> bool {
    const HTTP_METHODS: &[&[u8]] = &[
        b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC", b"CONN",
    ];
    for m in HTTP_METHODS {
        if prefix.starts_with(m) {
            return true;
        }
    }
    false
}

#[inline]
fn u16_be(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[inline]
fn u24_be(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_http() {
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\n"), PeekResult::PlainHttp);
        assert_eq!(parse_sni(b"CONNECT example.com:443 HTTP/1.1\r\n"), PeekResult::PlainHttp);
    }

    #[test]
    fn test_need_more() {
        assert_eq!(parse_sni(b"\x16\x03"), PeekResult::NeedMore);
    }

    #[test]
    fn test_not_tls() {
        assert_eq!(parse_sni(b"SSH-2.0-OpenSSH_8.9"), PeekResult::Unknown);
    }
}
