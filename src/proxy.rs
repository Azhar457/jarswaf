use once_cell::sync::Lazy;

static GEOIP_READER: Lazy<Option<maxminddb::Reader<Vec<u8>>>> =
    Lazy::new(|| maxminddb::Reader::open_readfile("GeoLite2-Country.mmdb").ok());

pub fn resolve_ip_country(ip: &std::net::IpAddr) -> String {
    if crate::types::is_local_ip(ip) {
        return "LOCAL".to_string();
    }

    if let Some(reader) = GEOIP_READER.as_ref() {
        if let Ok(lookup_res) = reader.lookup(*ip) {
            if let Ok(Some(record)) = lookup_res.decode::<maxminddb::geoip2::Country>() {
                if let Some(iso_code) = record.country.iso_code {
                    return iso_code.to_string();
                }
            }
        }
    }

    "XX".to_string()
}

pub fn match_ip(client_ip: &std::net::IpAddr, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern == "*" {
        return true;
    }
    if pattern.contains('/') {
        let parts: Vec<&str> = pattern.split('/').collect();
        if parts.len() == 2 {
            if let (Ok(subnet_ip), Ok(prefix_len)) =
                (parts[0].parse::<std::net::IpAddr>(), parts[1].parse::<u8>())
            {
                match (client_ip, subnet_ip) {
                    (std::net::IpAddr::V4(c_ip), std::net::IpAddr::V4(s_ip))
                        if prefix_len <= 32 =>
                    {
                        let mask = if prefix_len == 0 {
                            0u32
                        } else {
                            !0u32 << (32 - prefix_len)
                        };
                        let c_u32 = u32::from(*c_ip);
                        let s_u32 = u32::from(s_ip);
                        return (c_u32 & mask) == (s_u32 & mask);
                    }
                    (std::net::IpAddr::V6(c_ip), std::net::IpAddr::V6(s_ip))
                        if prefix_len <= 128 =>
                    {
                        let c_oct = c_ip.octets();
                        let s_oct = s_ip.octets();
                        let bytes_to_check = (prefix_len / 8) as usize;
                        if c_oct[0..bytes_to_check] == s_oct[0..bytes_to_check] {
                            let rem_bits = prefix_len % 8;
                            if rem_bits == 0 {
                                return true;
                            }
                            let mask = 0xffu8 << (8 - rem_bits);
                            return (c_oct[bytes_to_check] & mask)
                                == (s_oct[bytes_to_check] & mask);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if let Ok(ip) = pattern.parse::<std::net::IpAddr>() {
        return &ip == client_ip;
    }
    false
}

pub fn match_path(path: &str, pattern: &str) -> bool {
    let path = path.trim().to_lowercase();
    let pattern = pattern.trim().to_lowercase();
    if pattern == "*" {
        return true;
    }
    if pattern.ends_with('*') {
        let prefix = pattern.trim_end_matches('*');
        path.starts_with(prefix)
    } else if pattern.starts_with('*') {
        let suffix = pattern.trim_start_matches('*');
        path.ends_with(suffix)
    } else {
        path == pattern
    }
}
