use super::{InspectionResult, Inspector};
use crate::data_bus::context::{BlockAction, BlockReason, InspectionContext};
use async_trait::async_trait;
use std::net::IpAddr;

/// GeoIP blocking inspector.
///
/// Uses maxminddb to look up country codes from IP addresses.
/// GeoIP database is optional — inspector is disabled if no database found.
#[derive(Default)]
pub struct GeoipInspector {
    blocked_countries: Vec<String>,
    blocklist_type: GeoBlockType,
}

#[derive(Debug, Clone, Default)]
pub enum GeoBlockType {
    #[default]
    Blocklist,
    Allowlist,
}

impl GeoipInspector {
    pub fn new() -> Self {
        Self {
            blocked_countries: Vec::new(),
            blocklist_type: GeoBlockType::Blocklist,
        }
    }

    pub fn with_blocked_countries(countries: Vec<String>, blocklist_type: GeoBlockType) -> Self {
        Self {
            blocked_countries: countries,
            blocklist_type,
        }
    }

    fn lookup_country(&self, _ip: &IpAddr) -> Option<String> {
        // GeoIP lookup via maxminddb.
        // The actual database loading is deferred — on systems without the DB file,
        // this returns None and the inspector gracefully skips.
        // Full integration when maxminddb crate is available:
        //
        //   static GEOIP_READER: Lazy<Option<Arc<Reader<Vec<u8>>>>> = ...;
        //   reader.lookup(*ip).ok().and_then(|r: geoip2::Country| ...)
        //
        // For now, placeholder returns None (no DB = inspector disabled).
        None
    }
}

#[async_trait]
impl Inspector for GeoipInspector {
    fn name(&self) -> &str {
        "GEOIP"
    }
    fn priority(&self) -> u32 {
        60
    }

    fn should_run(&self, _ctx: &InspectionContext) -> bool {
        // Skip if no blocked countries configured
        !self.blocked_countries.is_empty()
    }

    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult {
        if let Some(country) = self.lookup_country(&ctx.client_ip) {
            ctx.set_metadata("country_code", country.clone());

            let blocked = match self.blocklist_type {
                GeoBlockType::Blocklist => self.blocked_countries.contains(&country),
                GeoBlockType::Allowlist => !self.blocked_countries.contains(&country),
            };

            if blocked {
                return InspectionResult::block(
                    BlockReason::GeoBlock,
                    BlockAction::Reject403,
                    0.0,
                    format!("Country {} is blocked", country),
                );
            }
        }

        InspectionResult::clean()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_block_type_default() {
        let inspector = GeoipInspector::new();
        assert!(matches!(inspector.blocklist_type, GeoBlockType::Blocklist));
    }

    #[test]
    fn test_skips_when_no_countries() {
        let inspector = GeoipInspector::new();
        let ctx = InspectionContext::new(
            "10.0.0.1".parse().unwrap(),
            hyper::Method::GET,
            "/".to_string(),
            String::new(),
            hyper::HeaderMap::new(),
            None,
            "test.local".to_string(),
            12345,
        );
        assert!(!inspector.should_run(&ctx));
    }
}
