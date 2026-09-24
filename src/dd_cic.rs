//! 64DD-specific CIC (boot/security chip) identification.
//!
//! Values sourced from LuigiBlood's 64dd wiki "CIC" page
//! (https://github.com/LuigiBlood/64dd/wiki/CIC), which lists the CIC chips
//! used by the 64DD's own IPL firmware (as opposed to per-cartridge CICs,
//! already handled in `checksum.rs`).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdCic {
    /// NDDJ 00 - early Japanese IPL cart revision.
    #[allow(dead_code)]
    Cic8301,
    /// NDDJ 01 - early Japanese IPL cart revision.
    #[allow(dead_code)]
    Cic8302,
    /// NDDJ 02 - Japanese retail IPL.
    Cic8303,
    /// NDXJ 00 - Japanese development IPL.
    Cic8401,
    /// NDDE 00 - USA retail IPL.
    Cic8501,
    Unknown,
}

impl DdCic {
    pub fn label(&self) -> &'static str {
        match self {
            DdCic::Cic8301 => "CIC-8301 (64DD IPL, JPN cart, early)",
            DdCic::Cic8302 => "CIC-8302 (64DD IPL, JPN cart, early)",
            DdCic::Cic8303 => "CIC-8303 (64DD IPL, JPN retail)",
            DdCic::Cic8401 => "CIC-8401 (64DD IPL, JPN development)",
            DdCic::Cic8501 => "CIC-8501 (64DD IPL, USA retail)",
            DdCic::Unknown => "Unknown / unidentified 64DD CIC",
        }
    }

    /// Checksum seed byte used by the 64DD's IPL, where known.
    #[allow(dead_code)]
    pub fn seed(&self) -> Option<u8> {
        match self {
            DdCic::Cic8301 | DdCic::Cic8302 | DdCic::Cic8303 | DdCic::Cic8401 => Some(0xDD),
            DdCic::Cic8501 => Some(0xDE),
            DdCic::Unknown => None,
        }
    }
}

/// Best-effort identification of the 64DD IPL CIC based on the disk's region
/// and retail/development flag (read from the System Data area). The 64DD
/// disk itself does not carry its own CIC (that lives in the 64DD unit's
/// IPL cart), so this reports which IPL a disk of this region/type would
/// have been verified against.
pub fn identify_dd_cic(region: u32, retail: bool) -> DdCic {
    use crate::dd_geometry::{REGION_JAPAN, REGION_USA};
    match (region, retail) {
        (REGION_JAPAN, true) => DdCic::Cic8303,
        (REGION_JAPAN, false) => DdCic::Cic8401,
        (REGION_USA, _) => DdCic::Cic8501,
        _ => DdCic::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dd_geometry::{REGION_JAPAN, REGION_USA};

    #[test]
    fn identifies_known_regions() {
        assert_eq!(identify_dd_cic(REGION_JAPAN, true), DdCic::Cic8303);
        assert_eq!(identify_dd_cic(REGION_JAPAN, false), DdCic::Cic8401);
        assert_eq!(identify_dd_cic(REGION_USA, true), DdCic::Cic8501);
    }

    #[test]
    fn seeds_present_for_known_cics() {
        assert_eq!(DdCic::Cic8303.seed(), Some(0xDD));
        assert_eq!(DdCic::Cic8501.seed(), Some(0xDE));
        assert_eq!(DdCic::Unknown.seed(), None);
    }
}
