//! Canonical, family-aware CIDR value types.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::AddressFamily;

/// Canonical IPv4 or IPv6 network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanonicalCidr {
    /// Canonical IPv4 network.
    V4(Ipv4Cidr),
    /// Canonical IPv6 network.
    V6(Ipv6Cidr),
}

impl CanonicalCidr {
    #[must_use]
    /// Returns the CIDR's address family.
    pub fn family(self) -> AddressFamily {
        match self {
            Self::V4(_) => AddressFamily::Ipv4,
            Self::V6(_) => AddressFamily::Ipv6,
        }
    }
}

impl std::fmt::Display for CanonicalCidr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(cidr) => write!(formatter, "{cidr}"),
            Self::V6(cidr) => write!(formatter, "{cidr}"),
        }
    }
}

/// Canonical IPv4 network and prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Cidr {
    pub(crate) network: u32,
    pub(crate) prefix: u8,
}

impl Ipv4Cidr {
    #[must_use]
    /// Constructs a canonical network from an address and prefix.
    ///
    /// Returns `None` when `prefix` exceeds 32. Host bits are cleared.
    pub fn new(address: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix > 32 {
            return None;
        }
        Some(Self::from_parts(u32::from(address), prefix))
    }

    #[must_use]
    pub(crate) fn from_parts(network: u32, prefix: u8) -> Self {
        debug_assert!(prefix <= 32);
        Self {
            network: network & ipv4_mask(prefix),
            prefix,
        }
    }

    #[must_use]
    /// Returns the canonical network address.
    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    #[must_use]
    /// Returns the prefix length in the inclusive range 0 through 32.
    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.network(), self.prefix)
    }
}

/// Canonical IPv6 network and prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv6Cidr {
    pub(crate) network: u128,
    pub(crate) prefix: u8,
}

impl Ipv6Cidr {
    #[must_use]
    /// Constructs a canonical network from an address and prefix.
    ///
    /// Returns `None` when `prefix` exceeds 128. Host bits are cleared.
    pub fn new(address: Ipv6Addr, prefix: u8) -> Option<Self> {
        if prefix > 128 {
            return None;
        }
        Some(Self::from_parts(u128::from(address), prefix))
    }

    #[must_use]
    pub(crate) fn from_parts(network: u128, prefix: u8) -> Self {
        debug_assert!(prefix <= 128);
        Self {
            network: network & ipv6_mask(prefix),
            prefix,
        }
    }

    #[must_use]
    /// Returns the canonical network address.
    pub fn network(self) -> Ipv6Addr {
        Ipv6Addr::from(self.network)
    }

    #[must_use]
    /// Returns the prefix length in the inclusive range 0 through 128.
    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.network(), self.prefix)
    }
}

/// CIDR vectors separated by address family.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FamilyCidrs {
    /// IPv4 CIDRs in their input or computed order.
    pub ipv4: Vec<Ipv4Cidr>,
    /// IPv6 CIDRs in their input or computed order.
    pub ipv6: Vec<Ipv6Cidr>,
}

pub(crate) fn ipv4_mask(prefix: u8) -> u32 {
    !ipv4_host_mask(prefix)
}

pub(crate) fn ipv6_mask(prefix: u8) -> u128 {
    !ipv6_host_mask(prefix)
}

pub(crate) fn ipv4_host_mask(prefix: u8) -> u32 {
    u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)
}

pub(crate) fn ipv6_host_mask(prefix: u8) -> u128 {
    u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)
}
