use std::net::{Ipv4Addr, Ipv6Addr};

use crate::AddressFamily;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanonicalCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl CanonicalCidr {
    #[must_use]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Cidr {
    pub(crate) network: u32,
    pub(crate) prefix: u8,
}

impl Ipv4Cidr {
    #[must_use]
    pub fn new(address: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix > 32 {
            return None;
        }
        Some(Self::from_parts(u32::from(address), prefix))
    }

    #[doc(hidden)]
    #[must_use]
    pub fn from_parts(network: u32, prefix: u8) -> Self {
        debug_assert!(prefix <= 32);
        Self {
            network: network & ipv4_mask(prefix),
            prefix,
        }
    }

    #[must_use]
    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    #[must_use]
    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.network(), self.prefix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv6Cidr {
    pub(crate) network: u128,
    pub(crate) prefix: u8,
}

impl Ipv6Cidr {
    #[must_use]
    pub fn new(address: Ipv6Addr, prefix: u8) -> Option<Self> {
        if prefix > 128 {
            return None;
        }
        Some(Self::from_parts(u128::from(address), prefix))
    }

    #[doc(hidden)]
    #[must_use]
    pub fn from_parts(network: u128, prefix: u8) -> Self {
        debug_assert!(prefix <= 128);
        Self {
            network: network & ipv6_mask(prefix),
            prefix,
        }
    }

    #[must_use]
    pub fn network(self) -> Ipv6Addr {
        Ipv6Addr::from(self.network)
    }

    #[must_use]
    pub fn prefix(self) -> u8 {
        self.prefix
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.network(), self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FamilyCidrs {
    pub ipv4: Vec<Ipv4Cidr>,
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
