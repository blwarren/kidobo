pub(crate) mod blocklist;
pub mod config;
pub mod lookup;
pub mod network;
pub mod sync;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}
