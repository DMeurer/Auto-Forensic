//! The starter neutral concepts (piece F8): system, user key and network interface.
//!
//! Native records stay what they are; these are small shared handles so plugins for different
//! operating systems can point at the same kind of thing. A new concept needs two OS
//! implementations before it joins this list. A field that exists on two systems never implies
//! the evidence behind it is equally strong.

use crate::ids::SystemId;
use crate::names::Kind;
use std::net::IpAddr;

/// A system, with its own ID. Detection, views and the OS profile come with pieces F9 and F10.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SystemRef {
    pub id: SystemId,
    /// A name for people, such as the computer name. Not unique.
    pub label: Option<String>,
}

/// A user, identified by its native ID on one system, such as a SID (`windows.sid`) or a numeric
/// user ID (`unix.uid`). The system is part of the key: the same SID or uid on two systems is two
/// users, unless an analyst links them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserKey {
    pub system: SystemId,
    pub scheme: Kind,
    pub value: String,
}

/// One observation of a network interface on a system, as read from one source. Several sources
/// can observe the same interface; they share `system` and `interface`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetInterfaceObservation {
    pub system: SystemId,
    /// The native identity of the interface, such as an adapter GUID or an interface name.
    pub interface: String,
    pub mac: Option<[u8; 6]>,
    pub name: Option<String>,
    pub addresses: Vec<IpAddr>,
}

impl NetInterfaceObservation {
    /// Whether two observations are of the same interface on the same system.
    pub fn same_interface(&self, other: &Self) -> bool {
        self.system == other.system && self.interface == other.interface
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_keys_from_two_systems_stay_unequal() {
        let (a, b) = (SystemId::new_random(), SystemId::new_random());
        let sid = |system| UserKey {
            system,
            scheme: Kind::new("windows.sid").unwrap(),
            value: "S-1-5-21-1004336348-1177238915-682003330-1001".into(),
        };
        assert_ne!(sid(a), sid(b));
        assert_eq!(sid(a), sid(a));
        let uid = |system| UserKey {
            system,
            scheme: Kind::new("unix.uid").unwrap(),
            value: "1000".into(),
        };
        assert_ne!(uid(a), uid(b));
        // Same system, same value, other scheme: not the same user either.
        let other = UserKey {
            scheme: Kind::new("unix.gid").unwrap(),
            ..uid(a)
        };
        assert_ne!(uid(a), other);
    }

    #[test]
    fn interface_observations() {
        let s = SystemId::new_random();
        let seen = |addr: &str| NetInterfaceObservation {
            system: s,
            interface: "{4D36E972-E325-11CE-BFC1-08002BE10318}".into(),
            mac: Some([0x00, 0x0c, 0x29, 0x12, 0x34, 0x56]),
            name: Some("Ethernet0".into()),
            addresses: vec![addr.parse().unwrap()],
        };
        let (dhcp, later) = (seen("192.168.2.10"), seen("192.168.2.57"));
        assert!(dhcp.same_interface(&later));
        assert_ne!(dhcp, later);
        let elsewhere = NetInterfaceObservation {
            system: SystemId::new_random(),
            ..dhcp.clone()
        };
        assert!(!dhcp.same_interface(&elsewhere));
    }
}
