use crate::THIS_SIDECHAIN;

pub const DEFAULT_PORT: u16 = 4000 + THIS_SIDECHAIN as u16;

pub mod peer {
    use std::{
        borrow::ToOwned,
        fmt::Display,
        net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
        str::FromStr,
    };

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use strum::Display;
    use utoipa::ToSchema;

    use crate::schema;

    pub type ParseAddressError = crate::error::ParsePeerAddress;

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    pub struct Address<S = String> {
        pub host: url::Host<S>,
        pub port: u16,
    }

    impl<S> Address<S> {
        pub fn as_ref(&self) -> Address<&S> {
            let Self { host, port } = self;
            let host = match host {
                url::Host::Domain(domain) => url::Host::Domain(domain),
                url::Host::Ipv4(v4) => url::Host::Ipv4(*v4),
                url::Host::Ipv6(v6) => url::Host::Ipv6(*v6),
            };
            Address { host, port: *port }
        }

        pub fn map_domain<F, T>(self, f: F) -> Address<T>
        where
            F: FnOnce(S) -> T,
        {
            let Self { host, port } = self;
            let host = match host {
                url::Host::Domain(domain) => url::Host::Domain(f(domain)),
                url::Host::Ipv4(v4) => url::Host::Ipv4(v4),
                url::Host::Ipv6(v6) => url::Host::Ipv6(v6),
            };
            Address { host, port }
        }
    }

    impl<S> Address<&S>
    where
        S: ?Sized,
    {
        pub fn to_owned(&self) -> Address<<S as ToOwned>::Owned>
        where
            S: ToOwned,
        {
            self.as_ref()
                .map_domain(|domain| <S as ToOwned>::to_owned(domain))
        }
    }

    /// An IP host gets the same bytes as a `SocketAddr`, so the older
    /// `known_peers` keys stay readable.
    #[derive(Deserialize, Serialize)]
    enum AddressRepr<S> {
        V4(SocketAddrV4),
        V6(SocketAddrV6),
        Domain(S, u16),
    }

    impl<'de> Deserialize<'de> for Address {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let s: &'_ str = Deserialize::deserialize(deserializer)?;
                <Self as FromStr>::from_str(s).map_err(serde::de::Error::custom)
            } else {
                let address = match AddressRepr::deserialize(deserializer)? {
                    AddressRepr::V4(v4) => Self::from(v4),
                    AddressRepr::V6(v6) => Self::from(v6),
                    AddressRepr::Domain(domain, port) => Self {
                        host: url::Host::Domain(domain),
                        port,
                    },
                };
                Ok(address)
            }
        }
    }

    impl<S> Display for Address<S>
    where
        url::Host<S>: Display,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let Self { host, port } = self;
            write!(f, "{host}:{port}")
        }
    }

    impl<S, T> From<T> for Address<S>
    where
        SocketAddr: From<T>,
    {
        fn from(value: T) -> Self {
            match SocketAddr::from(value) {
                SocketAddr::V4(v4) => Self {
                    host: url::Host::Ipv4(*v4.ip()),
                    port: v4.port(),
                },
                SocketAddr::V6(v6) => Self {
                    host: url::Host::Ipv6(*v6.ip()),
                    port: v6.port(),
                },
            }
        }
    }

    /// Parses `host:port`. IPv6 literals must be bracketed, as in `[::1]:4002`, so
    /// their colons are not read as the port separator.
    impl FromStr for Address {
        type Err = ParseAddressError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let (host_str, port) = match s.rsplit_once(':') {
                Some((host_str, port)) => {
                    let port: u16 = port
                        .parse()
                        .map_err(|_| url::ParseError::InvalidPort)?;
                    (host_str, port)
                }
                None => (s, crate::net::DEFAULT_PORT),
            };
            let host = url::Host::parse(host_str)?;
            Ok(Self { host, port })
        }
    }

    impl<T> Serialize for Address<T>
    where
        T: Serialize,
        url::Host<T>: Display,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_string())
            } else {
                let repr = match &self.host {
                    url::Host::Domain(domain) => {
                        AddressRepr::Domain(domain, self.port)
                    }
                    url::Host::Ipv4(v4) => {
                        AddressRepr::V4(SocketAddrV4::new(*v4, self.port))
                    }
                    url::Host::Ipv6(v6) => {
                        AddressRepr::V6(SocketAddrV6::new(*v6, self.port, 0, 0))
                    }
                };
                repr.serialize(serializer)
            }
        }
    }

    impl<S> utoipa::PartialSchema for Address<S> {
        fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
            let obj = utoipa::openapi::Object::with_type(
                utoipa::openapi::Type::String,
            );
            utoipa::openapi::RefOr::T(utoipa::openapi::Schema::Object(obj))
        }
    }

    impl<S> utoipa::ToSchema for Address<S> {
        fn name() -> std::borrow::Cow<'static, str> {
            std::borrow::Cow::Borrowed("PeerAddress")
        }
    }

    /// A peer address that has been resolved to one or more IP address
    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    pub enum ResolvedAddress<S = String> {
        Domain {
            port: u16,
            /// Addresses, in reverse order such that the last element is the
            /// first resolved address.
            addrs: nonempty::NonEmpty<IpAddr>,
            domain: S,
        },
        /// Resolution is not required for static addrs
        Static(SocketAddr),
    }

    impl<S> ResolvedAddress<S> {
        pub fn host(&self) -> url::Host<&S> {
            match self {
                Self::Domain { domain, .. } => url::Host::Domain(domain),
                Self::Static(SocketAddr::V4(v4)) => url::Host::Ipv4(*v4.ip()),
                Self::Static(SocketAddr::V6(v6)) => url::Host::Ipv6(*v6.ip()),
            }
        }

        pub fn port(&self) -> u16 {
            match self {
                Self::Domain { port, .. } => *port,
                Self::Static(addr) => addr.port(),
            }
        }

        pub fn as_peer_address(&self) -> Address<&S> {
            Address {
                host: self.host(),
                port: self.port(),
            }
        }

        /// first resolved IP addr
        pub fn first_ip_addr(&self) -> IpAddr {
            match self {
                Self::Domain { addrs, .. } => *addrs.last(),
                Self::Static(addr) => addr.ip(),
            }
        }

        pub fn pop_first_ip_addr(self) -> (IpAddr, Option<Self>) {
            match self {
                Self::Domain {
                    domain,
                    mut addrs,
                    port,
                } => {
                    if let Some(addr) = addrs.pop() {
                        (
                            addr,
                            Some(Self::Domain {
                                port,
                                addrs,
                                domain,
                            }),
                        )
                    } else {
                        (addrs.head, None)
                    }
                }
                Self::Static(addr) => (addr.ip(), None),
            }
        }

        pub fn ip_addrs(&self) -> impl Iterator<Item = IpAddr> {
            match self {
                Self::Domain { addrs, .. } => {
                    Box::new(addrs.iter().rev().cloned())
                        as Box<dyn Iterator<Item = IpAddr>>
                }
                Self::Static(addr) => Box::new(std::iter::once(addr.ip())),
            }
        }
    }

    impl<S, T> From<T> for ResolvedAddress<S>
    where
        SocketAddr: From<T>,
    {
        fn from(value: T) -> Self {
            Self::Static(SocketAddr::from(value))
        }
    }

    #[derive(
        Clone, Copy, Deserialize, Display, Eq, PartialEq, Serialize, ToSchema,
    )]
    #[schema(as = PeerConnectionStatus)]
    pub enum ConnectionStatus {
        /// We're still in the process of initializing the peer connection
        Connecting,
        /// The connection is successfully established
        Connected,
    }

    /// RPC output representation for peer + state
    #[derive(Clone, Deserialize, Serialize, ToSchema)]
    pub struct Peer {
        #[schema(value_type = schema::SocketAddr)]
        pub address: SocketAddr,
        pub status: ConnectionStatus,
    }

    #[cfg(test)]
    mod test {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

        use super::Address;

        /// A `known_peers` key from an older release reads as the same
        /// address.
        #[test]
        fn an_ip_address_keeps_the_socket_addr_bytes() -> anyhow::Result<()> {
            for socket_addr in [
                SocketAddr::from((Ipv4Addr::new(172, 105, 148, 135), 4002)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 4002)),
            ] {
                let bytes = bincode::serialize(&socket_addr)?;
                let address = Address::from(socket_addr);
                assert_eq!(bincode::serialize(&address)?, bytes);
                assert_eq!(bincode::deserialize::<Address>(&bytes)?, address);
            }
            Ok(())
        }

        #[test]
        fn a_domain_address_reads_back_the_same() -> anyhow::Result<()> {
            let address: Address = "seed.example.com:4002".parse()?;
            let bytes = bincode::serialize(&address)?;
            assert_eq!(bincode::deserialize::<Address>(&bytes)?, address);
            Ok(())
        }
    }
}
pub use peer::{
    Address as PeerAddress, ConnectionStatus as PeerConnectionStatus, Peer,
    ResolvedAddress as ResolvedPeerAddress,
};
