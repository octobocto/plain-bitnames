use borsh::BorshSerialize;
use generic_array::{ArrayLength, GenericArray};
use libes::{auth::HmacSha256, enc::Aes256Gcm, key::X25519};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeAs, DisplayFromStr, FromInto, SerializeAs};
use utoipa::ToSchema;

use crate::{error, util};

/// Wrapper around x25519 pubkeys
#[derive(BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct EncryptionPubKey(
    #[borsh(serialize_with = "util::borsh::serialize::x25519_pubkey")]
    pub  x25519_dalek::PublicKey,
);

impl EncryptionPubKey {
    /// HRP for Bech32m encoding
    const BECH32M_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("bn-enc");

    /// Encode to Bech32m format
    pub fn bech32m_encode(&self) -> String {
        bech32::encode::<bech32::Bech32m>(Self::BECH32M_HRP, self.0.as_bytes())
            .expect("Bech32m Encoding should not fail")
    }

    /// Decode from Bech32m format
    pub fn bech32m_decode(s: &str) -> Result<Self, error::Bech32mDecode> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp != Self::BECH32M_HRP {
            let err = error::WrongHrp {
                expected: Self::BECH32M_HRP,
                decoded: hrp,
            };
            return Err(Box::new(err).into());
        }
        let bytes = match <[u8; 32]>::try_from(data) {
            Ok(bytes) => bytes,
            Err(data) => {
                return Err(error::Bech32mDecode::WrongSize {
                    decoded_len: data.len(),
                    expected_len: 32,
                });
            }
        };
        let res = Self::from(bytes);
        if s != res.bech32m_encode() {
            return Err(error::Bech32mDecode::WrongVariant);
        }
        Ok(res)
    }
}

impl std::fmt::Display for EncryptionPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.bech32m_encode().fmt(f)
    }
}

impl<T> From<T> for EncryptionPubKey
where
    x25519_dalek::PublicKey: From<T>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl std::str::FromStr for EncryptionPubKey {
    type Err = error::Bech32mDecode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::bech32m_decode(s)
    }
}

impl<'de> Deserialize<'de> for EncryptionPubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde_with::IfIsHumanReadable::<
            DisplayFromStr,
            FromInto<x25519_dalek::PublicKey>,
        >::deserialize_as(deserializer)
    }
}

impl Serialize for EncryptionPubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            DisplayFromStr::serialize_as(self, serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

/// Wrapper around ristretto255 verifying keys
#[derive(BorshSerialize, Clone, Copy, Debug, Eq, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct VerifyingKey(
    #[borsh(serialize_with = "util::borsh::serialize::verifying_key")]
    pub  frost_ristretto255::VerifyingKey,
);

impl VerifyingKey {
    /// HRP for Bech32m encoding
    const BECH32M_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("bn-svk");

    pub const BYTE_LEN: usize = 32;

    /// Encode to Bech32m format
    pub fn bech32m_encode(&self) -> String {
        bech32::encode::<bech32::Bech32m>(Self::BECH32M_HRP, &self.to_bytes())
            .expect("Bech32m Encoding should not fail")
    }

    /// Decode from Bech32m format
    pub fn bech32m_decode(s: &str) -> Result<Self, error::Bech32mDecode> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp != Self::BECH32M_HRP {
            let err = error::WrongHrp {
                expected: Self::BECH32M_HRP,
                decoded: hrp,
            };
            return Err(Box::new(err).into());
        }
        let bytes = match <[u8; 32]>::try_from(data) {
            Ok(bytes) => bytes,
            Err(data) => {
                return Err(error::Bech32mDecode::WrongSize {
                    decoded_len: data.len(),
                    expected_len: 32,
                });
            }
        };
        let res = match frost_ristretto255::VerifyingKey::deserialize(&bytes) {
            Ok(vk) => Self(vk),
            Err(err) => {
                let err = error::Bech32mDecode::InvalidBytes {
                    bytes,
                    source: Box::new(err),
                };
                return Err(err);
            }
        };
        if s != res.bech32m_encode() {
            return Err(error::Bech32mDecode::WrongVariant);
        }
        Ok(res)
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        self.0.to_element().compress().to_bytes()
    }
}

impl std::hash::Hash for VerifyingKey {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.to_bytes().hash(state)
    }
}

impl std::fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.bech32m_encode().fmt(f)
    }
}

impl From<frost_ristretto255::VerifyingKey> for VerifyingKey {
    fn from(vk: frost_ristretto255::VerifyingKey) -> Self {
        Self(vk)
    }
}

impl From<VerifyingKey> for frost_ristretto255::VerifyingKey {
    fn from(vk: VerifyingKey) -> Self {
        vk.0
    }
}

impl From<&frost_ristretto255::SigningKey> for VerifyingKey {
    fn from(sk: &frost_ristretto255::SigningKey) -> Self {
        Self(frost_ristretto255::VerifyingKey::from(sk))
    }
}

impl TryFrom<&[u8; VerifyingKey::BYTE_LEN]> for VerifyingKey {
    type Error = frost_ristretto255::Error;

    fn try_from(
        bytes: &[u8; VerifyingKey::BYTE_LEN],
    ) -> Result<Self, Self::Error> {
        frost_ristretto255::VerifyingKey::deserialize(bytes).map(Self)
    }
}

impl std::str::FromStr for VerifyingKey {
    type Err = error::Bech32mDecode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::bech32m_decode(s)
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde_with::IfIsHumanReadable::<
            DisplayFromStr,
            FromInto<frost_ristretto255::VerifyingKey>,
        >::deserialize_as(deserializer)
    }
}

impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_with::IfIsHumanReadable::<
            DisplayFromStr,
            FromInto<frost_ristretto255::VerifyingKey>,
        >::serialize_as(self, serializer)
    }
}

// TODO: Remove dependency on generic-array / typenum,
// once #![feature(generic_const_exprs)] has been stabilized.
pub trait Base58Encoding: TryFrom<GenericArray<u8, Self::ByteLen>> {
    type ByteLen: ArrayLength;

    type B58PrefixLen: ArrayLength + std::ops::Add<Self::ByteLen>;

    /// Data prefix, used to ensure that the encoded string has a certain
    /// prefix
    const B58_DATA_PREFIX: GenericArray<u8, Self::B58PrefixLen>;

    /// Encoded prefix, used only for tests
    const B58_PREFIX: &str;

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteLen>;
}

mod private {
    pub trait Base58EncodingExtSealed {}

    impl<T> Base58EncodingExtSealed for T where T: super::Base58Encoding {}
}

type B58ckDecodeError<T> = error::Base58ckDecode<
    <T as Base58Encoding>::B58PrefixLen,
    <T as TryFrom<GenericArray<u8, <T as Base58Encoding>::ByteLen>>>::Error,
>;

pub trait Base58EncodingExt:
    Base58Encoding + private::Base58EncodingExtSealed
{
    #[inline(always)]
    fn base58_data(
        &self,
    ) -> GenericArray<u8, typenum::Sum<Self::B58PrefixLen, Self::ByteLen>>
    where
        typenum::Sum<Self::B58PrefixLen, Self::ByteLen>: ArrayLength,
    {
        use generic_array::sequence::GenericSequence;
        use typenum::Unsigned;
        let payload: &[u8] = &self.to_bytes();
        GenericArray::generate(|idx| {
            if idx < Self::B58PrefixLen::USIZE {
                Self::B58_DATA_PREFIX[idx]
            } else {
                payload[idx - Self::B58PrefixLen::USIZE]
            }
        })
    }

    /// Decode from Base58ck
    fn base58ck_decode(s: &str) -> Result<Self, B58ckDecodeError<Self>>
    where
        typenum::Sum<Self::B58PrefixLen, Self::ByteLen>: ArrayLength
            + std::ops::Sub<Self::B58PrefixLen, Output = Self::ByteLen>,
    {
        use typenum::Unsigned;
        let decoded = bitcoin::base58::decode_check(s)?;
        let decoded: &GenericArray<
            u8,
            typenum::Sum<Self::B58PrefixLen, Self::ByteLen>,
        > = decoded.as_slice().try_into().map_err(
            |generic_array::LengthError| {
                error::base58ck_decode::Inner::IncorrectSize {
                    decoded: decoded.len(),
                    expected: Self::B58PrefixLen::USIZE + Self::ByteLen::USIZE,
                }
            },
        )?;
        let (prefix, payload) =
            generic_array::sequence::Split::split(decoded.clone());
        if prefix != Self::B58_DATA_PREFIX {
            return Err(error::base58ck_decode::Inner::IncorrectPrefix {
                decoded: prefix,
                expected: Self::B58_DATA_PREFIX,
            }
            .into());
        }
        payload
            .try_into()
            .map_err(|err| error::base58ck_decode::Inner::TryFrom(err).into())
    }

    /// Encode to Base58ck
    fn base58ck_encode_fmt(
        &self,
        fmt: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result
    where
        typenum::Sum<Self::B58PrefixLen, Self::ByteLen>: ArrayLength,
    {
        bitcoin::base58::encode_check_to_fmt(fmt, self.base58_data().as_slice())
    }

    /// Encode to Base58ck
    fn base58ck_encode(&self) -> String
    where
        typenum::Sum<Self::B58PrefixLen, Self::ByteLen>: ArrayLength,
    {
        bitcoin::base58::encode_check(self.base58_data().as_slice())
    }
}

impl<T> Base58EncodingExt for T where T: Base58Encoding {}

/// Wrapper around ed25519 xpubkeys
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct XPubKey(pub ed25519_bip32::XPub);

impl XPubKey {
    /// HRP for Bech32m encoding
    const BECH32M_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("bn-xpub");

    const BYTE_LEN: usize = ed25519_bip32::XPUB_SIZE;

    /// Encode to Bech32m format
    pub fn bech32m_encode(&self) -> String {
        bech32::encode::<bech32::Bech32m>(Self::BECH32M_HRP, self.0.as_ref())
            .expect("Bech32m Encoding should not fail")
    }

    /// Decode from Bech32m format
    pub fn bech32m_decode(s: &str) -> Result<Self, error::Bech32mDecode> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp != Self::BECH32M_HRP {
            let err = error::WrongHrp {
                expected: Self::BECH32M_HRP,
                decoded: hrp,
            };
            return Err(Box::new(err).into());
        }
        let bytes = match <[u8; Self::BYTE_LEN]>::try_from(data) {
            Ok(bytes) => bytes,
            Err(data) => {
                return Err(error::Bech32mDecode::WrongSize {
                    decoded_len: data.len(),
                    expected_len: Self::BYTE_LEN,
                });
            }
        };
        let res = Self(ed25519_bip32::XPub::from_bytes(bytes));
        if s != res.bech32m_encode() {
            return Err(error::Bech32mDecode::WrongVariant);
        }
        Ok(res)
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        self.0.into()
    }
}

impl Base58Encoding for XPubKey {
    type B58PrefixLen = generic_array::ConstArrayLength<6>;

    type ByteLen =
        generic_array::ConstArrayLength<{ ed25519_bip32::XPUB_SIZE }>;

    const B58_PREFIX: &str = "BNsXPub";

    const B58_DATA_PREFIX: GenericArray<u8, Self::B58PrefixLen> =
        generic_array::arr![0x24, 0x16, 0x69, 0x9f, 0x0e, 0xc6];

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteLen> {
        let bytes: [u8; ed25519_bip32::XPUB_SIZE] = self.0.into();
        GenericArray::from_array(bytes)
    }
}

impl std::fmt::Display for XPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.base58ck_encode_fmt(f)
    }
}

impl From<ed25519_bip32::XPub> for XPubKey {
    fn from(xpub: ed25519_bip32::XPub) -> Self {
        Self(xpub)
    }
}

impl From<XPubKey> for ed25519_bip32::XPub {
    fn from(xpub: XPubKey) -> Self {
        xpub.0
    }
}

impl From<[u8; XPubKey::BYTE_LEN]> for XPubKey {
    fn from(bytes: [u8; XPubKey::BYTE_LEN]) -> Self {
        Self(ed25519_bip32::XPub::from_bytes(bytes))
    }
}

impl From<GenericArray<u8, <XPubKey as Base58Encoding>::ByteLen>> for XPubKey {
    fn from(
        bytes: GenericArray<u8, <XPubKey as Base58Encoding>::ByteLen>,
    ) -> Self {
        let bytes: [u8; ed25519_bip32::XPUB_SIZE] = bytes.into_array();
        XPubKey::from(bytes)
    }
}

impl std::str::FromStr for XPubKey {
    type Err = error::Base58ckDecode<
        <Self as Base58Encoding>::B58PrefixLen,
        std::convert::Infallible,
    >;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::base58ck_decode(s)
    }
}

impl<'de> Deserialize<'de> for XPubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            DisplayFromStr::deserialize_as(deserializer)
        } else {
            let bytes: [u8; XPubKey::BYTE_LEN] =
                serde_with::Bytes::deserialize_as(deserializer)?;
            Ok(bytes.into())
        }
    }
}

impl Serialize for XPubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            Serialize::serialize(&self.to_string(), serializer)
        } else {
            serde_with::Bytes::serialize_as(&self.to_bytes(), serializer)
        }
    }
}

/// Wrapper around ed25519 xpubkeys
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct XVerifyingKey(pub ed25519_bip32::XPub);

impl XVerifyingKey {
    /// HRP for Bech32m encoding
    const BECH32M_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("bn-xvk");

    const BYTE_LEN: usize = ed25519_bip32::XPUB_SIZE;

    /// Encode to Bech32m format
    pub fn bech32m_encode(&self) -> String {
        bech32::encode::<bech32::Bech32m>(Self::BECH32M_HRP, self.0.as_ref())
            .expect("Bech32m Encoding should not fail")
    }

    /// Decode from Bech32m format
    pub fn bech32m_decode(s: &str) -> Result<Self, error::Bech32mDecode> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp != Self::BECH32M_HRP {
            let err = error::WrongHrp {
                expected: Self::BECH32M_HRP,
                decoded: hrp,
            };
            return Err(Box::new(err).into());
        }
        let bytes = match <[u8; Self::BYTE_LEN]>::try_from(data) {
            Ok(bytes) => bytes,
            Err(data) => {
                return Err(error::Bech32mDecode::WrongSize {
                    decoded_len: data.len(),
                    expected_len: Self::BYTE_LEN,
                });
            }
        };
        let res = Self(ed25519_bip32::XPub::from_bytes(bytes));
        if s != res.bech32m_encode() {
            return Err(error::Bech32mDecode::WrongVariant);
        }
        Ok(res)
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        self.0.into()
    }
}

impl Base58Encoding for XVerifyingKey {
    type B58PrefixLen = generic_array::ConstArrayLength<5>;

    type ByteLen =
        generic_array::ConstArrayLength<{ ed25519_bip32::XPUB_SIZE }>;

    const B58_PREFIX: &str = "BNsXVK";

    const B58_DATA_PREFIX: GenericArray<u8, Self::B58PrefixLen> =
        generic_array::arr![0x9f, 0x48, 0x71, 0x91, 0x4b];

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteLen> {
        let bytes: [u8; ed25519_bip32::XPUB_SIZE] = self.0.into();
        GenericArray::from_array(bytes)
    }
}

impl std::fmt::Display for XVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.base58ck_encode_fmt(f)
    }
}

impl From<ed25519_bip32::XPub> for XVerifyingKey {
    fn from(xpub: ed25519_bip32::XPub) -> Self {
        Self(xpub)
    }
}

impl From<XVerifyingKey> for ed25519_bip32::XPub {
    fn from(xvk: XVerifyingKey) -> Self {
        xvk.0
    }
}

impl From<[u8; XVerifyingKey::BYTE_LEN]> for XVerifyingKey {
    fn from(bytes: [u8; XVerifyingKey::BYTE_LEN]) -> Self {
        Self(ed25519_bip32::XPub::from_bytes(bytes))
    }
}

impl From<GenericArray<u8, <XVerifyingKey as Base58Encoding>::ByteLen>>
    for XVerifyingKey
{
    fn from(
        bytes: GenericArray<u8, <XVerifyingKey as Base58Encoding>::ByteLen>,
    ) -> Self {
        let bytes: [u8; ed25519_bip32::XPUB_SIZE] = bytes.into_array();
        XVerifyingKey::from(bytes)
    }
}

impl std::str::FromStr for XVerifyingKey {
    type Err = error::Base58ckDecode<
        <Self as Base58Encoding>::B58PrefixLen,
        std::convert::Infallible,
    >;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::base58ck_decode(s)
    }
}

impl<'de> Deserialize<'de> for XVerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            DisplayFromStr::deserialize_as(deserializer)
        } else {
            let bytes: [u8; XVerifyingKey::BYTE_LEN] =
                serde_with::Bytes::deserialize_as(deserializer)?;
            Ok(bytes.into())
        }
    }
}

impl Serialize for XVerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            Serialize::serialize(&self.to_string(), serializer)
        } else {
            serde_with::Bytes::serialize_as(&self.to_bytes(), serializer)
        }
    }
}

/// Wrapper around ed25519 xprivkeys
#[derive(Clone, Debug, Eq, PartialEq, ToSchema)]
#[repr(transparent)]
#[schema(value_type = String)]
pub struct XEncryptionSecretKey(pub ed25519_bip32::XPrv);

impl XEncryptionSecretKey {
    pub fn encryption_secret(&self) -> x25519_dalek::StaticSecret {
        // This is safe since the signing scalar is already clamped
        let (secret_bytes, _): (&[u8; 32], _) = self
            .0
            .extended_secret_key_bytes()
            .split_first_chunk()
            .unwrap();
        (*secret_bytes).into()
    }
}

impl Base58Encoding for XEncryptionSecretKey {
    type B58PrefixLen = generic_array::ConstArrayLength<6>;

    type ByteLen =
        generic_array::ConstArrayLength<{ ed25519_bip32::XPRV_SIZE }>;

    const B58_PREFIX: &str = "BNsXEsk";

    const B58_DATA_PREFIX: GenericArray<u8, Self::B58PrefixLen> =
        generic_array::arr![0x79, 0x7b, 0x44, 0x3e, 0xb7, 0x3b];

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteLen> {
        let bytes: [u8; ed25519_bip32::XPRV_SIZE] = self.0.clone().into();
        GenericArray::from_array(bytes)
    }
}

impl std::fmt::Display for XEncryptionSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.base58ck_encode_fmt(f)
    }
}

impl From<ed25519_bip32::XPrv> for XEncryptionSecretKey {
    fn from(xprv: ed25519_bip32::XPrv) -> Self {
        Self(xprv)
    }
}

impl From<XEncryptionSecretKey> for ed25519_bip32::XPrv {
    fn from(xesk: XEncryptionSecretKey) -> Self {
        xesk.0
    }
}

impl TryFrom<[u8; ed25519_bip32::XPRV_SIZE]> for XEncryptionSecretKey {
    type Error = ed25519_bip32::PrivateKeyError;

    fn try_from(
        bytes: [u8; ed25519_bip32::XPRV_SIZE],
    ) -> Result<Self, Self::Error> {
        ed25519_bip32::XPrv::from_bytes_verified(bytes).map(Self)
    }
}

impl
    TryFrom<GenericArray<u8, <XEncryptionSecretKey as Base58Encoding>::ByteLen>>
    for XEncryptionSecretKey
{
    type Error = ed25519_bip32::PrivateKeyError;

    fn try_from(
        bytes: GenericArray<
            u8,
            <XEncryptionSecretKey as Base58Encoding>::ByteLen,
        >,
    ) -> Result<Self, Self::Error> {
        let bytes: [u8; ed25519_bip32::XPRV_SIZE] = bytes.into_array();
        XEncryptionSecretKey::try_from(bytes)
    }
}

impl std::str::FromStr for XEncryptionSecretKey {
    type Err = error::Base58ckDecode<
        <Self as Base58Encoding>::B58PrefixLen,
        ed25519_bip32::PrivateKeyError,
    >;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::base58ck_decode(s)
    }
}

impl<'de> Deserialize<'de> for XEncryptionSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            DisplayFromStr::deserialize_as(deserializer)
        } else {
            let bytes: [u8; ed25519_bip32::XPRV_SIZE] =
                serde_with::Bytes::deserialize_as(deserializer)?;
            Self::try_from(bytes).map_err(|err| {
                <D::Error as serde::de::Error>::custom(err.to_string())
            })
        }
    }
}

impl Serialize for XEncryptionSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            Serialize::serialize(&self.to_string(), serializer)
        } else {
            let bytes: [u8; _] = self.0.clone().into();
            serde_with::Bytes::serialize_as(&bytes, serializer)
        }
    }
}

/// ECIES crypto scheme over x25519
pub type Ecies = libes::Ecies<X25519, Aes256Gcm, HmacSha256>;

#[cfg(test)]
mod tests {
    use generic_array::{ArrayLength, GenericArray};

    use crate::keys::XEncryptionSecretKey;

    use super::{Base58Encoding, Base58EncodingExt, XPubKey, XVerifyingKey};

    fn test_b58ck_roundtrip<T>(value: &T) -> anyhow::Result<()>
    where
        T: Base58Encoding + Eq,
        typenum::Sum<T::B58PrefixLen, T::ByteLen>:
            ArrayLength + std::ops::Sub<T::B58PrefixLen, Output = T::ByteLen>,
        <T as TryFrom<GenericArray<u8, T::ByteLen>>>::Error:
            std::fmt::Debug + std::error::Error + Send + Sync + 'static,
    {
        let encoded = value.base58ck_encode();
        anyhow::ensure!(encoded.starts_with(T::B58_PREFIX));
        let decoded = T::base58ck_decode(&encoded)?;
        anyhow::ensure!(decoded == *value);
        Ok(())
    }

    #[test]
    fn test_b58ck_roundtrips() -> anyhow::Result<()> {
        test_b58ck_roundtrip(&XPubKey::from([0; XPubKey::BYTE_LEN]))?;
        test_b58ck_roundtrip(&XPubKey::from([u8::MAX; XPubKey::BYTE_LEN]))?;
        test_b58ck_roundtrip(&XVerifyingKey::from(
            [0; XVerifyingKey::BYTE_LEN],
        ))?;
        test_b58ck_roundtrip(&XVerifyingKey::from(
            [u8::MAX; XVerifyingKey::BYTE_LEN],
        ))?;
        test_b58ck_roundtrip(&XEncryptionSecretKey::from(
            ed25519_bip32::XPrv::normalize_bytes_ed25519(
                [0; ed25519_bip32::XPRV_SIZE],
            ),
        ))?;
        test_b58ck_roundtrip(&XEncryptionSecretKey::from(
            ed25519_bip32::XPrv::normalize_bytes_ed25519(
                [u8::MAX; ed25519_bip32::XPRV_SIZE],
            ),
        ))
    }
}
