use chrono::{DateTime, Datelike, LocalResult, TimeZone, Timelike, Utc};
use serde::ser::Error;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct LightBlock {
    #[prost_amino(message, optional, tag="1")]
    pub signed_header: ::std::option::Option<SignedHeader>,
    #[prost_amino(message, optional, tag="2")]
    pub validator_set: ::std::option::Option<ValidatorSet>,
    #[prost_amino(message, optional, tag="3")]
    pub next_validator_set: ::std::option::Option<ValidatorSet>,
}

#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct ValidatorSet {
    #[prost_amino(message, repeated, tag="1")]
    pub validators: ::std::vec::Vec<Validator>,
    #[prost_amino(message, optional, tag="2")]
    pub proposer: ::std::option::Option<Validator>,
    #[prost_amino(int64, tag="3")]
    pub total_voting_power: i64,
}

#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct Validator {
    #[prost_amino(bytes, tag="1")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub address: std::vec::Vec<u8>,
    #[prost_amino(bytes, tag = "2", amino_name = "tendermint/PubKeyEd25519")]
    pub pub_key: Vec<u8>,
    #[prost_amino(int64, tag="3")]
    #[serde(alias = "power", with = "crate::serializers::from_str")]
    pub voting_power: i64,
    #[prost_amino(int64, tag="4")]
    #[serde(with = "crate::serializers::from_str", default)]
    pub proposer_priority: i64,
}

#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct SignedHeader {
    #[prost_amino(message, optional, tag="1")]
    pub header: ::std::option::Option<Header>,
    #[prost_amino(message, optional, tag="2")]
    pub commit: ::std::option::Option<Commit>,
}

/// Commit contains the evidence that a block was committed by a set of validators.
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct Commit {
    #[prost_amino(message, optional, tag="1")]
    pub block_id: ::std::option::Option<BlockId>,
    #[prost_amino(message, repeated, tag="2")]
    #[serde(with = "crate::serializers::nullable")]
    pub signatures: ::std::vec::Vec<CommitSig>,
}
/// CommitSig is a part of the Vote included in a Commit.
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct CommitSig {
    #[prost_amino(int32, tag="1")]
    pub vote_type: i32,
    #[prost_amino(int64, tag="2")]
    pub height: i64,
    #[prost_amino(int32, tag="3")]
    pub round: i32,
    #[prost_amino(message, optional, tag="4")]
    pub block_id: ::std::option::Option<BlockId>,
    #[prost_amino(message, optional, tag="5")]
    #[serde(with = "crate::serializers::optional")]
    pub timestamp: ::std::option::Option<Timestamp>,
    #[prost_amino(bytes, tag="6")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub validator_address: std::vec::Vec<u8>,
    #[prost_amino(int32, tag="7")]
    pub validator_index: i32,
    #[prost_amino(bytes, tag="8")]
    #[serde(with = "crate::serializers::bytes::base64string")]
    pub signature: std::vec::Vec<u8>,
}



#[derive(Clone, PartialEq, ::prost_amino_derive::Message, ::serde::Deserialize, ::serde::Serialize)]
#[serde(from = "Rfc3339", into = "Rfc3339")]
pub struct Timestamp {
    /// Represents seconds of UTC time since Unix epoch
    /// 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to
    /// 9999-12-31T23:59:59Z inclusive.
    #[prost_amino(int64, tag = "1")]
    pub seconds: i64,
    /// Non-negative fractions of a second at nanosecond resolution. Negative
    /// second values with fractions must still have non-negative nanos values
    /// that count forward in time. Must be from 0 to 999,999,999
    /// inclusive.
    #[prost_amino(int32, tag = "2")]
    pub nanos: i32,
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct Rfc3339(Timestamp);
impl From<Timestamp> for Rfc3339 {
    fn from(value: Timestamp) -> Self {
        Rfc3339(value)
    }
}
impl From<Rfc3339> for Timestamp {
    fn from(value: Rfc3339) -> Self {
        value.0
    }
}

/// Deserialize string into Timestamp
pub fn deserialize<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
    where
        D: Deserializer<'de>,
{
    let value_string = String::deserialize(deserializer)?;
    let value_datetime = DateTime::parse_from_rfc3339(value_string.as_str())
        .map_err(|e| D::Error::custom(format!("{}", e)))?;
    Ok(Timestamp {
        seconds: value_datetime.timestamp(),
        nanos: value_datetime.timestamp_subsec_nanos() as i32,
    })
}

/// Serialize from Timestamp into string
pub fn serialize<S>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    if value.nanos < 0 {
        return Err(S::Error::custom("invalid nanoseconds in time"));
    }
    match Utc.timestamp_opt(value.seconds, value.nanos as u32) {
        LocalResult::None => Err(S::Error::custom("invalid time")),
        LocalResult::Single(t) => Ok(to_rfc3339_custom(&t)),
        LocalResult::Ambiguous(_, _) => Err(S::Error::custom("ambiguous time")),
    }?
        .serialize(serializer)
}

/// Serialization helper for converting a `DateTime<Utc>` object to a string.
///
/// Due to incompatibilities between the way that `chrono` serializes timestamps
/// and the way that Go does for RFC3339, we unfortunately need to define our
/// own timestamp serialization mechanism.
pub fn to_rfc3339_custom(t: &DateTime<Utc>) -> String {
    let nanos = format!(".{}", t.nanosecond());
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}Z",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        nanos.trim_end_matches('0').trim_end_matches('.'),
    )
}



#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct Consensus {
    #[prost_amino(uint64, tag="1")]
    #[serde(with = "crate::serializers::from_str")]
    pub block: u64,
    #[prost_amino(uint64, tag="2")]
    #[serde(with = "crate::serializers::from_str", default)]
    pub app: u64,
}


/// Header defines the structure of a Tendermint block header.
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct Header {
    /// basic block info
    #[prost_amino(message, optional, tag="1")]
    pub version: ::std::option::Option<Consensus>,
    #[prost_amino(string, tag="2")]
    pub chain_id: std::string::String,
    #[prost_amino(int64, tag="3")]
    #[serde(with = "crate::serializers::from_str")]
    pub height: i64,
    #[prost_amino(message, optional, tag="4")]
    #[serde(with = "crate::serializers::optional")]
    pub time: ::std::option::Option<Timestamp>,
    #[prost_amino(int64, tag="5")]
    #[serde(with = "crate::serializers::from_str")]
    pub num_txs: i64,
    #[prost_amino(int64, tag="6")]
    #[serde(with = "crate::serializers::from_str")]
    pub total_txs: i64,
    /// prev block info
    #[prost_amino(message, optional, tag="7")]
    pub last_block_id: ::std::option::Option<BlockId>,
    /// hashes of block data
    ///
    /// commit from validators from the last block
    #[prost_amino(bytes, tag="8")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub last_commit_hash: std::vec::Vec<u8>,
    /// transactions
    #[prost_amino(bytes, tag="9")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub data_hash: std::vec::Vec<u8>,
    /// hashes from the app output from the prev block
    ///
    /// validators for the current block
    #[prost_amino(bytes, tag="10")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub validators_hash: std::vec::Vec<u8>,
    /// validators for the next block
    #[prost_amino(bytes, tag="11")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub next_validators_hash: std::vec::Vec<u8>,
    /// consensus params for current block
    #[prost_amino(bytes, tag="12")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub consensus_hash: std::vec::Vec<u8>,
    /// state after txs from the previous block
    #[prost_amino(bytes, tag="13")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub app_hash: std::vec::Vec<u8>,
    /// root hash of all results from the txs from the previous block
    #[prost_amino(bytes, tag="14")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub last_results_hash: std::vec::Vec<u8>,
    /// consensus info
    ///
    /// evidence included in the block
    #[prost_amino(bytes, tag="15")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub evidence_hash: std::vec::Vec<u8>,
    /// original proposer of the block
    #[prost_amino(bytes, tag="16")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub proposer_address: std::vec::Vec<u8>,
}

/// BlockID
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct BlockId {
    #[prost_amino(bytes, tag="1")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub hash: std::vec::Vec<u8>,
    #[prost_amino(message, optional, tag="2")]
    #[serde(alias = "parts")]
    pub part_set_header: ::std::option::Option<PartSetHeader>,
}

#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct PartSetHeader {
    #[prost_amino(uint32, tag="1")]
    #[serde(with = "crate::serializers::part_set_header_total")]
    pub total: u32,
    #[prost_amino(bytes, tag="2")]
    #[serde(with = "crate::serializers::bytes::hexstring")]
    pub hash: std::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message, ::serde::Deserialize, ::serde::Serialize)]
pub struct Proof {
    #[prost(int64, tag = "1")]
    #[serde(with = "crate::serializers::from_str")]
    pub total: i64,
    #[prost(int64, tag = "2")]
    #[serde(with = "crate::serializers::from_str")]
    pub index: i64,
    #[prost(bytes, tag = "3")]
    #[serde(with = "crate::serializers::bytes::base64string")]
    pub leaf_hash: std::vec::Vec<u8>,
    #[prost(bytes, repeated, tag = "4")]
    #[serde(with = "crate::serializers::bytes::vec_base64string")]
    pub aunts: ::std::vec::Vec<std::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValueOp {
    /// Encoded in ProofOp.Key.
    #[prost(bytes, tag = "1")]
    pub key: std::vec::Vec<u8>,
    /// To encode in ProofOp.Data
    #[prost(message, optional, tag = "2")]
    pub proof: ::std::option::Option<Proof>,
}

#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct IavlValueProofOp {
    #[prost_amino(message, optional, tag="1")]
    pub proof: ::std::option::Option<RangeProof>,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct RangeProof {
    #[prost_amino(message, repeated, tag="1")]
    pub left_path: ::std::vec::Vec<ProofInnerNode>,
    #[prost_amino(message, repeated, tag="2")]
    pub inner_nodes: ::std::vec::Vec<PathToLeaf>,
    #[prost_amino(message, repeated, tag="3")]
    pub leaves: ::std::vec::Vec<ProofLeafNode>,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct PathToLeaf {
    #[prost_amino(message, repeated, tag="1")]
    pub inners: ::std::vec::Vec<ProofInnerNode>,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct ProofInnerNode {
    #[prost_amino(sint32, tag="1")]
    pub height: i32,
    #[prost_amino(int64, tag="2")]
    pub size: i64,
    #[prost_amino(int64, tag="3")]
    pub version: i64,
    #[prost_amino(bytes, tag="4")]
    pub left: std::vec::Vec<u8>,
    #[prost_amino(bytes, tag="5")]
    pub right: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct ProofLeafNode {
    #[prost_amino(bytes, tag="1")]
    pub key: std::vec::Vec<u8>,
    #[prost_amino(bytes, tag="2")]
    pub value_hash: std::vec::Vec<u8>,
    #[prost_amino(int64, tag="3")]
    pub version: i64,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct CommitId {
    #[prost_amino(int64, tag="1")]
    pub version: i64,
    #[prost_amino(bytes, tag="2")]
    pub hash: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct StoreCore {
    #[prost_amino(message, optional, tag="1")]
    pub commit_id: ::std::option::Option<CommitId>,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct StoreInfo {
    #[prost_amino(string, tag="1")]
    pub name: std::string::String,
    #[prost_amino(message, optional, tag="2")]
    pub core: ::std::option::Option<StoreCore>,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct MultiStoreProof {
    #[prost_amino(message, repeated, tag="1")]
    pub store_infos: ::std::vec::Vec<StoreInfo>,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
pub struct MultiStoreProofOp {
    #[prost_amino(message, optional, tag="1")]
    pub proof: ::std::option::Option<MultiStoreProof>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DominoOp {
    #[prost(string, tag = "1")]
    pub key: std::string::String,
    #[prost(string, tag = "2")]
    pub input: std::string::String,
    #[prost(string, tag = "3")]
    pub output: std::string::String,
}
/// ProofOp defines an operation used for calculating Merkle root
/// The data could be arbitrary format, providing nessecary data
/// for example neighbouring node hash
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofOp {
    #[prost(string, tag = "1")]
    pub r#type: std::string::String,
    #[prost(bytes, tag = "2")]
    pub key: std::vec::Vec<u8>,
    #[prost(bytes, tag = "3")]
    pub data: std::vec::Vec<u8>,
}
/// ProofOps is Merkle proof defined by the list of ProofOps
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofOps {
    #[prost(message, repeated, tag = "1")]
    pub ops: std::vec::Vec<ProofOp>,
}
/// PublicKey defines the keys available for use with Tendermint Validators
#[derive(Clone, PartialEq, ::prost::Message, ::serde::Deserialize, ::serde::Serialize)]
pub struct PublicKey {
    #[prost(oneof = "public_key::Sum", tags = "1, 2")]
    pub sum: ::std::option::Option<public_key::Sum>,
}
pub mod public_key {
    #[derive(Clone, PartialEq, ::prost::Oneof, ::serde::Deserialize, ::serde::Serialize)]
    #[serde(tag = "type", content = "value")]
    pub enum Sum {
        #[prost(bytes, tag = "1")]
        #[serde(
            rename = "tendermint/PubKeyEd25519",
            with = "crate::serializers::bytes::base64string"
        )]
        Ed25519(std::vec::Vec<u8>),
        #[prost(bytes, tag = "2")]
        #[serde(
            rename = "tendermint/PubKeySecp256k1",
            with = "crate::serializers::bytes::base64string"
        )]
        Secp256k1(std::vec::Vec<u8>),
    }
}

#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct CanonicalBlockId {
    #[prost_amino(bytes, tag="1")]
    pub hash: std::vec::Vec<u8>,
    #[prost_amino(message, optional, tag="2")]
    #[serde(alias = "parts")]
    pub part_set_header: ::std::option::Option<CanonicalPartSetHeader>,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct CanonicalPartSetHeader {
    #[prost_amino(bytes, tag="1")]
    pub hash: std::vec::Vec<u8>,
    #[prost_amino(uint32, tag="2")]
    pub total: u32,
}
#[derive(Clone, PartialEq, ::prost_amino_derive::Message)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
pub struct CanonicalVote {
    /// type alias for byte
    #[prost_amino(int32, tag="1")]
    pub signed_msg_type: i32,
    /// canonicalization requires fixed size encoding here
    #[prost_amino(sfixed64, tag="2")]
    pub height: i64,
    /// canonicalization requires fixed size encoding here
    #[prost_amino(sfixed64, tag="3")]
    pub round: i64,
    #[prost_amino(message, optional, tag="4")]
    pub block_id: ::std::option::Option<CanonicalBlockId>,
    #[prost_amino(message, optional, tag="5")]
    pub timestamp: ::std::option::Option<Timestamp>,
    #[prost_amino(string, tag="6")]
    pub chain_id: std::string::String,
}
