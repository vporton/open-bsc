//! Proposals from validators

mod canonical_proposal;
mod msg_type;
mod sign_proposal;

pub use self::canonical_proposal::CanonicalProposal;
pub use msg_type::Type;
pub use sign_proposal::{SignProposalRequest, SignedProposalResponse};

use crate::{
    block::{Height, Id as BlockId, Round},
    chain::Id as ChainId,
    consensus::State,
    Error, Kind, Signature, Time,
};
use bytes::BufMut;
use std::convert::{TryFrom, TryInto};
use tendermint_proto::{types::Proposal as RawProposal, Error as ProtobufError, Protobuf};

/// Proposal
#[derive(Clone, PartialEq, Debug)]
pub struct Proposal {
    /// Proposal message type
    pub msg_type: Type,
    /// Height
    pub height: Height,
    /// Round
    pub round: Round,
    /// POL Round
    pub pol_round: Option<Round>,
    /// Block ID
    pub block_id: Option<BlockId>,
    /// Timestamp
    pub timestamp: Option<Time>,
    /// Signature
    pub signature: Signature,
}

impl Protobuf<RawProposal> for Proposal {}

impl TryFrom<RawProposal> for Proposal {
    type Error = Error;

    fn try_from(value: RawProposal) -> Result<Self, Self::Error> {
        if value.pol_round < -1 {
            return Err(Kind::NegativePolRound.into());
        }
        let pol_round = match value.pol_round {
            -1 => None,
            n => Some(Round::try_from(n)?),
        };
        Ok(Proposal {
            msg_type: value.r#type.try_into()?,
            height: value.height.try_into()?,
            round: value.round.try_into()?,
            pol_round,
            block_id: value.block_id.map(TryInto::try_into).transpose()?,
            timestamp: value.timestamp.map(TryInto::try_into).transpose()?,
            signature: value.signature.try_into()?,
        })
    }
}

impl From<Proposal> for RawProposal {
    fn from(value: Proposal) -> Self {
        RawProposal {
            r#type: value.msg_type.into(),
            height: value.height.into(),
            round: value.round.into(),
            pol_round: value.pol_round.map_or(-1, Into::into),
            block_id: value.block_id.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
            signature: value.signature.into(),
        }
    }
}

impl Proposal {
    /// Create signable bytes from Proposal.
    pub fn to_signable_bytes<B>(
        &self,
        chain_id: ChainId,
        sign_bytes: &mut B,
    ) -> Result<bool, ProtobufError>
    where
        B: BufMut,
    {
        CanonicalProposal::new(self.clone(), chain_id).encode_length_delimited(sign_bytes)?;
        Ok(true)
    }

    /// Create signable vector from Proposal.
    pub fn to_signable_vec(&self, chain_id: ChainId) -> Result<Vec<u8>, ProtobufError> {
        CanonicalProposal::new(self.clone(), chain_id).encode_length_delimited_vec()
    }

    /// Consensus state from this proposal - This doesn't seem to be used anywhere.
    #[deprecated(
        since = "0.17.0",
        note = "This seems unnecessary, please raise it to the team, if you need it."
    )]
    pub fn consensus_state(&self) -> State {
        State {
            height: self.height,
            round: self.round,
            step: 3,
            block_id: self.block_id,
        }
    }
}
