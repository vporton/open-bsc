//! Light header verify
use crate::account::Id as AccountId;
use crate::hash::SHA256_HASH_SIZE;
use crate::merkle::{simple_hash_from_byte_vectors, Hash};
use crate::PublicKey;
use bstr::ByteSlice;
use byteorder::{BigEndian, ByteOrder};
use parity_bytes::BytesRef;
use prost_amino::Message as _;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::convert::TryInto;
use tendermint_proto::crypto::CanonicalVote as RawCanonicalVote;
use tendermint_proto::crypto::{
    CanonicalBlockId, CanonicalPartSetHeader, Commit, CommitSig, LightBlock, SignedHeader,
    ValidatorSet,
};

const PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH: usize = 32;
const UINT64_TYPE_LENGTH: usize = 8;
const CONSENSUS_STATE_LENGTH_BYTES_LENGTH: usize = 32;

const CHAIN_ID_LENGTH: usize = 32;
const HEIGHT_LENGTH: usize = 8;
const VALIDATOR_SET_HASH_LENGTH: usize = 32;
const APP_HASH_LENGTH: usize = 32;
const VALIDATOR_PUBKEY_LENGTH: usize = 32;
const VALIDATOR_VOTING_POWER_LENGTH: usize = 8;
const MAX_CONSENSUS_STATE_LENGTH: usize = 32 * (128 - 1);

#[derive(
    Clone, PartialEq, ::prost_amino_derive::Message, ::serde::Deserialize, ::serde::Serialize,
)]
struct Validator {
    #[prost_amino(bytes, tag = "1", amino_name = "tendermint/PubKeyEd25519")]
    pub_key: Vec<u8>,
    #[prost_amino(uint64, tag = "2")]
    voting_power: u64,
}

struct ConsensusState {
    chain_id: String,
    height: u64,
    app_hash: Vec<u8>,
    cur_validator_set_hash: Vec<u8>,
    next_validator_set: Vec<Validator>,
}

struct HeaderCs {
    cs: ConsensusState,
    header: LightBlock,
}

impl ConsensusState {
    pub fn encode(self) -> Result<Vec<u8>, &'static str> {
        let validator_set_size: usize = self.next_validator_set.len();

        let serialize_length: usize = CHAIN_ID_LENGTH
            + HEIGHT_LENGTH
            + APP_HASH_LENGTH
            + VALIDATOR_SET_HASH_LENGTH
            + validator_set_size * (VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH);

        if serialize_length > MAX_CONSENSUS_STATE_LENGTH {
            return Err("too many validators,consensus state bytes should not exceed");
        }

        let mut encoded_bytes: Vec<u8> = Vec::new();
        if self.chain_id.len() > CHAIN_ID_LENGTH {
            return Err("chainID length should be no more than 32");
        }

        let mut chain_id_bytes: [u8; CHAIN_ID_LENGTH] = [0; CHAIN_ID_LENGTH];
        chain_id_bytes[..self.chain_id.len()].copy_from_slice(self.chain_id.as_bytes());
        encoded_bytes.extend(chain_id_bytes.to_vec());

        let mut height_bytes: [u8; HEIGHT_LENGTH] = [0; HEIGHT_LENGTH];
        BigEndian::write_u64(&mut height_bytes[..], self.height);

        encoded_bytes.extend(height_bytes.to_vec());
        encoded_bytes.extend(self.app_hash);
        encoded_bytes.extend(self.cur_validator_set_hash);

        for index in 0..validator_set_size {
            let mut validator_bytes: [u8; VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH] =
                [0; VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH];
            validator_bytes[..VALIDATOR_PUBKEY_LENGTH]
                .copy_from_slice(self.next_validator_set[index].pub_key.as_slice());
            let mut voting_power_bytes: [u8; VALIDATOR_VOTING_POWER_LENGTH] =
                [0; VALIDATOR_VOTING_POWER_LENGTH];
            BigEndian::write_u64(
                &mut voting_power_bytes[..],
                self.next_validator_set[index].voting_power,
            );

            validator_bytes[VALIDATOR_PUBKEY_LENGTH..].copy_from_slice(&voting_power_bytes[..]);
            encoded_bytes.extend(validator_bytes.to_vec());
        }

        return Ok(encoded_bytes);
    }
}

/// tendermint header verifier
pub struct TmHeaderVerifier {}

impl TmHeaderVerifier {
    /// verify next header
    pub fn execute(input: &[u8], output: &mut BytesRef) -> Result<(), &'static str> {
        let input_length: usize = input.len();
        if input_length <= PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH {
            return Err("invalid input");
        }

        let payload_length = BigEndian::read_u64(
            &input[PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH - UINT64_TYPE_LENGTH
                ..PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH],
        ) as usize;
        if input_length != payload_length + PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH {
            return Err("invalid input size");
        }
        let header_cs = TmHeaderVerifier::decode_tendermint_header_validation_input(
            &input[PRECOMPILE_CONTRACT_INPUT_META_DATA_LENGTH..],
        )?;

        let header = header_cs.header;
        let cs = header_cs.cs;
        TmHeaderVerifier::validator_sets_match(&header)?;
        TmHeaderVerifier::next_validators_match(&header)?;
        TmHeaderVerifier::header_matches_commit(&header.signed_header.as_ref().unwrap())?;
        TmHeaderVerifier::valid_commit(
            &header.signed_header.as_ref().unwrap(),
            &header.validator_set.as_ref().unwrap(),
        )?;

        let trusted_next_height = cs.height + 1;
        let un_trusted_height = header
            .signed_header
            .as_ref()
            .unwrap()
            .header
            .as_ref()
            .unwrap()
            .height as u64;
        if un_trusted_height == trusted_next_height {
            // If the untrusted block is the very next block after the trusted block,
            // check that their (next) validator sets hashes match.
            TmHeaderVerifier::valid_next_validator_set(&header, &cs)?;
        } else if un_trusted_height < trusted_next_height {
            return Err("Non Increasing Height");
        } else {
            TmHeaderVerifier::verify_sufficient_validators_overlap(
                &header.signed_header.as_ref().unwrap(),
                &cs.next_validator_set,
            )?;
        }

        TmHeaderVerifier::verify_sufficient_signers_overlap(&header)?;

        let next_validator_set = cs
            .next_validator_set
            .iter()
            .map(|validator| Validator {
                pub_key: validator.pub_key.clone(),
                voting_power: validator.voting_power,
            })
            .collect();
        let new_cs = ConsensusState {
            chain_id: cs.chain_id,
            height: un_trusted_height,
            app_hash: header
                .signed_header
                .as_ref()
                .unwrap()
                .header
                .as_ref()
                .unwrap()
                .app_hash
                .clone(),
            cur_validator_set_hash: header
                .signed_header
                .unwrap()
                .header
                .unwrap()
                .validators_hash,
            next_validator_set,
        };
        let validator_set_changed = new_cs.cur_validator_set_hash != cs.cur_validator_set_hash;
        let cs_bytes = new_cs.encode()?;
        if validator_set_changed {
            output.write(0, &[1_u8, 1]);
        }
        let cs_len = cs_bytes.len() as u64;
        let mut height_bytes: [u8; 8] = [0; 8];
        BigEndian::write_u64(&mut height_bytes[..], cs_len);

        output.write(24, &height_bytes[..]);
        output.write(32, &cs_bytes[..]);
        Ok(())
    }

    fn valid_next_validator_set(
        light_block: &LightBlock,
        cs: &ConsensusState,
    ) -> Result<(), &'static str> {
        let validator_bytes: Vec<Vec<u8>> = cs
            .next_validator_set
            .iter()
            .map(|validator| {
                let mut wire = Vec::new();
                validator.encode(&mut wire).unwrap();
                wire
            })
            .collect();

        let trust_next_validators_hash = simple_hash_from_byte_vectors(validator_bytes);
        if light_block
            .signed_header
            .as_ref()
            .unwrap()
            .header
            .as_ref()
            .unwrap()
            .validators_hash
            != trust_next_validators_hash.to_vec()
        {
            return Err("Invalid NextValidatorSet");
        }
        return Ok(());
    }
    fn validator_sets_match(light_block: &LightBlock) -> Result<(), &'static str> {
        let validators_hash =
            TmHeaderVerifier::hash_validator_set(&light_block.validator_set.as_ref().unwrap());

        if light_block
            .signed_header
            .as_ref()
            .unwrap()
            .header
            .as_ref()
            .unwrap()
            .validators_hash
            != validators_hash.to_vec()
        {
            return Err("invalid validators_hash");
        }
        Ok(())
    }

    fn next_validators_match(light_block: &LightBlock) -> Result<(), &'static str> {
        let next_validators_hash =
            TmHeaderVerifier::hash_validator_set(&light_block.next_validator_set.as_ref().unwrap());

        if light_block
            .signed_header
            .as_ref()
            .unwrap()
            .header
            .as_ref()
            .unwrap()
            .next_validators_hash
            != next_validators_hash.to_vec()
        {
            return Err("invalid next_validators_hash");
        }

        Ok(())
    }

    /// Compute the Merkle root of the validator set
    fn hash_validator_set(validator_set: &ValidatorSet) -> Hash {
        let validator_bytes: Vec<Vec<u8>> = validator_set
            .validators
            .iter()
            .map(|validator| {
                let mut wire = Vec::new();
                Validator {
                    pub_key: validator.pub_key.clone(),
                    voting_power: validator.voting_power as u64,
                }
                .encode(&mut wire)
                .unwrap();
                wire
            })
            .collect();
        simple_hash_from_byte_vectors(validator_bytes)
    }

    fn hash_header(sh: &SignedHeader) -> Hash {
        let header = sh.header.as_ref().unwrap();
        let mut fields_bytes: Vec<Vec<u8>> = Vec::with_capacity(14);
        fields_bytes.push({
            let mut wire = Vec::new();
            header.version.as_ref().unwrap().encode(&mut wire).unwrap();
            wire
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.chain_id.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.height.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.time.as_ref().unwrap().encode(&mut wire).unwrap();
            wire
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.num_txs.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire.push(0);
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.total_txs.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire.push(0);
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header
                .last_block_id
                .as_ref()
                .unwrap()
                .encode(&mut wire)
                .unwrap();
            wire
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.last_commit_hash.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.data_hash.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.validators_hash.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.next_validators_hash.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.consensus_hash.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.app_hash.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.last_results_hash.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.evidence_hash.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        fields_bytes.push({
            let mut wire = Vec::new();
            header.proposer_address.encode(&mut wire).unwrap();
            if wire.is_empty() {
                wire
            } else {
                wire[1..].to_vec()
            }
        });
        simple_hash_from_byte_vectors(fields_bytes)
    }

    fn header_matches_commit(signed_header: &SignedHeader) -> Result<(), &'static str> {
        let header_hash = TmHeaderVerifier::hash_header(&signed_header);

        if header_hash.to_vec()
            != signed_header
                .commit
                .as_ref()
                .unwrap()
                .block_id
                .as_ref()
                .unwrap()
                .hash
        {
            return Err("InvalidCommitValue");
        }
        Ok(())
    }

    fn valid_commit(
        signed_header: &SignedHeader,
        validators: &ValidatorSet,
    ) -> Result<(), &'static str> {
        TmHeaderVerifier::valid_commit_basic(signed_header, validators)?;
        TmHeaderVerifier::validate_commit_full(signed_header, validators)?;
        Ok(())
    }

    fn valid_commit_basic(
        signed_header: &SignedHeader,
        validator_set: &ValidatorSet,
    ) -> Result<(), &'static str> {
        let signatures = &signed_header.commit.as_ref().unwrap().signatures;

        // Check that that the number of signatures matches the number of validators.
        if signatures.len() != validator_set.validators.len() {
            return Err("pre-commit length doesn't match validator length");
        }
        Ok(())
    }

    fn validate_commit_full(
        signed_header: &SignedHeader,
        validator_set: &ValidatorSet,
    ) -> Result<(), &'static str> {
        for commit_sig in signed_header.commit.as_ref().unwrap().signatures.iter() {
            let validator_address = &commit_sig.validator_address;
            if validator_address.is_empty() {
                continue;
            }
            if validator_set
                .validators
                .iter()
                .find(|val| &val.address == validator_address)
                .cloned()
                == None
            {
                return Err("Found a faulty signer not present in the validator set ");
            }
        }

        Ok(())
    }

    fn verify_sufficient_signers_overlap(untrusted_sh: &LightBlock) -> Result<(), &'static str> {
        let mut vals = vec![];
        for v in untrusted_sh
            .validator_set
            .as_ref()
            .unwrap()
            .validators
            .clone()
        {
            vals.push(Validator {
                pub_key: v.pub_key,
                voting_power: v.voting_power as u64,
            })
        }
        TmHeaderVerifier::verify_sufficient_validators_overlap(
            &untrusted_sh.signed_header.as_ref().unwrap(),
            &vals,
        )?;
        Ok(())
    }

    fn verify_sufficient_validators_overlap(
        signed_header: &SignedHeader,
        validator_set: &Vec<Validator>,
    ) -> Result<(), &'static str> {
        let signatures = &signed_header.commit.as_ref().unwrap().signatures;
        let chain_id = signed_header.header.as_ref().unwrap().chain_id.to_string();

        let mut tallied_voting_power = 0_u64;
        let mut seen_validators = HashSet::new();
        let non_absent_votes = signatures.iter().enumerate().flat_map(|(_, signature)| {
            if let Some(vote) = TmHeaderVerifier::non_absent_vote(
                signature,
                chain_id.clone(),
                &signed_header.commit.as_ref().unwrap(),
            ) {
                Some((signature, vote))
            } else {
                None
            }
        });

        for (signature, vote) in non_absent_votes {
            // Ensure we only count a validator's power once
            let addr_id: AccountId = signature.validator_address.clone().try_into().unwrap();
            if !seen_validators.contains(&addr_id) {
                seen_validators.insert(addr_id);
            } else {
                return Err("Duplicate Validator");
            }

            let validator = match validator_set
                .iter()
                .find(|val| {
                    let digest = Sha256::digest(&val.pub_key);
                    let mut hash_bytes = [0u8; SHA256_HASH_SIZE];
                    hash_bytes.copy_from_slice(&digest);
                    hash_bytes[..20].to_vec() == signature.validator_address.clone()
                })
                .cloned()
            {
                Some(validator) => validator,
                None => continue, // Cannot find matching validator, so we skip the vote
            };

            // Check vote is valid
            let mut sign_bytes = Vec::new();
            vote.encode_length_delimited(&mut sign_bytes).unwrap();

            let pubkey = PublicKey::from_raw_ed25519(validator.pub_key.as_slice()).unwrap();
            if pubkey
                .verify(
                    &sign_bytes,
                    &signature.signature.clone().try_into().unwrap(),
                )
                .is_err()
            {
                return Err("InvalidSignature");
            }

            tallied_voting_power += validator.voting_power;
        }

        let total_voting_power = validator_set
            .iter()
            .fold(0u64, |total, val_info| total + val_info.voting_power);

        if tallied_voting_power * 3 <= total_voting_power * 2 {
            return Err("No enough voting power");
        }

        Ok(())
    }

    fn non_absent_vote(
        commit_sig: &CommitSig,
        chain_id: String,
        commit: &Commit,
    ) -> Option<RawCanonicalVote> {
        if commit_sig.vote_type != 2 {
            return None;
        }
        let timestamp = &commit_sig.timestamp;
        let block_id = &commit.block_id.as_ref().unwrap();
        let mut h = [0u8; SHA256_HASH_SIZE];
        h.copy_from_slice(&block_id.hash.as_slice());
        let mut ph = [0u8; SHA256_HASH_SIZE];
        ph.copy_from_slice(&block_id.part_set_header.as_ref().unwrap().hash.as_slice());
        let p = CanonicalPartSetHeader {
            total: block_id.part_set_header.as_ref().unwrap().total,
            hash: ph.to_vec(),
        };
        Some(RawCanonicalVote {
            signed_msg_type: commit_sig.vote_type,
            height: commit_sig.height,
            round: commit_sig.round as i64,
            block_id: Some(CanonicalBlockId {
                hash: h.to_vec(),
                part_set_header: Some(p),
            }),
            timestamp: timestamp.clone(),
            chain_id,
        })
    }

    fn decode_tendermint_header_validation_input(input: &[u8]) -> Result<HeaderCs, &'static str> {
        let cs_len = BigEndian::read_u64(
            &input[CONSENSUS_STATE_LENGTH_BYTES_LENGTH - UINT64_TYPE_LENGTH
                ..CONSENSUS_STATE_LENGTH_BYTES_LENGTH],
        ) as usize;
        let input_length: usize = input.len();
        if input_length <= CONSENSUS_STATE_LENGTH_BYTES_LENGTH + cs_len {
            panic!("invalid consensus length")
        }
        let cs = TmHeaderVerifier::decode_consensus_state(
            &input
                [CONSENSUS_STATE_LENGTH_BYTES_LENGTH..CONSENSUS_STATE_LENGTH_BYTES_LENGTH + cs_len],
        )?;
        let header = TmHeaderVerifier::decode_header(
            &input[CONSENSUS_STATE_LENGTH_BYTES_LENGTH + cs_len..],
        )?;

        return Ok(HeaderCs { cs, header });
    }

    fn decode_header(input: &[u8]) -> Result<LightBlock, &'static str> {
        let header = LightBlock::decode_length_delimited(input).unwrap();
        return Ok(header);
    }

    fn decode_consensus_state(input: &[u8]) -> Result<ConsensusState, &'static str> {
        let minimum_length: usize =
            CHAIN_ID_LENGTH + HEIGHT_LENGTH + APP_HASH_LENGTH + VALIDATOR_SET_HASH_LENGTH;
        let single_validator_bytes_length: usize =
            VALIDATOR_PUBKEY_LENGTH + VALIDATOR_VOTING_POWER_LENGTH;
        let input_length: usize = input.len();

        if input_length <= minimum_length
            || (input_length - minimum_length) % single_validator_bytes_length != 0
        {
            return Err("unexpected payload size");
        }

        let mut pos: usize = 0;
        let chain_id = input[pos..pos + CHAIN_ID_LENGTH].trim_with(|c| c == '\x00');
        let chain_id_str = String::from_utf8_lossy(chain_id);
        pos = pos + CHAIN_ID_LENGTH;

        let height: u64 = BigEndian::read_u64(&input[pos..pos + HEIGHT_LENGTH]);
        pos = pos + HEIGHT_LENGTH;

        let mut app_hash: [u8; APP_HASH_LENGTH] = [0; APP_HASH_LENGTH];
        app_hash.copy_from_slice(&input[pos..pos + APP_HASH_LENGTH]);
        pos = pos + APP_HASH_LENGTH;

        let mut cur_validator_set_hash: [u8; VALIDATOR_SET_HASH_LENGTH] =
            [0; VALIDATOR_SET_HASH_LENGTH];
        cur_validator_set_hash.copy_from_slice(&input[pos..pos + VALIDATOR_SET_HASH_LENGTH]);
        pos = pos + VALIDATOR_SET_HASH_LENGTH;

        let next_validator_set_size: usize =
            (input_length - minimum_length) / single_validator_bytes_length;

        let mut next_validator_set: Vec<Validator> = Vec::new();
        for index in 0..next_validator_set_size {
            let mut start_pos: usize = pos + index * single_validator_bytes_length;

            let mut pub_key_bytes: [u8; VALIDATOR_PUBKEY_LENGTH] = [0; VALIDATOR_PUBKEY_LENGTH];
            pub_key_bytes.copy_from_slice(&input[start_pos..start_pos + VALIDATOR_PUBKEY_LENGTH]);
            start_pos = start_pos + VALIDATOR_PUBKEY_LENGTH;

            let voting_power: u64 =
                BigEndian::read_u64(&input[start_pos..start_pos + VALIDATOR_VOTING_POWER_LENGTH]);

            let validator = Validator {
                pub_key: pub_key_bytes.to_vec(),
                voting_power,
            };
            next_validator_set.push(validator);
        }

        let consensus_state = ConsensusState {
            chain_id: chain_id_str.to_string(),
            height,
            app_hash: app_hash.to_vec(),
            cur_validator_set_hash: cur_validator_set_hash.to_vec(),
            next_validator_set,
        };
        Ok(consensus_state)
    }
}

#[cfg(test)]
mod test {
    use crate::lite::light_client::TmHeaderVerifier;
    use parity_bytes::BytesRef;
    use prost_amino::Message as _;

    use tendermint_proto::crypto::CanonicalVote;
    use tendermint_proto::crypto::LightBlock;

    #[test]
    fn test_verify_execute() {
        let input = hex::decode("0000000000000000000000000000000000000000000000000000000000001325000000000000000000000000000000000000000000000000000000000000022042696e616e63652d436861696e2d4e696c6500000000000000000000000000000000000003fc05e2b7029751d2a6581efc2f79712ec44d8b4981850325a7feadaa58ef4ddaa18a9380d9ab0fc10d18ca0e0832d5f4c063c5489ec1443dfb738252d038a82131b27ae17cbe9c20cdcfdf876b3b12978d3264a007fcaaa71c4cdb701d9ebc0323f44f000000174876e800184e7b103d34c41003f9b864d5f8c1adda9bd0436b253bb3c844bc739c1e77c9000000174876e8004d420aea843e92a0cfe69d89696dff6827769f9cb52a249af537ce89bf2a4b74000000174876e800bd03de9f8ab29e2800094e153fac6f696cfa512536c9c2f804dcb2c2c4e4aed6000000174876e8008f4a74a07351895ddf373057b98fae6dfaf2cd21f37a063e19601078fe470d53000000174876e8004a5d4753eb79f92e80efe22df7aca4f666a4f44bf81c536c4a09d4b9c5b654b5000000174876e800c80e9abef7ff439c10c68fe8f1303deddfc527718c3b37d8ba6807446e3c827a000000174876e8009142afcc691b7cc05d26c7b0be0c8b46418294171730e079f384fde2fa50bafc000000174876e80049b288e4ebbb3a281c2d546fc30253d5baf08993b6e5d295fb787a5b314a298e000000174876e80004224339688f012e649de48e241880092eaa8f6aa0f4f14bfcf9e0c76917c0b6000000174876e8004034b37ceda8a0bf13b1abaeee7a8f9383542099a554d219b93d0ce69e3970e8000000174876e800e3210a92130abb020a02080a121242696e616e63652d436861696e2d4e696c6518e38bf01f220c08e191aef20510f5f4e4c70230dae0c7173a480a20102b54820dd8fb5bc2c4e875ee573fa294d9b7b7ceb362aa8fd21b33dee41b1c12240801122082f341511f3e6b89d6177fd31f8a106013ba09d6e12ef40a7dec885d81b687634220b1b77e6977e0cd0177e3102a78833c9e152aa646ed4fb5a77e8af58c9867eec0522080d9ab0fc10d18ca0e0832d5f4c063c5489ec1443dfb738252d038a82131b27a5a2080d9ab0fc10d18ca0e0832d5f4c063c5489ec1443dfb738252d038a82131b27a6220294d8fbd0b94b767a7eba9840f299a3586da7fe6b5dead3b7eecba193c400f936a20a3e248bc209955054d880e4d89ff3c0419c0cd77681f4b4c6649ead5545054b982011462633d9db7ed78e951f79913fdc8231aa77ec12b12d1100a480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be212b601080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef20510cebfe23e321406fd60078eb4c2356137dd50036597db267cf61642409276f20ad4b152f91c344bd63ac691bad66e04e228a8b58dca293ff0bd10f8aef6dfbcecae49e32b09d89e10b771a6c01628628596a95e126b04763560c66c0f12b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef20510a4caa532321418e69cc672973992bb5f76d049a5b2c5ddf77436380142409ed2b74fa835296d552e68c439dd4ee3fa94fb197282edcc1cc815c863ca42a2c9a73475ff6be9064371a61655a3c31d2f0acc89c3a4489ad4c2671aef52360512b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef20510a69eca2f3214344c39bb8f4512d6cab1f6aafac1811ef9d8afdf38024240de2768ead90011bcbb1914abc1572749ab7b81382eb81cff3b41c56edc12470a7b8a4d61f8b4ca7b2cb7e24706edd219455796b4db74cd36965859f91dc8910312b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef20510dcdd833b321437ef19af29679b368d2b9e9de3f8769b357866763803424072ddfe0aeb13616b3f17eb60b19a923ec51fcc726625094aa069255c829c8cdd9e242080a1e559b0030fe9a0db19fd34e392bd78df12a9caff9f2b811bc1ac0a12b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef20510e9f2f859321462633d9db7ed78e951f79913fdc8231aa77ec12b38044240f5f61c640ab2402b44936de0d24e7b439df78bc3ef15467ecb29b92ece4aa0550790d5ce80761f2ac4b0e3283969725c42343749d9b44b179b2d4fced66c5d0412b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef20510ff90f55532147b343e041ca130000a8bc00c35152bd7e774003738054240df6e298b3efd42eb536e68a0210bc921e8b5dc145fe965f63f4d3490064f239f2a54a6db16c96086e4ae52280c04ad8b32b44f5ff3d41f0c364949ccb628c50312b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef20510cad7c931321491844d296bd8e591448efc65fd6ad51a888d58fa3806424030298627da1afd28229aac150f553724b594989e59136d6a175d84e45a4dee344ff9e0eeb69fdf29abb6d833adc3e1ccdc87b2a65019ef5fb627c44d9d132c0012b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef20510c8c296323214b3727172ce6473bc780298a2d66c12f1a14f5b2a38074240918491100730b4523f0c85409f6d1cca9ebc4b8ca6df8d55fe3d85158fa43286608693c50332953e1d3b93e3e78b24e158d6a2275ce8c6c7c07a7a646a19200312b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef2051086f1a2403214b6f20c7faa2b2f6f24518fa02b71cb5f4a09fba338084240ca59c9fc7f6ab660e9970fc03e5ed588ccb8be43fe5a3e8450287b726f29d039e53fe888438f178ac63c3d2ca969cd8c2fbc8606f067634339b6a94a7382960212b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef2051080efbb543214e0dd72609cc106210d1aa13936cb67b93a0aee2138094240e787a21f5cb7052624160759a9d379dd9db144f2b498bca026375c9ce8ecdc2a0936af1c309b3a0f686c92bf5578b595a4ca99036a19c9fc50d3718fd454b30012b801080210e38bf01f22480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f122408011220d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be22a0b08e291aef20510ddf8d85a3214fc3108dc3814888f4187452182bc1baf83b71bc9380a4240d51ea31f6449eed71de22339722af1edbb0b21401037d85882b32a2ed8ae9127f2df4d1da2092729e582812856227ed6cdf98a3f60203d1ff80bd635fb03bb0912a4070a4f0a1406fd60078eb4c2356137dd50036597db267cf61612251624de6420e17cbe9c20cdcfdf876b3b12978d3264a007fcaaa71c4cdb701d9ebc0323f44f1880d0dbc3f4022080e0ebdaf2e2ffffff010a4b0a1418e69cc672973992bb5f76d049a5b2c5ddf7743612251624de6420184e7b103d34c41003f9b864d5f8c1adda9bd0436b253bb3c844bc739c1e77c91880d0dbc3f4022080d0dbc3f4020a4b0a14344c39bb8f4512d6cab1f6aafac1811ef9d8afdf12251624de64204d420aea843e92a0cfe69d89696dff6827769f9cb52a249af537ce89bf2a4b741880d0dbc3f4022080d0dbc3f4020a4b0a1437ef19af29679b368d2b9e9de3f8769b3578667612251624de6420bd03de9f8ab29e2800094e153fac6f696cfa512536c9c2f804dcb2c2c4e4aed61880d0dbc3f4022080d0dbc3f4020a4b0a1462633d9db7ed78e951f79913fdc8231aa77ec12b12251624de64208f4a74a07351895ddf373057b98fae6dfaf2cd21f37a063e19601078fe470d531880d0dbc3f4022080d0dbc3f4020a4b0a147b343e041ca130000a8bc00c35152bd7e774003712251624de64204a5d4753eb79f92e80efe22df7aca4f666a4f44bf81c536c4a09d4b9c5b654b51880d0dbc3f4022080d0dbc3f4020a4b0a1491844d296bd8e591448efc65fd6ad51a888d58fa12251624de6420c80e9abef7ff439c10c68fe8f1303deddfc527718c3b37d8ba6807446e3c827a1880d0dbc3f4022080d0dbc3f4020a4b0a14b3727172ce6473bc780298a2d66c12f1a14f5b2a12251624de64209142afcc691b7cc05d26c7b0be0c8b46418294171730e079f384fde2fa50bafc1880d0dbc3f4022080d0dbc3f4020a4b0a14b6f20c7faa2b2f6f24518fa02b71cb5f4a09fba312251624de642049b288e4ebbb3a281c2d546fc30253d5baf08993b6e5d295fb787a5b314a298e1880d0dbc3f4022080d0dbc3f4020a4b0a14e0dd72609cc106210d1aa13936cb67b93a0aee2112251624de642004224339688f012e649de48e241880092eaa8f6aa0f4f14bfcf9e0c76917c0b61880d0dbc3f4022080d0dbc3f4020a4b0a14fc3108dc3814888f4187452182bc1baf83b71bc912251624de64204034b37ceda8a0bf13b1abaeee7a8f9383542099a554d219b93d0ce69e3970e81880d0dbc3f4022080d0dbc3f402124f0a1406fd60078eb4c2356137dd50036597db267cf61612251624de6420e17cbe9c20cdcfdf876b3b12978d3264a007fcaaa71c4cdb701d9ebc0323f44f1880d0dbc3f4022080e0ebdaf2e2ffffff011aa4070a4f0a1406fd60078eb4c2356137dd50036597db267cf61612251624de6420e17cbe9c20cdcfdf876b3b12978d3264a007fcaaa71c4cdb701d9ebc0323f44f1880d0dbc3f4022080e0ebdaf2e2ffffff010a4b0a1418e69cc672973992bb5f76d049a5b2c5ddf7743612251624de6420184e7b103d34c41003f9b864d5f8c1adda9bd0436b253bb3c844bc739c1e77c91880d0dbc3f4022080d0dbc3f4020a4b0a14344c39bb8f4512d6cab1f6aafac1811ef9d8afdf12251624de64204d420aea843e92a0cfe69d89696dff6827769f9cb52a249af537ce89bf2a4b741880d0dbc3f4022080d0dbc3f4020a4b0a1437ef19af29679b368d2b9e9de3f8769b3578667612251624de6420bd03de9f8ab29e2800094e153fac6f696cfa512536c9c2f804dcb2c2c4e4aed61880d0dbc3f4022080d0dbc3f4020a4b0a1462633d9db7ed78e951f79913fdc8231aa77ec12b12251624de64208f4a74a07351895ddf373057b98fae6dfaf2cd21f37a063e19601078fe470d531880d0dbc3f4022080d0dbc3f4020a4b0a147b343e041ca130000a8bc00c35152bd7e774003712251624de64204a5d4753eb79f92e80efe22df7aca4f666a4f44bf81c536c4a09d4b9c5b654b51880d0dbc3f4022080d0dbc3f4020a4b0a1491844d296bd8e591448efc65fd6ad51a888d58fa12251624de6420c80e9abef7ff439c10c68fe8f1303deddfc527718c3b37d8ba6807446e3c827a1880d0dbc3f4022080d0dbc3f4020a4b0a14b3727172ce6473bc780298a2d66c12f1a14f5b2a12251624de64209142afcc691b7cc05d26c7b0be0c8b46418294171730e079f384fde2fa50bafc1880d0dbc3f4022080d0dbc3f4020a4b0a14b6f20c7faa2b2f6f24518fa02b71cb5f4a09fba312251624de642049b288e4ebbb3a281c2d546fc30253d5baf08993b6e5d295fb787a5b314a298e1880d0dbc3f4022080d0dbc3f4020a4b0a14e0dd72609cc106210d1aa13936cb67b93a0aee2112251624de642004224339688f012e649de48e241880092eaa8f6aa0f4f14bfcf9e0c76917c0b61880d0dbc3f4022080d0dbc3f4020a4b0a14fc3108dc3814888f4187452182bc1baf83b71bc912251624de64204034b37ceda8a0bf13b1abaeee7a8f9383542099a554d219b93d0ce69e3970e81880d0dbc3f4022080d0dbc3f402124f0a1406fd60078eb4c2356137dd50036597db267cf61612251624de6420e17cbe9c20cdcfdf876b3b12978d3264a007fcaaa71c4cdb701d9ebc0323f44f1880d0dbc3f4022080e0ebdaf2e2ffffff01").unwrap();

        let mut data = vec![];

        let valid = TmHeaderVerifier::execute(&input[..], &mut BytesRef::Flexible(&mut data));
        let res = hex::encode(&data);
        assert!(valid.is_ok());
        assert_eq!(res,"000000000000000000000000000000000000000000000000000000000000022042696e616e63652d436861696e2d4e696c6500000000000000000000000000000000000003fc05e3a3e248bc209955054d880e4d89ff3c0419c0cd77681f4b4c6649ead5545054b980d9ab0fc10d18ca0e0832d5f4c063c5489ec1443dfb738252d038a82131b27ae17cbe9c20cdcfdf876b3b12978d3264a007fcaaa71c4cdb701d9ebc0323f44f000000174876e800184e7b103d34c41003f9b864d5f8c1adda9bd0436b253bb3c844bc739c1e77c9000000174876e8004d420aea843e92a0cfe69d89696dff6827769f9cb52a249af537ce89bf2a4b74000000174876e800bd03de9f8ab29e2800094e153fac6f696cfa512536c9c2f804dcb2c2c4e4aed6000000174876e8008f4a74a07351895ddf373057b98fae6dfaf2cd21f37a063e19601078fe470d53000000174876e8004a5d4753eb79f92e80efe22df7aca4f666a4f44bf81c536c4a09d4b9c5b654b5000000174876e800c80e9abef7ff439c10c68fe8f1303deddfc527718c3b37d8ba6807446e3c827a000000174876e8009142afcc691b7cc05d26c7b0be0c8b46418294171730e079f384fde2fa50bafc000000174876e80049b288e4ebbb3a281c2d546fc30253d5baf08993b6e5d295fb787a5b314a298e000000174876e80004224339688f012e649de48e241880092eaa8f6aa0f4f14bfcf9e0c76917c0b6000000174876e8004034b37ceda8a0bf13b1abaeee7a8f9383542099a554d219b93d0ce69e3970e8000000174876e800");
    }
    #[test]
    fn test_decode_encode() {
        let input = hex::decode("4e0a1f0a141203616263220b088cca9f800610b8d48766306412070a050a0301020312290a2712251624de642001010101010101010101010101010101010101010101010101010101010101011a00").unwrap();
        let light_block: LightBlock = LightBlock::decode_length_delimited(&input[..]).unwrap();
        let mut wire = Vec::new();
        light_block.encode_length_delimited(&mut wire).unwrap();
        assert_eq!(wire, input);

        let input1 =hex::decode("76080211e305fc030000000022480a207eaabf7df1081377e06e08efe7ad17974049380bdd65a9b053c099ef80ff6e6f12240a20d153cc308d9cb96ca43ffeceaae1ee85794c83d17408ff76cfee92f5e91d0be210012a0b08e291aef20510cebfe23e321242696e616e63652d436861696e2d4e696c65").unwrap();
        let vote: CanonicalVote = CanonicalVote::decode_length_delimited(&input1[..]).unwrap();
        println!("{:?}", vote);
    }
}
