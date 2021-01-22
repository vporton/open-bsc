//! Iavl proofs
use crate::{
    hash::SHA256_HASH_SIZE,
    merkle::{simple_hash_from_byte_vectors, Hash},
    serializers, Error,
};
use bstr::ByteSlice;
use byteorder::{BigEndian, ReadBytesExt};
use parity_bytes::BytesRef;
use prost_amino::{encoding::encode_varint, Message as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering::Equal, convert::TryFrom, io::Cursor};
use tendermint_proto::{
    crypto::{
        IavlValueProofOp, MultiStoreProof, MultiStoreProofOp, PathToLeaf, ProofInnerNode,
        ProofLeafNode, ProofOp as RawProofOp, ProofOps as RawProofOps, RangeProof, StoreInfo,
    },
    Protobuf,
};

const PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH: usize = 32;
const MERKLE_PROOF_VALIDATE_RESULT_LENGTH: usize = 32;
const UINT64_TYPE_LENGTH: usize = 8;

const STORE_NAME_LENGTH_BYTES_LENGTH: usize = 32;
const APP_HASH_LENGTH: usize = 32;
const KEY_LENGTH_BYTES_LENGTH: usize = 32;
const VALUE_LENGTH_BYTES_LENGTH: usize = 32;

/// Proof is Merkle proof defined by the list of ProofOps
/// <https://github.com/tendermint/tendermint/blob/c8483531d8e756f7fbb812db1dd16d841cdf298a/crypto/merkle/merkle.proto#L26>
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    /// The list of ProofOps
    pub ops: Vec<ProofOp>,
}

/// ProofOp defines an operation used for calculating Merkle root
/// The data could be arbitrary format, providing necessary data
/// for example neighbouring node hash
/// <https://github.com/tendermint/tendermint/blob/c8483531d8e756f7fbb812db1dd16d841cdf298a/crypto/merkle/merkle.proto#L19>
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ProofOp {
    /// Type of the ProofOp
    #[serde(alias = "type")]
    pub field_type: String,
    /// Key of the ProofOp
    #[serde(default, with = "serializers::bytes::base64string")]
    pub key: Vec<u8>,
    /// Actual data
    #[serde(default, with = "serializers::bytes::base64string")]
    pub data: Vec<u8>,
}

impl Protobuf<RawProofOp> for ProofOp {}

impl TryFrom<RawProofOp> for ProofOp {
    type Error = Error;

    fn try_from(value: RawProofOp) -> Result<Self, Self::Error> {
        Ok(Self {
            field_type: value.r#type,
            key: value.key,
            data: value.data,
        })
    }
}

impl From<ProofOp> for RawProofOp {
    fn from(value: ProofOp) -> Self {
        RawProofOp {
            r#type: value.field_type,
            key: value.key,
            data: value.data,
        }
    }
}

impl Protobuf<RawProofOps> for Proof {}

impl TryFrom<RawProofOps> for Proof {
    type Error = Error;

    fn try_from(value: RawProofOps) -> Result<Self, Self::Error> {
        let ops: Result<Vec<ProofOp>, _> = value.ops.into_iter().map(ProofOp::try_from).collect();

        Ok(Self { ops: ops? })
    }
}

impl From<Proof> for RawProofOps {
    fn from(value: Proof) -> Self {
        let ops: Vec<RawProofOp> = value.ops.into_iter().map(RawProofOp::from).collect();

        RawProofOps { ops }
    }
}

trait NodeHash {
    fn node_hash(&self) -> Hash;
    fn child_node_hash(&self, child_hash: Hash) -> Hash;
}

impl NodeHash for ProofInnerNode {
    fn node_hash(&self) -> Hash {
        unimplemented!()
    }

    fn child_node_hash(&self, child_hash: Hash) -> Hash {
        let mut inner_bytes: Vec<u8> = Vec::with_capacity(100);
        let mut h = (self.height as u64) << 1;
        if self.height < 0 {
            h = !h;
        }
        encode_varint(h, &mut inner_bytes);
        encode_varint((self.size as u64) << 1, &mut inner_bytes);
        encode_varint((self.version as u64) << 1, &mut inner_bytes);
        if self.left.is_empty() {
            encode_varint(child_hash.len() as u64, &mut inner_bytes);
            inner_bytes.extend_from_slice(&child_hash[..]);
            encode_varint(self.right.len() as u64, &mut inner_bytes);
            inner_bytes.extend_from_slice(&self.right);
        } else {
            encode_varint(self.left.len() as u64, &mut inner_bytes);
            inner_bytes.extend_from_slice(&self.left);
            encode_varint(child_hash.len() as u64, &mut inner_bytes);
            inner_bytes.extend_from_slice(&child_hash[..]);
        }
        let digest = Sha256::digest(&inner_bytes);
        let mut hash_bytes = [0u8; SHA256_HASH_SIZE];
        hash_bytes.copy_from_slice(&digest);
        hash_bytes
    }
}

fn compute_path_leaf_hash(path_to_leaf: &PathToLeaf, leaf: &ProofLeafNode) -> Hash {
    let mut hash = leaf.node_hash();
    let n = path_to_leaf.inners.len();
    for i in 0..n {
        let pin = path_to_leaf.inners.get(n - i - 1).unwrap();
        hash = pin.child_node_hash(hash);
    }
    return hash;
}

impl NodeHash for ProofLeafNode {
    fn node_hash(&self) -> Hash {
        let mut leaf_bytes: Vec<u8> = Vec::with_capacity(100);
        encode_varint(0_u64, &mut leaf_bytes);
        encode_varint(1_u64 << 1, &mut leaf_bytes);
        encode_varint((self.version as u64) << 1, &mut leaf_bytes);
        encode_varint(self.key.len() as u64, &mut leaf_bytes);
        leaf_bytes.extend_from_slice(&self.key);
        encode_varint(self.value_hash.len() as u64, &mut leaf_bytes);
        leaf_bytes.extend_from_slice(&self.value_hash);
        let digest = Sha256::digest(&leaf_bytes);

        // copy the GenericArray out
        let mut hash_bytes = [0u8; SHA256_HASH_SIZE];
        hash_bytes.copy_from_slice(&digest);
        hash_bytes
    }

    fn child_node_hash(&self, _: Hash) -> Hash {
        unimplemented!()
    }
}

trait ProofExecute {
    fn run(&self, value: Vec<u8>, key: Vec<u8>) -> Result<Hash, &'static str>;
}

struct RangeProofVerifier {
    proof: RangeProof,
}

struct MultiStoreProofVerifier {
    proof: MultiStoreProof,
}

impl MultiStoreProofVerifier {
    fn store_info_hash(s: &StoreInfo) -> Hash {
        let mut wire = Vec::new();
        s.core
            .as_ref()
            .unwrap()
            .encode_length_delimited(&mut wire)
            .unwrap();
        let tmp_hash = Sha256::digest(wire.as_slice());
        let mut hash = [0u8; SHA256_HASH_SIZE];
        hash.copy_from_slice(&tmp_hash);
        hash
    }
    pub fn compute_root_hash(&mut self) -> Result<Hash, &'static str> {
        let mut kvs = Vec::new();
        struct KVPair {
            key: Vec<u8>,
            value: Vec<u8>,
        }
        for store in self.proof.store_infos.iter() {
            let tmp_hash = Sha256::digest(
                MultiStoreProofVerifier::store_info_hash(&store)
                    .to_vec()
                    .as_slice(),
            );
            let mut store_hash = [0u8; SHA256_HASH_SIZE];
            store_hash.copy_from_slice(&tmp_hash);
            kvs.push(KVPair {
                key: store.name.clone().into_bytes(),
                value: store_hash.to_vec(),
            })
        }
        kvs.sort_by(|a, b| {
            let x = a.key.cmp(&b.key);
            if x == Equal {
                a.value.cmp(&b.value)
            } else {
                x
            }
        });

        let kvs_bytes: Vec<Vec<u8>> = kvs
            .iter()
            .map(|kv| {
                let mut kv_bytes: Vec<u8> = Vec::new();
                encode_varint(kv.key.len() as u64, &mut kv_bytes);
                kv_bytes.extend_from_slice(&kv.key);
                encode_varint(kv.value.len() as u64, &mut kv_bytes);
                kv_bytes.extend_from_slice(&kv.value);
                kv_bytes
            })
            .collect();

        Ok(simple_hash_from_byte_vectors(kvs_bytes))
    }
}

impl RangeProofVerifier {
    fn verify_item(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), &'static str> {
        let leaves = &self.proof.leaves;
        let i = match leaves.binary_search_by(|probe| probe.key.cmp(&key)) {
            Ok(index) => index,
            Err(index) => index,
        };
        let elemant = leaves.get(i).unwrap();
        if i >= leaves.len() || !elemant.key.eq(&key) {
            return Err("leaf key not found in proof");
        }
        let value_hash = Sha256::digest(value.as_slice());
        let mut hash_bytes = [0u8; SHA256_HASH_SIZE];
        hash_bytes.copy_from_slice(&value_hash);
        if !elemant.value_hash.eq(&hash_bytes) {
            return Err("leaf value hash not same");
        }
        return Ok(());
    }

    fn ite_compute_root_hash(
        leaves: &[ProofLeafNode],
        innersq: &Vec<PathToLeaf>,
        mut path: PathToLeaf,
    ) -> (Result<Hash, &'static str>, bool) {
        let nleaf = &leaves[0];
        let rleaves = &leaves[1..];

        let hash = compute_path_leaf_hash(&path, nleaf);
        if rleaves.is_empty() {
            return (Ok(hash), true);
        }
        while !path.inners.is_empty() {
            let rpath = path.inners[..path.inners.len() - 1].to_vec().clone();
            let lpath = path.inners[path.inners.len() - 1].clone();
            path.inners = rpath;
            if lpath.right.is_empty() {
                continue;
            }
            let inners: PathToLeaf = innersq[0].clone();
            let rinnersq = &innersq[1..].to_vec();
            let (derived_root, done) =
                RangeProofVerifier::ite_compute_root_hash(rleaves, rinnersq, inners);
            if derived_root.is_err() {
                return (derived_root, false);
            }
            if !derived_root.unwrap().eq(&lpath.right.as_slice()) {
                return (Err("intermediate root hash doesn't match"), false);
            }
            if done {
                return (Ok(hash), true);
            }
        }
        return (Ok(hash), false);
    }

    pub fn compute_root_hash(&mut self) -> Result<Hash, &'static str> {
        let leaves = self.proof.leaves.clone();
        if leaves.len() == 0 {
            return Err("no leaves");
        }
        if self.proof.inner_nodes.len() + 1 != leaves.len() {
            return Err("InnerNodes vs Leaves length mismatch, leaves should be 1 more.");
        }
        let ite_leaves = leaves.as_slice();
        let innersq = &self.proof.inner_nodes;
        let path = PathToLeaf {
            inners: self.proof.left_path.clone(),
        };
        let (root_hash, done) =
            RangeProofVerifier::ite_compute_root_hash(ite_leaves, innersq, path);
        if !done {
            return Err("left over leaves -- malformed proof");
        }
        return root_hash;
    }
}

impl ProofExecute for IavlValueProofOp {
    fn run(&self, value: Vec<u8>, key: Vec<u8>) -> Result<Hash, &'static str> {
        let mut verifier = RangeProofVerifier {
            proof: self.proof.as_ref().unwrap().clone(),
        };
        let root_hash = verifier.compute_root_hash()?;
        verifier.verify_item(key, value)?;
        return Ok(root_hash);
    }
}

impl ProofExecute for MultiStoreProofOp {
    fn run(&self, value: Vec<u8>, key: Vec<u8>) -> Result<Hash, &'static str> {
        let mut verifier = MultiStoreProofVerifier {
            proof: self.proof.as_ref().unwrap().clone(),
        };
        let root_hash = verifier.compute_root_hash()?;
        for si in self.proof.as_ref().unwrap().store_infos.iter() {
            if si.name.as_bytes() == key.as_slice() {
                if value == si.core.as_ref().unwrap().commit_id.as_ref().unwrap().hash {
                    return Ok(root_hash);
                }
                return Err("hash mismatch for substore");
            }
        }
        return Err("key not found in multistore proof");
    }
}

struct KeyValueMerkleProof {
    key: Vec<u8>,
    value: Vec<u8>,
    store_name: Vec<u8>,
    app_hash: Vec<u8>,
    proof: Proof,
}

impl KeyValueMerkleProof {
    fn validate(&self) -> bool {
        if self.value.len() == 0 {
            return false;
        }
        // expect multi store and iavl store
        if self.proof.ops.len() != 2 {
            return false;
        }
        // execute iavl store verify
        let iavl_op = self.proof.ops.get(0).unwrap();
        if iavl_op.field_type != "iavl:v" {
            return false;
        }
        let iavl_proof = IavlValueProofOp::decode_length_delimited(&iavl_op.data[..]).unwrap();
        let iavl_hash: Result<Hash, &'static str> =
            iavl_proof.run(self.value.clone(), self.key.clone());
        if iavl_hash.is_err() {
            return false;
        }
        let mul_op = self.proof.ops.get(1).unwrap();
        if mul_op.field_type != "multistore" {
            return false;
        }
        let mul_proof = MultiStoreProofOp::decode_length_delimited(&mul_op.data[..]).unwrap();
        let mul_root_hash: Result<Hash, &'static str> =
            mul_proof.run(iavl_hash.unwrap().to_vec(), self.store_name.clone());
        if mul_root_hash.is_err() {
            return false;
        }
        if mul_root_hash.unwrap().to_vec() != self.app_hash {
            return false;
        }
        return true;
    }
}

fn decode_key_value_merkle_proof(input: &[u8]) -> Result<KeyValueMerkleProof, &'static str> {
    let input_length = input.len();
    let mut pos = 0;
    if input_length
        <= STORE_NAME_LENGTH_BYTES_LENGTH
            + KEY_LENGTH_BYTES_LENGTH
            + VALUE_LENGTH_BYTES_LENGTH
            + APP_HASH_LENGTH
    {
        return Err("no enough input length");
    }
    let mut cursor = Cursor::new(input);
    let store_name = input[pos..pos + STORE_NAME_LENGTH_BYTES_LENGTH].trim_with(|c| c == '\x00');
    pos += STORE_NAME_LENGTH_BYTES_LENGTH;
    cursor.set_position((pos + KEY_LENGTH_BYTES_LENGTH - 8) as u64);
    let key_length = cursor.read_u64::<BigEndian>().unwrap();
    pos += KEY_LENGTH_BYTES_LENGTH;
    if input_length
        <= STORE_NAME_LENGTH_BYTES_LENGTH
            + KEY_LENGTH_BYTES_LENGTH
            + (key_length as usize)
            + VALUE_LENGTH_BYTES_LENGTH
    {
        return Err("invalid input, keyLength is too long");
    }
    let key = &input[pos..pos + key_length as usize];
    pos += key_length as usize;
    cursor.set_position((pos + VALUE_LENGTH_BYTES_LENGTH - 8) as u64);
    let value_length = cursor.read_u64::<BigEndian>().unwrap();
    pos += VALUE_LENGTH_BYTES_LENGTH;
    if input_length
        <= STORE_NAME_LENGTH_BYTES_LENGTH
            + KEY_LENGTH_BYTES_LENGTH
            + (key_length as usize)
            + VALUE_LENGTH_BYTES_LENGTH
            + (value_length as usize)
            + APP_HASH_LENGTH
    {
        return Err("invalid input, valueLength is too long");
    }
    let value = &input[pos..pos + (value_length as usize)];
    pos += value_length as usize;
    let app_hash = &input[pos..pos + APP_HASH_LENGTH];
    pos += APP_HASH_LENGTH;
    let proof_bytes = &input[pos..];
    let proof = Proof::decode(proof_bytes);
    if proof.is_err() {
        return Err("Decode proof failed");
    }
    Ok(KeyValueMerkleProof {
        key: key.to_vec(),
        value: value.to_vec(),
        store_name: store_name.to_vec(),
        app_hash: app_hash.to_vec(),
        proof: proof.unwrap(),
    })
}
/// Iavl proof verification
pub fn execute(input: &[u8], output: &mut BytesRef) -> Result<(), &'static str> {
    if input.len() <= PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH {
        return Err("invalid input: input should include 32 bytes payload length and payload");
    }
    let mut cursor = Cursor::new(input);
    cursor.set_position((PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH - UINT64_TYPE_LENGTH) as u64);
    let payload_length = cursor.read_u64::<BigEndian>().unwrap();
    if input.len() != ((payload_length as usize) + PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH) {
        return Err("invalid input: input size do not match");
    }
    let kvmp = decode_key_value_merkle_proof(&input[PRECOMPILE_CONTRACT_INPUT_METADATA_LENGTH..])?;
    let valid = kvmp.validate();
    if !valid {
        return Err("invalid merkle proof");
    }
    output.write(0, &[0_u8; MERKLE_PROOF_VALIDATE_RESULT_LENGTH - 1]);
    output.write(MERKLE_PROOF_VALIDATE_RESULT_LENGTH - 1, &[1_u8; 1]);
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{execute, Proof};
    use crate::test::test_serialization_roundtrip;
    use hex;
    use parity_bytes::BytesRef;

    #[test]
    fn test_proof_execute() {
        let input = hex::decode("00000000000000000000000000000000000000000000000000000000000007ae6962630000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0000010038020000000000019ce2000000000000000000000000000000000000000000000000000000000000009300000000000000000000000000000000000000000000000000000e35fa931a0000f870a0424e420000000000000000000000000000000000000000000000000000000000940000000000000000000000000000000000000000889bef94293405280094ef81397266e8021d967c3099aa8b781f8c3f99f2948ba31c21685c7ffa3cbb69cd837672dd5254cadb86017713ec8491cb58b672e759d5c7d9b6ac2d39568153aaa730c488acaa3d6097d774df0976900a91070a066961766c3a76120e0000010038020000000000019ce21af606f4060af1060a2d08121083bc0618cbcf954222206473c3fc09d3e700e4b8121ebedb8defedb38a57a11fa54300c7f537318c9b190a2d0811108f960418cbcf954222208b061ab760b6341a915696265ab0841f0657f0d0ad75c5bc08b5a92df9f6e84a0a2d081010c7d20118cbcf9542222091759ca6146640e0a33de7be5b53db2c69abf3eaf4b483a0b86cc8893d8853ce0a2c080f10c77318cbcf95422220d0d5c5c95b4e1d15b8cf01dfa68b3af6a846d549d7fb61eaed3ae6a256bd0e350a2c080e10c74318cbcf954222207183ccf5b70efc3e4c849c86ded15118819a46a9fb7eea5034fd477d56bf3c490a2c080d10c72b18cbcf954222205b5a92812ee771649fa4a53464ae7070adfd3aaea01140384bd9bfc11fe1ec400a2c080c10c71318cbcf95422220dc4d735d7096527eda97f96047ac42bcd53eee22c67a8e2f4ed3f581cb11851a0a2c080b10c70718cbcf95422a20b5d530b424046e1269950724735a0da5c402d8640ad4a0e65499b2d05bf7b87b0a2c080a10e40518cbcf95422220a51a3db12a79f3c809f63df49061ad40b7276a10a1a6809d9e0281cc35534b3f0a2c080910e40318cbcf9542222015eb48e2a1dd37ad88276cb04935d4d3b39eb993b24ee20a18a6c3d3feabf7200a2c080810e40118cbcf954222204c1b127f2e7b9b063ef3111479426a3b7a8fdea03b566a6f0a0decc1ef4584b20a2b0807106418cbcf95422220d17128bc7133f1f1159d5c7c82748773260d9a9958aa03f39a380e6a506435000a2b0806102418cbcf95422220959951e4ac892925994b564b54f7dcdf96be49e6167497b7c34aac7d8b3e11ac0a2b0805101418cbcf95422220e047c1f1c58944a27af737dcee1313dc501c4e2006663e835bcca9662ffd84220a2b0804100c18cbcf95422220ddf4258a669d79d3c43411bdef4161d7fc299f0558e204f4eda40a7e112007300a2b0803100818cbcf95422220e2ecce5e132eebd9d01992c71a2d5eb5d579b10ab162fc8a35f41015ab08ac750a2b0802100418cbcf9542222078a11f6a79afcc1e2e4abf6c62d5c1683cfc3bd9789d5fd4828f88a9e36a3b230a2b0801100218cbcf954222206d61aa355d7607683ef2e3fafa19d85eca227e417d68a8fdc6166dde4930fece1a370a0e0000010038020000000000019ce2122086295bb11ac7cba0a6fc3b9cfd165ea6feb95c37b6a2f737436a5d138f29e23f18cbcf95420af6050a0a6d756c746973746f726512036962631ae205e0050add050a330a06746f6b656e7312290a2708d6cf95421220789d2c8eac364abf32a2200e1d924a0e255703a162ee0c3ac2c37b347ae3daff0a0e0a0376616c12070a0508d6cf95420a320a057374616b6512290a2708d6cf954212207ebe9250eeae08171b95b93a0e685e8f25b9e2cce0464d2101f3e5607b76869e0a320a05706169727312290a2708d6cf95421220fe5e73b53ccd86f727122d6ae81aeab35f1e5338c4bdeb90e30fae57b202e9360a300a0369626312290a2708d6cf95421220af249eb96336e7498ffc266165a9716feb3363fc9560980804e491e181d8b5760a330a0662726964676512290a2708d6cf95421220bd239e499785b20d4a4c61862145d1f8ddf96c8e7e046d6679e4dfd4d38f98300a0f0a046d61696e12070a0508d6cf95420a300a0361636312290a2708d6cf954212208450d84a94122dcbf3a60b59b5f03cc13d0fee2cfe4740928457b885e9637f070a380a0b61746f6d69635f7377617012290a2708d6cf954212208d76e0bb011e064ad1964c1b322a0df526d24158e1f3189efbf5197818e711cb0a2f0a02736312290a2708d6cf95421220aebdaccfd22b92af6a0d9357232b91b342f068386e1ddc610f433d9feeef18480a350a08736c617368696e6712290a2708d6cf95421220fb0f9a8cf22cca3c756f8fefed19516ea27b6793d23a68ee85873b92ffddfac20a360a0974696d655f6c6f636b12290a2708d6cf95421220b40e4164b954e829ee8918cb3310ba691ea8613dc810bf65e77379dca70bf6ae0a330a06706172616d7312290a2708d6cf9542122024a0aa2cea5a4fd1b5f375fcf1e1318e5f49a5ff89209f18c12505f2d7b6ecb40a300a03676f7612290a2708d6cf95421220939b333eb64a437d398da930435d6ca6b0b1c9db810698f1734c141013c08e350a300a0364657812290a2708d6cf954212204fb5c65140ef175a741c8603efe98fc04871717d978e7dfb80a4a48e66d21e960a110a066f7261636c6512070a0508d6cf9542").unwrap();

        let mut output = [0u8; 32];

        let valid = execute(&input[..], &mut BytesRef::Fixed(&mut output[..]));
        assert!(valid.is_ok())
    }

    #[test]
    fn serialization_roundtrip() {
        let payload = r#"
        {
            "ops": [
                {
                    "type": "iavl:v",
                    "key": "Y29uc2Vuc3VzU3RhdGUvaWJjb25lY2xpZW50LzIy",
                    "data": "8QEK7gEKKAgIEAwYHCIgG9RAkJgHlxNjmyzOW6bUAidhiRSja0x6+GXCVENPG1oKKAgGEAUYFyIgwRns+dJvjf1Zk2BaFrXz8inPbvYHB7xx2HCy9ima5f8KKAgEEAMYFyogOr8EGajEV6fG5fzJ2fAAvVMgRLhdMJTzCPlogl9rxlIKKAgCEAIYFyIgcjzX/a+2bFbnNldpawQqZ+kYhIwz5r4wCUzuu1IFW04aRAoeY29uc2Vuc3VzU3RhdGUvaWJjb25lY2xpZW50LzIyEiAZ1uuG60K4NHJZZMuS9QX6o4eEhica5jIHYwflRiYkDBgX"
                },
                {
                    "type": "multistore",
                    "key": "aWJj",
                    "data": "CvEECjAKBGJhbmsSKAomCIjYAxIg2MEyyonbZButYnvSRkf2bPQg+nqA+Am1MeDxG6F4p1UKLwoDYWNjEigKJgiI2AMSIN2YHczeuXNvyetrSFQpkCcJzfB6PXVCw0i/XShMgPnIChEKB3VwZ3JhZGUSBgoECIjYAwovCgNnb3YSKAomCIjYAxIgYM0TfBli7KxhY4nWgDSDPykhUJwtKFql9RU5l86WinQKLwoDaWJjEigKJgiI2AMSIFp6aJASeInQKF8y824zjmgcFORN6M+ECbgFfJkobKs8CjAKBG1haW4SKAomCIjYAxIgsZzwmLQ7PH1UeZ/vCUSqlQmfgt3CGfoMgJLkUqKCv0EKMwoHc3Rha2luZxIoCiYIiNgDEiCiBZoBLyDGj5euy3n33ik+SpqYK9eB5xbI+iY8ycYVbwo0CghzbGFzaGluZxIoCiYIiNgDEiAJz3gEYuIhdensHU3b5qH5ons2quepd6EaRgCHXab6PQoyCgZzdXBwbHkSKAomCIjYAxIglWLA5/THPTiTxAlaLHOBYFIzEJTmKPznItUwAc8zD+AKEgoIZXZpZGVuY2USBgoECIjYAwowCgRtaW50EigKJgiI2AMSIMS8dZ1j8F6JVVv+hB1rHBZC+gIFJxHan2hM8qDC64n/CjIKBnBhcmFtcxIoCiYIiNgDEiB8VIzExUHX+SvHZFz/P9NM9THnw/gTDDLVReuZX8htLgo4CgxkaXN0cmlidXRpb24SKAomCIjYAxIg3u/Nd4L+8LT8OXJCh14o8PHIJ/GLQwsmE7KYIl1GdSYKEgoIdHJhbnNmZXISBgoECIjYAw=="
                }
            ]
        }"#;
        test_serialization_roundtrip::<Proof>(payload);
    }
}
