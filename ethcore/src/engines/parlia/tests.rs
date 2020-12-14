use parking_lot::RwLock;
use lru_cache::LruCache;
use engines::parlia::SNAP_CACHE_NUM;
use ethereum_types::U256;
use ethjson::hash::H256;
use engines::parlia::snapshot::Snapshot;
use std::collections::{HashMap, BTreeSet, BTreeMap};
use ethabi::Address;

// use_contract!(validator_ins, "res/contracts/bsc_validators.json");
//
// #[test]
// fn test() {
//     let x = Address::from_str("d46e8dd67c5d32be8058bb8eb970870f07244567").unwrap();
//     let data: Vec<u8> = validator_ins::functions::deposit::encode_input(x);
//     println!("{:x?}", data.to_hex());
// }

pub struct Snapshot1 {
    pub epoch: u64,
    pub number: u64,
    pub hash: H256,

    pub validators: BTreeSet<Address>,
    pub recents: BTreeMap<u64, Address>,
}
#[test]
fn test2() {
    // let recent_snaps:RwLock<LruCache<H256, Snapshot>> = RwLock::new(LruCache::new(SNAP_CACHE_NUM));
    // let mut snap_by_hash = recent_snaps.write();
    // let mut snap_by_hash = LruCache::new(SNAP_CACHE_NUM);
    // snap_by_hash.insert(H256(ethereum_types::H256::from(0)),Snapshot1{
    //     epoch: 0_u64,
    //     number: 0,
    //     hash: Default::default(),
    //     validators: Default::default(),
    //     recents: Default::default()
    // });
    println!("{}",std::u64::MAX / 2);

}
