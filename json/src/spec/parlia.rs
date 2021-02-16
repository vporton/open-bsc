// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

//! Parlia params deserialization.

use std::num::NonZeroU64;

/// Clique params deserialization.
#[derive(Debug, PartialEq, Deserialize)]
pub struct ParliaParams {
    /// Number of seconds between blocks to enforce
    pub period: Option<u64>,
    /// Epoch length to update validatorSet
    pub epoch: Option<NonZeroU64>,
}

/// Parlia engine deserialization.
#[derive(Debug, PartialEq, Deserialize)]
pub struct Parlia {
    /// CliqueEngine params
    pub params: ParliaParams,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn clique_deserialization() {
        let s = r#"{
			"params": {
				"period": 5,
				"epoch": 30000
			}
		}"#;

        let deserialized: Parlia = serde_json::from_str(s).unwrap();
        assert_eq!(deserialized.params.period, Some(5u64));
        assert_eq!(deserialized.params.epoch, NonZeroU64::new(30000));
    }
}
