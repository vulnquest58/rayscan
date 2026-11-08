//! Deterministic target sharding for distributed scans.
//!
//! Every target address is mapped to exactly one shard with a stable hash so
//! independent scan nodes can cover a large target set without coordination.
//! Combine the resulting reports with `rayscan merge`.

use std::net::IpAddr;

use crate::error::AppError;

/// Maximum number of shards accepted by [`validate`].
pub const MAX_SHARDS: usize = 1024;

/// Validate a shard selection.
pub fn validate(
    index: Option<usize>,
    count: Option<usize>,
) -> Result<Option<(usize, usize)>, AppError> {
    match (index, count) {
        (None, None) => Ok(None),
        (Some(index), Some(count)) => {
            if !(1..=MAX_SHARDS).contains(&count) {
                return Err(AppError::usage(format!(
                    "--shard-count must be between 1 and {MAX_SHARDS}"
                )));
            }
            if index >= count {
                return Err(AppError::usage(format!(
                    "--shard-index {index} is out of range for {count} shard(s)"
                )));
            }
            Ok(Some((index, count)))
        }
        _ => Err(AppError::usage(
            "--shard-index and --shard-count must be used together",
        )),
    }
}

/// Stable 64-bit FNV-1a hash used for shard placement.
fn hash_address(address: IpAddr) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let bytes = match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Return the shard index that owns `address`.
pub fn shard_for(address: IpAddr, count: usize) -> usize {
    debug_assert!(count > 0);
    (hash_address(address) % count as u64) as usize
}

/// Keep only the targets owned by shard `index` of `count`.
pub fn select(targets: Vec<IpAddr>, index: usize, count: usize) -> Vec<IpAddr> {
    targets
        .into_iter()
        .filter(|target| shard_for(*target, count) == index)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets() -> Vec<IpAddr> {
        (1..=200)
            .map(|last| format!("192.0.2.{last}").parse().unwrap())
            .collect()
    }

    #[test]
    fn shards_cover_every_target_exactly_once() {
        let all = targets();
        let count = 7;
        let mut combined = Vec::new();
        for index in 0..count {
            let shard = select(all.clone(), index, count);
            assert!(!shard.is_empty());
            for address in shard {
                assert_eq!(shard_for(address, count), index);
                combined.push(address);
            }
        }
        combined.sort();
        let mut expected = all;
        expected.sort();
        assert_eq!(combined, expected);
    }

    #[test]
    fn placement_is_stable_and_family_aware() {
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        let v6: IpAddr = "2001:db8::7".parse().unwrap();
        assert_eq!(shard_for(v4, 16), shard_for(v4, 16));
        assert_ne!(v4, v6);
        assert!(shard_for(v4, 16) < 16);
        assert!(shard_for(v6, 16) < 16);
    }

    #[test]
    fn validation_rejects_bad_selections() {
        assert!(validate(None, None).unwrap().is_none());
        assert!(validate(Some(0), Some(4)).unwrap().is_some());
        assert_eq!(validate(Some(4), Some(4)).unwrap_err().exit_code(), 2);
        assert_eq!(validate(Some(0), Some(0)).unwrap_err().exit_code(), 2);
        assert_eq!(
            validate(Some(0), Some(MAX_SHARDS + 1))
                .unwrap_err()
                .exit_code(),
            2
        );
        assert_eq!(validate(Some(0), None).unwrap_err().exit_code(), 2);
    }
}
