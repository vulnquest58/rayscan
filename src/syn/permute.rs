/// BlackRock cipher: a stateless bijection over `[0, n)` for permutation scanning.
///
/// Based on masscan's format-preserving Feistel network construction
/// (Black & Rogaway, "Ciphers with Arbitrary Finite Domains").
/// This ensures every probe index `i ∈ [0, n)` is visited exactly once with no
/// repeats and $O(1)$ memory consumption.
#[derive(Clone, Copy, Debug)]
pub struct BlackRock {
    /// Number of Feistel rounds.
    pub rounds: u32,
    /// Feistel partition factor A.
    pub a: u64,
    /// Feistel partition factor B.
    pub b: u64,
    /// Upper bound of the domain `[0, range)`.
    range: u64,
    /// Seed used for round mixing.
    seed: u64,
}

impl BlackRock {
    /// Initialize a new BlackRock permutation for the range `[0, n)`.
    pub fn new(n: u64) -> Self {
        Self::with_seed(n, 4, 0x9e37_79b9_7f4a_7c15)
    }

    /// Initialize with an explicit number of rounds and seed.
    pub fn with_seed(n: u64, rounds: u32, seed: u64) -> Self {
        if n <= 1 {
            return Self {
                rounds,
                a: 1,
                b: 1,
                range: n,
                seed,
            };
        }

        let sqrt = (n as f64).sqrt().ceil() as u64;
        let a = sqrt.max(2);
        let mut b = n.div_ceil(a).max(2);
        while a * b < n {
            b += 1;
        }

        Self {
            rounds: rounds.max(1),
            a,
            b,
            range: n,
            seed,
        }
    }

    /// Encrypt index `x` into a pseudo-random permutation in `[0, n)`.
    ///
    /// Applies cycle-walking: if the Feistel output falls outside `[0, n)`,
    /// it recursively re-encrypts until it lands within the target range.
    pub fn encrypt(&self, mut x: u64) -> u64 {
        if self.range <= 1 || x >= self.range {
            return x;
        }

        loop {
            x = self.feistel(x);
            if x < self.range {
                return x;
            }
        }
    }

    /// Single pass through the generalized Feistel network over `[0, a * b)`.
    fn feistel(&self, m: u64) -> u64 {
        let mut l = m % self.a;
        let mut r = m / self.a;

        for j in 1..=self.rounds {
            let f = Self::round_fn(j, r, self.seed);
            let tmp = if (j & 1) != 0 {
                (l.wrapping_add(f)) % self.a
            } else {
                (l.wrapping_add(f)) % self.b
            };
            l = r;
            r = tmp;
        }

        r * self.a + l
    }

    /// High-diffusion 64-bit mixing round function (SplitMix64 style).
    fn round_fn(round: u32, r: u64, seed: u64) -> u64 {
        let mut z = r
            .wrapping_add(seed)
            .wrapping_add((round as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn small_ranges_are_bijections() {
        for n in 1..=100 {
            let br = BlackRock::new(n);
            let mut seen = HashSet::new();
            for i in 0..n {
                let out = br.encrypt(i);
                assert!(out < n, "out of bounds: out={out} >= n={n}");
                seen.insert(out);
            }
            assert_eq!(seen.len(), n as usize, "failed bijection for n={n}");
        }
    }

    #[test]
    fn single_element_and_zero_are_identity() {
        let br0 = BlackRock::new(0);
        assert_eq!(br0.encrypt(0), 0);
        let br1 = BlackRock::new(1);
        assert_eq!(br1.encrypt(0), 0);
    }
}
