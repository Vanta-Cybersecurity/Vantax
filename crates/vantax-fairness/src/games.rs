//! Games and how each one turns the stream into an outcome.
//!
//! Every derivation uses integer arithmetic only, so any language reproduces
//! it exactly. The rules, in the order values are drawn:
//!
//! | Game | Draws | Outcome |
//! |---|---|---|
//! | `dice` | `below(10000)` | roll 0–9999, shown as 0.00–99.99 |
//! | `coin` | `below(2)` | 0 = heads, 1 = tails |
//! | `range` | `below(max − min + 1)` | `min + draw` |
//! | `crash` | `bits52()` = h | `max(100, ⌊(10000 − edge_bps)·2⁵² / (100·(2⁵² − h))⌋)` hundredths |
//! | `wheel` | `below(segments)` | segment index |
//! | `plinko` | `below(2)` per row | `L`/`R` path; bucket = number of `R` |
//! | `mines` | partial shuffle of `0..tiles`, `mines` steps | first `mines` positions, sorted |
//! | `keno` | partial shuffle of `1..=pool`, `draws` steps | first `draws` numbers, in draw order |
//! | `shuffle` | full shuffle of `0..cards` | the order |
//!
//! Partial shuffle (forward Fisher–Yates): for `i` in `0..k`, `j = i +
//! below(n − i)`, swap items `i` and `j`. Full shuffle (Durstenfeld): for `i`
//! from `n − 1` down to 1, `j = below(i + 1)`, swap items `i` and `j`.

use crate::rng::FairRng;
use crate::FairnessError;
use serde::{Deserialize, Serialize};

/// Largest crash house edge accepted, in basis points (50%).
pub const MAX_HOUSE_EDGE_BPS: u32 = 5_000;

/// A game and its parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "game", rename_all = "snake_case", deny_unknown_fields)]
pub enum Game {
    /// A roll from 0.00 to 99.99.
    Dice,
    /// Heads or tails.
    Coin,
    /// A whole number from `min` to `max` inclusive (at most 2³² − 1 values).
    Range {
        /// Smallest value.
        min: i64,
        /// Largest value.
        max: i64,
    },
    /// A crash multiplier with the given house edge.
    Crash {
        /// House edge in basis points (100 = 1%).
        house_edge_bps: u32,
    },
    /// A wheel with `segments` equal segments (2 to 10,000).
    Wheel {
        /// Number of segments.
        segments: u32,
    },
    /// A plinko drop through `rows` rows (1 to 32).
    Plinko {
        /// Number of rows.
        rows: u32,
    },
    /// Mine positions on a board of `tiles` tiles (2 to 1,024).
    Mines {
        /// Board size.
        tiles: u32,
        /// Number of mines (1 to `tiles − 1`).
        mines: u32,
    },
    /// `draws` numbers drawn from `1..=pool` (pool 1 to 1,024).
    Keno {
        /// Numbers in the pool.
        pool: u32,
        /// Numbers drawn.
        draws: u32,
    },
    /// An ordering of `cards` cards (2 to 1,024), e.g. 52 for one deck.
    Shuffle {
        /// Number of cards.
        cards: u32,
    },
}

impl Game {
    /// Check the parameters.
    pub fn validate(&self) -> Result<(), FairnessError> {
        let bad = |m: String| Err(FairnessError::InvalidGame(m));
        match *self {
            Game::Dice | Game::Coin => Ok(()),
            Game::Range { min, max } => {
                if max < min {
                    return bad(format!("range: max {max} is below min {min}"));
                }
                let span = (i128::from(max) - i128::from(min)) + 1;
                if span > i128::from(u32::MAX) {
                    return bad("range: at most 4,294,967,295 values".into());
                }
                Ok(())
            }
            Game::Crash { house_edge_bps } if house_edge_bps > MAX_HOUSE_EDGE_BPS => bad(format!(
                "crash: house edge {house_edge_bps} bps is above {MAX_HOUSE_EDGE_BPS}"
            )),
            Game::Crash { .. } => Ok(()),
            Game::Wheel { segments } if !(2..=10_000).contains(&segments) => {
                bad("wheel: 2 to 10,000 segments".into())
            }
            Game::Wheel { .. } => Ok(()),
            Game::Plinko { rows } if !(1..=32).contains(&rows) => {
                bad("plinko: 1 to 32 rows".into())
            }
            Game::Plinko { .. } => Ok(()),
            Game::Mines { tiles, mines } => {
                if !(2..=1024).contains(&tiles) || mines == 0 || mines >= tiles {
                    return bad("mines: 2 to 1,024 tiles and 1 to tiles − 1 mines".into());
                }
                Ok(())
            }
            Game::Keno { pool, draws } => {
                if !(1..=1024).contains(&pool) || draws == 0 || draws > pool {
                    return bad("keno: pool 1 to 1,024 and 1 to pool draws".into());
                }
                Ok(())
            }
            Game::Shuffle { cards } if !(2..=1024).contains(&cards) => {
                bad("shuffle: 2 to 1,024 cards".into())
            }
            Game::Shuffle { .. } => Ok(()),
        }
    }

    /// The canonical text form signed into receipts, e.g. `crash:100`.
    pub fn canonical(&self) -> String {
        match *self {
            Game::Dice => "dice".into(),
            Game::Coin => "coin".into(),
            Game::Range { min, max } => format!("range:{min}:{max}"),
            Game::Crash { house_edge_bps } => format!("crash:{house_edge_bps}"),
            Game::Wheel { segments } => format!("wheel:{segments}"),
            Game::Plinko { rows } => format!("plinko:{rows}"),
            Game::Mines { tiles, mines } => format!("mines:{tiles}:{mines}"),
            Game::Keno { pool, draws } => format!("keno:{pool}:{draws}"),
            Game::Shuffle { cards } => format!("shuffle:{cards}"),
        }
    }

    /// Draw this game's outcome from `rng`.
    pub fn play(&self, rng: &mut FairRng) -> Result<Outcome, FairnessError> {
        self.validate()?;
        Ok(match *self {
            Game::Dice => Outcome::Dice {
                roll: rng.below(10_000),
            },
            Game::Coin => Outcome::Coin {
                heads: rng.below(2) == 0,
            },
            Game::Range { min, max } => {
                let span = (i128::from(max) - i128::from(min) + 1) as u32;
                Outcome::Range {
                    value: (i128::from(min) + i128::from(rng.below(span))) as i64,
                }
            }
            Game::Crash { house_edge_bps } => Outcome::Crash {
                multiplier_x100: crash_multiplier(rng.bits52(), house_edge_bps),
            },
            Game::Wheel { segments } => Outcome::Wheel {
                segment: rng.below(segments),
            },
            Game::Plinko { rows } => {
                let mut path = String::with_capacity(rows as usize);
                let mut bucket = 0;
                for _ in 0..rows {
                    if rng.below(2) == 1 {
                        path.push('R');
                        bucket += 1;
                    } else {
                        path.push('L');
                    }
                }
                Outcome::Plinko { path, bucket }
            }
            Game::Mines { tiles, mines } => {
                let mut items: Vec<u32> = (0..tiles).collect();
                partial_shuffle(rng, &mut items, mines as usize);
                let mut positions = items[..mines as usize].to_vec();
                positions.sort_unstable();
                Outcome::Mines { positions }
            }
            Game::Keno { pool, draws } => {
                let mut items: Vec<u32> = (1..=pool).collect();
                partial_shuffle(rng, &mut items, draws as usize);
                Outcome::Keno {
                    numbers: items[..draws as usize].to_vec(),
                }
            }
            Game::Shuffle { cards } => {
                let mut order: Vec<u32> = (0..cards).collect();
                for i in (1..order.len()).rev() {
                    let j = rng.below(i as u32 + 1) as usize;
                    order.swap(i, j);
                }
                Outcome::Shuffle { order }
            }
        })
    }
}

fn partial_shuffle(rng: &mut FairRng, items: &mut [u32], k: usize) {
    let n = items.len();
    for i in 0..k {
        let j = i + rng.below((n - i) as u32) as usize;
        items.swap(i, j);
    }
}

/// The crash multiplier, in hundredths (198 = 1.98x), for a 52-bit draw `h`.
///
/// `(1 − edge) / (1 − h/2⁵²)`, floored to hundredths and never below 1.00x.
/// The chance of reaching at least `x` is `(1 − edge) / x`.
pub fn crash_multiplier(h: u64, house_edge_bps: u32) -> u64 {
    let e = 1u128 << 52;
    let h = u128::from(h) & (e - 1);
    let numerator = u128::from(10_000 - house_edge_bps.min(10_000)) * e;
    let denominator = 100 * (e - h);
    ((numerator / denominator) as u64).max(100)
}

/// A game's result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    /// Roll in hundredths: 4207 means 42.07.
    Dice {
        /// 0 to 9999.
        roll: u32,
    },
    /// Coin result.
    Coin {
        /// True for heads.
        heads: bool,
    },
    /// Range result.
    Range {
        /// The value drawn.
        value: i64,
    },
    /// Crash point in hundredths: 198 means 1.98x.
    Crash {
        /// Multiplier × 100.
        multiplier_x100: u64,
    },
    /// Wheel segment.
    Wheel {
        /// 0-based segment index.
        segment: u32,
    },
    /// Plinko drop.
    Plinko {
        /// One `L` or `R` per row.
        path: String,
        /// Number of `R` moves.
        bucket: u32,
    },
    /// Mine positions, 0-based, ascending.
    Mines {
        /// Positions.
        positions: Vec<u32>,
    },
    /// Keno numbers in the order drawn.
    Keno {
        /// Numbers, 1-based.
        numbers: Vec<u32>,
    },
    /// Card order, 0-based.
    Shuffle {
        /// The permutation.
        order: Vec<u32>,
    },
}

fn join(v: &[u32]) -> String {
    v.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
}

impl Outcome {
    /// The canonical text form signed into receipts, e.g. `crash:198`.
    pub fn canonical(&self) -> String {
        match self {
            Outcome::Dice { roll } => format!("dice:{roll}"),
            Outcome::Coin { heads } => format!("coin:{}", if *heads { "heads" } else { "tails" }),
            Outcome::Range { value } => format!("range:{value}"),
            Outcome::Crash { multiplier_x100 } => format!("crash:{multiplier_x100}"),
            Outcome::Wheel { segment } => format!("wheel:{segment}"),
            Outcome::Plinko { path, bucket } => format!("plinko:{path}:{bucket}"),
            Outcome::Mines { positions } => format!("mines:{}", join(positions)),
            Outcome::Keno { numbers } => format!("keno:{}", join(numbers)),
            Outcome::Shuffle { order } => format!("shuffle:{}", join(order)),
        }
    }

    /// A short human-readable form, e.g. `42.07` or `1.98x`.
    pub fn display(&self) -> String {
        match self {
            Outcome::Dice { roll } => format!("{}.{:02}", roll / 100, roll % 100),
            Outcome::Coin { heads } => (if *heads { "heads" } else { "tails" }).into(),
            Outcome::Range { value } => value.to_string(),
            Outcome::Crash { multiplier_x100 } => {
                format!("{}.{:02}x", multiplier_x100 / 100, multiplier_x100 % 100)
            }
            Outcome::Wheel { segment } => format!("segment {segment}"),
            Outcome::Plinko { path, bucket } => format!("{path} → bucket {bucket}"),
            Outcome::Mines { positions } => format!("mines at {}", join(positions)),
            Outcome::Keno { numbers } => join(numbers),
            Outcome::Shuffle { order } => join(order),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [42u8; 32];

    fn play(game: Game, nonce: u64) -> Outcome {
        game.play(&mut FairRng::new(&SEED, "client", nonce))
            .unwrap()
    }

    #[test]
    fn deterministic() {
        for g in [
            Game::Dice,
            Game::Coin,
            Game::Range { min: -5, max: 5 },
            Game::Crash {
                house_edge_bps: 100,
            },
            Game::Wheel { segments: 37 },
            Game::Plinko { rows: 16 },
            Game::Mines {
                tiles: 25,
                mines: 3,
            },
            Game::Keno {
                pool: 80,
                draws: 20,
            },
            Game::Shuffle { cards: 52 },
        ] {
            assert_eq!(play(g.clone(), 9), play(g, 9));
        }
    }

    #[test]
    fn shapes() {
        match play(Game::Shuffle { cards: 52 }, 1) {
            Outcome::Shuffle { order } => {
                let mut s = order.clone();
                s.sort_unstable();
                assert_eq!(s, (0..52).collect::<Vec<_>>(), "a permutation");
            }
            o => panic!("{o:?}"),
        }
        match play(
            Game::Mines {
                tiles: 25,
                mines: 5,
            },
            2,
        ) {
            Outcome::Mines { positions } => {
                assert_eq!(positions.len(), 5);
                assert!(positions.windows(2).all(|w| w[0] < w[1]));
                assert!(positions.iter().all(|p| *p < 25));
            }
            o => panic!("{o:?}"),
        }
        match play(
            Game::Keno {
                pool: 80,
                draws: 20,
            },
            3,
        ) {
            Outcome::Keno { numbers } => {
                let mut s = numbers.clone();
                s.sort_unstable();
                s.dedup();
                assert_eq!(s.len(), 20, "no repeats");
                assert!(numbers.iter().all(|n| (1..=80).contains(n)));
            }
            o => panic!("{o:?}"),
        }
        match play(Game::Plinko { rows: 12 }, 4) {
            Outcome::Plinko { path, bucket } => {
                assert_eq!(path.len(), 12);
                assert_eq!(path.matches('R').count() as u32, bucket);
            }
            o => panic!("{o:?}"),
        }
        match play(Game::Range { min: -3, max: 3 }, 5) {
            Outcome::Range { value } => assert!((-3..=3).contains(&value)),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn crash_formula() {
        // h = 0 gives exactly (1 − edge): floored to 1.00x minimum.
        assert_eq!(crash_multiplier(0, 100), 100);
        assert_eq!(crash_multiplier(0, 0), 100);
        // h = 2^51 is r = 0.5: (1 − 0.01) / 0.5 = 1.98x.
        assert_eq!(crash_multiplier(1 << 51, 100), 198);
        // h = 3·2^50 is r = 0.75: 0.99 / 0.25 = 3.96x.
        assert_eq!(crash_multiplier(3 << 50, 100), 396);
        // Edge 0, r = 0.9: 1 / 0.1 = 10.00x.
        let h = ((1u128 << 52) * 9 / 10) as u64 + 1;
        assert_eq!(crash_multiplier(h, 0), 1000);
    }

    #[test]
    fn crash_distribution_matches_edge() {
        // P(multiplier >= 2.00x) should be 0.99 / 2 = 0.495 with a 1% edge.
        let n = 40_000u64;
        let mut hits = 0;
        for nonce in 0..n {
            if let Outcome::Crash { multiplier_x100 } = play(
                Game::Crash {
                    house_edge_bps: 100,
                },
                nonce,
            ) {
                if multiplier_x100 >= 200 {
                    hits += 1;
                }
            }
        }
        let p = hits as f64 / n as f64;
        assert!((0.48..0.51).contains(&p), "{p}");
    }

    #[test]
    fn validation() {
        assert!(Game::Range { min: 5, max: 4 }.validate().is_err());
        assert!(Game::Range {
            min: 0,
            max: u32::MAX as i64
        }
        .validate()
        .is_err());
        assert!(Game::Range {
            min: 0,
            max: u32::MAX as i64 - 1
        }
        .validate()
        .is_ok());
        assert!(Game::Crash {
            house_edge_bps: 5001
        }
        .validate()
        .is_err());
        assert!(Game::Wheel { segments: 1 }.validate().is_err());
        assert!(Game::Plinko { rows: 33 }.validate().is_err());
        assert!(Game::Mines {
            tiles: 25,
            mines: 25
        }
        .validate()
        .is_err());
        assert!(Game::Keno {
            pool: 10,
            draws: 11
        }
        .validate()
        .is_err());
        assert!(Game::Shuffle { cards: 1 }.validate().is_err());
    }

    #[test]
    fn canonical_and_json_forms() {
        assert_eq!(
            Game::Mines {
                tiles: 25,
                mines: 3
            }
            .canonical(),
            "mines:25:3"
        );
        assert_eq!(
            Outcome::Crash {
                multiplier_x100: 198
            }
            .display(),
            "1.98x"
        );
        assert_eq!(Outcome::Dice { roll: 4207 }.display(), "42.07");
        assert_eq!(Outcome::Dice { roll: 5 }.display(), "0.05");
        let j = serde_json::to_string(&Game::Crash {
            house_edge_bps: 100,
        })
        .unwrap();
        assert_eq!(j, r#"{"game":"crash","house_edge_bps":100}"#);
        let back: Game = serde_json::from_str(&j).unwrap();
        assert_eq!(
            back,
            Game::Crash {
                house_edge_bps: 100
            }
        );
    }
}
