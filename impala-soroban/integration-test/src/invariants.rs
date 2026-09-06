//! Property-based state machine for `MultisigUsdcWrapper`.
//!
//! A random sequence of operations is driven through the generated `try_*`
//! client methods against a reference model, and the reservation,
//! conservation, id-monotonicity, storage-class and configuration invariants
//! are checked after **every** operation. Each op's expected outcome is
//! computed from the model with the contract's own predicates, so an accepted
//! call that should have failed (or vice versa) is a failure too.
//!
//! Authorization is deliberately outside the property (`mock_all_auths`);
//! the deterministic `mock_auths(&[])` tests in `lib.rs` are mandatory and
//! not redundant with this file.
//!
//! Conservation note: `usdc.balance(contract) == total_supply` holds only
//! against `MockUsdc`. On-chain `SAC.balance(contract) >= total_wrapped`
//! (anyone can pay USDC straight to the contract address; there is no sweep).
//!
//! Failing seeds persist to `proptest-regressions/invariants.txt` (proptest's
//! default `SourceParallel` persistence); commit that file whenever a
//! regression is found. `PROPTEST_CASES` overrides the case count (64).

use super::tests::{create_usdc_token, MockUsdcClient};
use super::*;
use proptest::prelude::*;
use soroban_sdk::testutils::storage::Instance as _;
use soroban_sdk::testutils::{Address as _, EnvTestConfig, Ledger as _};
use soroban_sdk::{TryFromVal, Vec as SVec};
use std::vec;
use std::vec::Vec;

const HOLDERS: usize = 4;
/// Signer pool S0..S4; the initial configuration is [S0, S1, S2].
const POOL: usize = 5;
const INIT_THRESHOLD: u32 = 2;
/// Equal to the initial threshold so `Rotate` exercises the floor.
const MIN_THRESHOLD: u32 = 2;
const MIN_LOCK: u64 = 10;
/// Minted to each holder on `MockUsdc` at start.
const MINT: i128 = 20_000;

#[derive(Clone, Debug)]
enum Amt {
    Fixed(i128),
    ExactAvailable,
    AvailablePlusOne,
}

#[derive(Clone, Debug)]
enum Op {
    Wrap {
        h: usize,
        amt: i128,
    },
    SchedUnwrap {
        h: usize,
        amt: Amt,
        delay: u64,
    },
    SchedTransfer {
        from: usize,
        to: usize,
        amt: Amt,
        delay: u64,
    },
    Execute {
        slot: usize,
    },
    Cancel {
        slot: usize,
    },
    Expire {
        slot: usize,
    },
    Advance {
        secs: u64,
    },
    Pause,
    Unpause,
    Rotate {
        mask: u8,
        threshold: u32,
    },
    BumpEntries,
}

#[derive(Clone, Debug)]
struct Pend {
    id: u64,
    kind: u32,
    from: usize,
    to: usize,
    amt: i128,
    unlock: u64,
    expires: u64,
}

struct Model {
    bal: [i128; HOLDERS],
    res: [i128; HOLDERS],
    sac: [i128; HOLDERS],
    total: i128,
    paused: bool,
    signers: Vec<usize>,
    threshold: u32,
    epoch: u32,
    next_id: u64,
    now: u64,
    /// Every id ever issued with its kind; consumed ids are retried by
    /// `slot` indexing and must fail with "Timelock not found".
    issued: Vec<(u64, u32)>,
    pending: Vec<Pend>,
}

fn amt_strategy() -> impl Strategy<Value = Amt> {
    prop_oneof![
        6 => (1..=6_000i128).prop_map(Amt::Fixed),
        1 => Just(Amt::ExactAvailable),
        1 => Just(Amt::AvailablePlusOne),
    ]
}

fn delay_strategy() -> impl Strategy<Value = u64> {
    prop_oneof![
        8 => MIN_LOCK..=2_000u64,
        1 => Just(MIN_LOCK - 1),
        1 => Just(MAX_LOCK_DURATION + 1),
    ]
}

fn secs_strategy() -> impl Strategy<Value = u64> {
    prop_oneof![
        6 => 0..=3_000u64,
        1 => Just(EXECUTION_WINDOW - 1),
        1 => Just(EXECUTION_WINDOW + 1),
        1 => Just(MAX_LOCK_DURATION + EXECUTION_WINDOW + 10),
    ]
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..HOLDERS, 1..=6_000i128).prop_map(|(h, amt)| Op::Wrap { h, amt }),
        3 => (0..HOLDERS, amt_strategy(), delay_strategy())
            .prop_map(|(h, amt, delay)| Op::SchedUnwrap { h, amt, delay }),
        3 => (0..HOLDERS, 0..HOLDERS, amt_strategy(), delay_strategy())
            .prop_map(|(from, to, amt, delay)| Op::SchedTransfer { from, to, amt, delay }),
        3 => (0..64usize).prop_map(|slot| Op::Execute { slot }),
        2 => (0..64usize).prop_map(|slot| Op::Cancel { slot }),
        1 => (0..64usize).prop_map(|slot| Op::Expire { slot }),
        3 => secs_strategy().prop_map(|secs| Op::Advance { secs }),
        1 => Just(Op::Pause),
        1 => Just(Op::Unpause),
        1 => (0u8..32, 1u32..=5).prop_map(|(mask, threshold)| Op::Rotate { mask, threshold }),
        1 => Just(Op::BumpEntries),
    ]
}

struct World {
    env: Env,
    contract: Address,
    token: Address,
    holders: Vec<Address>,
    pool: Vec<Address>,
    model: Model,
}

impl World {
    fn new() -> Self {
        let env = Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let issuer = Address::generate(&env);
        let token = create_usdc_token(&env, &issuer);
        let holders: Vec<Address> = (0..HOLDERS).map(|_| Address::generate(&env)).collect();
        let pool: Vec<Address> = (0..POOL).map(|_| Address::generate(&env)).collect();

        let usdc = MockUsdcClient::new(&env, &token);
        for h in &holders {
            usdc.mint(h, &MINT);
        }

        let mut initial = SVec::new(&env);
        for a in pool.iter().take(3) {
            initial.push_back(a.clone());
        }
        let contract = env.register(
            MultisigUsdcWrapper,
            (
                initial,
                INIT_THRESHOLD,
                MIN_THRESHOLD,
                token.clone(),
                issuer,
                MIN_LOCK,
            ),
        );

        let model = Model {
            bal: [0; HOLDERS],
            res: [0; HOLDERS],
            sac: [MINT; HOLDERS],
            total: 0,
            paused: false,
            signers: std::vec![0, 1, 2],
            threshold: INIT_THRESHOLD,
            epoch: 0,
            next_id: 0,
            now: env.ledger().timestamp(),
            issued: Vec::new(),
            pending: Vec::new(),
        };

        World {
            env,
            contract,
            token,
            holders,
            pool,
            model,
        }
    }

    fn client(&self) -> MultisigUsdcWrapperClient<'_> {
        MultisigUsdcWrapperClient::new(&self.env, &self.contract)
    }

    fn usdc(&self) -> MockUsdcClient<'_> {
        MockUsdcClient::new(&self.env, &self.token)
    }

    /// The first `threshold` members of the current signer set.
    fn quorum(&self) -> SVec<Address> {
        let mut q = SVec::new(&self.env);
        for i in self
            .model
            .signers
            .iter()
            .take(self.model.threshold as usize)
        {
            q.push_back(self.pool[*i].clone());
        }
        q
    }

    fn pick(&self, slot: usize) -> Option<(u64, u32)> {
        if self.model.issued.is_empty() {
            None
        } else {
            Some(self.model.issued[slot % self.model.issued.len()])
        }
    }

    fn pending_index(&self, id: u64) -> Option<usize> {
        self.model.pending.iter().position(|p| p.id == id)
    }

    fn resolve_amt(&self, h: usize, amt: &Amt) -> i128 {
        let avail = self.model.bal[h] - self.model.res[h];
        match amt {
            Amt::Fixed(a) => *a,
            Amt::ExactAvailable => avail,
            Amt::AvailablePlusOne => avail + 1,
        }
    }

    fn schedule_ok(&self, from: usize, amount: i128, delay: u64) -> bool {
        let avail = self.model.bal[from] - self.model.res[from];
        !self.model.paused
            && amount >= 1
            && (MIN_LOCK..=MAX_LOCK_DURATION).contains(&delay)
            && avail >= amount
    }

    fn record_schedule(
        &mut self,
        id: u64,
        kind: u32,
        from: usize,
        to: usize,
        amt: i128,
        delay: u64,
    ) {
        let unlock = self.model.now + delay;
        self.model.res[from] += amt;
        self.model.pending.push(Pend {
            id,
            kind,
            from,
            to,
            amt,
            unlock,
            expires: unlock + EXECUTION_WINDOW,
        });
        self.model.issued.push((id, kind));
        self.model.next_id += 1;
    }

    fn release(&mut self, idx: usize) {
        let p = self.model.pending.remove(idx);
        self.model.res[p.from] -= p.amt;
    }

    fn step(&mut self, op: &Op) -> Result<(), TestCaseError> {
        let q = self.quorum();
        match op {
            Op::Wrap { h, amt } => {
                let expected = !self.model.paused && self.model.sac[*h] >= *amt;
                let res = self.client().try_wrap(&q, &self.holders[*h], amt);
                prop_assert_eq!(res.is_ok(), expected, "op {:?}", op);
                if expected {
                    self.model.bal[*h] += amt;
                    self.model.sac[*h] -= amt;
                    self.model.total += amt;
                }
            }
            Op::SchedUnwrap { h, amt, delay } => {
                let amount = self.resolve_amt(*h, amt);
                let expected = self.schedule_ok(*h, amount, *delay);
                let res = self
                    .client()
                    .try_schedule_unwrap(&q, &self.holders[*h], &amount, delay);
                prop_assert_eq!(res.is_ok(), expected, "op {:?} amount {}", op, amount);
                if expected {
                    let id = res.unwrap().unwrap();
                    prop_assert_eq!(id, self.model.next_id, "id not sequential");
                    self.record_schedule(id, 1, *h, *h, amount, *delay);
                }
            }
            Op::SchedTransfer {
                from,
                to,
                amt,
                delay,
            } => {
                let amount = self.resolve_amt(*from, amt);
                let expected = from != to && self.schedule_ok(*from, amount, *delay);
                let res = self.client().try_schedule_transfer(
                    &q,
                    &self.holders[*from],
                    &self.holders[*to],
                    &amount,
                    delay,
                );
                prop_assert_eq!(res.is_ok(), expected, "op {:?} amount {}", op, amount);
                if expected {
                    let id = res.unwrap().unwrap();
                    prop_assert_eq!(id, self.model.next_id, "id not sequential");
                    self.record_schedule(id, 2, *from, *to, amount, *delay);
                }
            }
            Op::Execute { slot } => {
                if let Some((id, kind)) = self.pick(*slot) {
                    let idx = self.pending_index(id);
                    let expected = !self.model.paused
                        && idx.is_some_and(|i| {
                            let p = &self.model.pending[i];
                            p.unlock <= self.model.now && self.model.now < p.expires
                        });
                    let ok = if kind == 1 {
                        self.client().try_execute_unwrap(&q, &id).is_ok()
                    } else {
                        self.client().try_execute_transfer(&q, &id).is_ok()
                    };
                    prop_assert_eq!(ok, expected, "op {:?} id {} kind {}", op, id, kind);
                    if expected {
                        let p = self.model.pending.remove(idx.unwrap());
                        self.model.res[p.from] -= p.amt;
                        self.model.bal[p.from] -= p.amt;
                        if p.kind == 1 {
                            self.model.total -= p.amt;
                            self.model.sac[p.from] += p.amt;
                        } else {
                            self.model.bal[p.to] += p.amt;
                        }
                    }
                }
            }
            Op::Cancel { slot } => {
                if let Some((id, _kind)) = self.pick(*slot) {
                    let idx = self.pending_index(id);
                    let expected = idx.is_some();
                    let res = self.client().try_cancel_timelock(&q, &id);
                    prop_assert_eq!(res.is_ok(), expected, "op {:?} id {}", op, id);
                    if expected {
                        self.release(idx.unwrap());
                    }
                }
            }
            Op::Expire { slot } => {
                if let Some((id, _kind)) = self.pick(*slot) {
                    let idx = self.pending_index(id);
                    let expected =
                        idx.is_some_and(|i| self.model.now >= self.model.pending[i].expires);
                    let res = self.client().try_expire_timelock(&id);
                    prop_assert_eq!(res.is_ok(), expected, "op {:?} id {}", op, id);
                    if expected {
                        self.release(idx.unwrap());
                    }
                }
            }
            Op::Advance { secs } => {
                self.model.now += secs;
                let now = self.model.now;
                self.env.ledger().with_mut(|li| li.timestamp = now);
            }
            Op::Pause => {
                let res = self.client().try_pause(&q);
                prop_assert!(res.is_ok(), "op {:?}", op);
                self.model.paused = true;
            }
            Op::Unpause => {
                let res = self.client().try_unpause(&q);
                prop_assert!(res.is_ok(), "op {:?}", op);
                self.model.paused = false;
            }
            Op::Rotate { mask, threshold } => {
                let new: Vec<usize> = (0..POOL).filter(|i| mask & (1u8 << i) != 0).collect();
                let expected = !new.is_empty()
                    && MIN_THRESHOLD <= *threshold
                    && *threshold <= new.len() as u32;
                let mut new_addrs = SVec::new(&self.env);
                for i in &new {
                    new_addrs.push_back(self.pool[*i].clone());
                }
                let res = self.client().try_rotate_signers(&q, &new_addrs, threshold);
                prop_assert_eq!(res.is_ok(), expected, "op {:?}", op);
                if expected {
                    self.model.signers = new;
                    self.model.threshold = *threshold;
                    self.model.epoch += 1;
                }
            }
            Op::BumpEntries => {
                let mut addrs = SVec::new(&self.env);
                for h in &self.holders {
                    addrs.push_back(h.clone());
                }
                let mut ids = SVec::new(&self.env);
                for p in &self.model.pending {
                    ids.push_back(p.id);
                }
                let expected = (HOLDERS + self.model.pending.len()) as u32 <= MAX_BUMP_BATCH;
                let res = self.client().try_bump_entry_ttl(&addrs, &ids);
                prop_assert_eq!(res.is_ok(), expected, "op {:?}", op);
            }
        }
        Ok(())
    }

    fn check(&self) -> Result<(), TestCaseError> {
        let client = self.client();
        let usdc = self.usdc();
        let m = &self.model;

        // 1 + 3: per-holder balances, reservations, availability, and the
        // reservation equals the sum of pending debits.
        let mut sum: i128 = 0;
        for h in 0..HOLDERS {
            let b = client.balance(&self.holders[h]);
            let r = client.reserved(&self.holders[h]);
            let a = client.available(&self.holders[h]);
            prop_assert_eq!(b, m.bal[h], "balance of holder {}", h);
            prop_assert_eq!(r, m.res[h], "reserved of holder {}", h);
            prop_assert_eq!(a, b - r, "available of holder {}", h);
            prop_assert!(
                r >= 0 && r <= b,
                "0 <= reserved <= balance for holder {}",
                h
            );
            let pend_sum: i128 = m
                .pending
                .iter()
                .filter(|p| p.from == h)
                .map(|p| p.amt)
                .sum();
            prop_assert_eq!(r, pend_sum, "reserved != Σ pending for holder {}", h);
            sum += b;
        }

        // 2: conservation (equality holds only against MockUsdc; on-chain the
        // SAC balance of the contract is >= total_wrapped).
        prop_assert_eq!(sum, client.total_supply(), "Σ balances != total_supply");
        prop_assert_eq!(client.total_supply(), m.total, "total_supply != model");
        prop_assert_eq!(
            usdc.balance(&self.contract),
            client.total_supply(),
            "token balance of contract != total_supply"
        );
        let mut circulating = usdc.balance(&self.contract);
        for (h, addr) in self.holders.iter().enumerate() {
            let s = usdc.balance(addr);
            prop_assert_eq!(s, m.sac[h], "token balance of holder {}", h);
            circulating += s;
        }
        prop_assert_eq!(
            circulating,
            HOLDERS as i128 * MINT,
            "token supply not conserved"
        );

        // 4: id counter.
        prop_assert_eq!(client.next_timelock_id(), m.next_id);
        for (id, _) in &m.issued {
            prop_assert!(*id < m.next_id);
        }

        // 5: pending entries exist and match; consumed ones are gone.
        for p in &m.pending {
            let tl = client.get_timelock(&p.id);
            prop_assert!(!tl.executed);
            prop_assert_eq!(tl.operation_type, p.kind);
            prop_assert_eq!(tl.amount, p.amt);
            prop_assert_eq!(tl.sender, self.holders[p.from].clone());
            prop_assert_eq!(tl.recipient, self.holders[p.to].clone());
            prop_assert_eq!(tl.unlock_time, p.unlock);
            prop_assert_eq!(tl.expires_at, p.expires);
        }
        for (id, _) in &m.issued {
            if self.pending_index(*id).is_none() {
                prop_assert!(
                    client.try_get_timelock(id).is_err(),
                    "consumed id {} readable",
                    id
                );
                let present = self.env.as_contract(&self.contract, || {
                    self.env.storage().persistent().has(&DataKey::TimeLock(*id))
                });
                prop_assert!(!present, "consumed id {} still stored", id);
            }
        }

        // 6: pause flag and configuration.
        prop_assert_eq!(client.is_paused(), m.paused);
        let cfg = client.multisig_config();
        prop_assert_eq!(cfg.threshold, m.threshold);
        prop_assert_eq!(cfg.epoch, m.epoch);
        prop_assert_eq!(cfg.signers.len() as usize, m.signers.len());
        for i in &m.signers {
            prop_assert!(cfg.signers.contains(&self.pool[*i]), "signer {} missing", i);
        }

        // 7: instance storage holds only configuration keys.
        let all = self
            .env
            .as_contract(&self.contract, || self.env.storage().instance().all());
        for (k, _v) in all.iter() {
            let key = DataKey::try_from_val(&self.env, &k);
            let ok = matches!(
                key,
                Ok(DataKey::MultisigConfig
                    | DataKey::WrappedUsdc
                    | DataKey::MinLockDuration
                    | DataKey::MinThreshold
                    | DataKey::NextTimeLockId
                    | DataKey::Paused)
            );
            prop_assert!(ok, "unexpected instance key {:?}", key);
        }
        Ok(())
    }
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]
    #[test]
    fn state_machine(ops in prop::collection::vec(op_strategy(), 1..=40)) {
        let mut world = World::new();
        world.check()?;
        for op in &ops {
            world.step(op)?;
            world.check()?;
        }
    }
}
