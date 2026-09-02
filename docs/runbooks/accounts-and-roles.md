# Runbook — Accounts, roles and MFA

**Audience:** whoever onboards and offboards operators, grants privilege, and
handles "I've lost my second factor".

**Prerequisites:** the `admin` role on the target bridge for governance
operations (grants, deletion, sync), and `impalactl` or the admin UI's
Accounts page.

**See also:** [`impalactl-operations.md`](./impalactl-operations.md) for the
command detail, [`triage.md`](./triage.md) for what a 401 or 403 actually means.

---

## 1. The role model

Seven roles, server-side, carried in the JWT's `role` claim. The database
column is `impala_account.role`, constrained to exactly these values
(migration 035 — run it **before** rolling the binary that knows the new
names, or granting one 500s against the old CHECK).

The original **ladder** is unchanged (each row adds to the one above):

| Role | Adds |
|---|---|
| `view-only` | view accounts, MFA, transactions, cards |
| `device` | + create transactions, manage cards |
| `token` | + manage accounts, manage MFA |
| `admin` | + everything, including governance (below) |

Alongside it, three **lateral** privileged roles split what used to be the
monolithic admin surface by blast radius. None includes another's surface;
`admin` remains the superset:

| Role | Holds | Does NOT hold |
|---|---|---|
| `treasurer` | Reserve & replenishment money operations: disburse, resolve, write-off, confirm fiat, refunds, policy ([`conversion-reserve.md`](./conversion-reserve.md)) | Key custody, governance |
| `key-custodian` | Bridge provider credentials & custodial seeds: import, rotate, revoke, seed provisioning ([`import-keys.md`](./import-keys.md)); can read accounts (provisioning is keyed by account id) | Treasury operations, governance |
| `auditor` | Read-only oversight: accounts list & detail, transactions across accounts, reserve state including the work queues and cross-account reserve orders, key inventory metadata (fingerprints, never material), the event feed and webhook registrations | Any mutation on those surfaces |

**`admin` is the only governance role.** Role grants, account deletion,
directory sync, webhook register/delete/test, and transaction review remain
admin-only. Enforcement is one capability matrix in the bridge
(`impala-bridge/src/auth.rs`, `role_has_capability`), pinned against the same
fixture the UI tests use (`impala-ui/tests/fixtures/role-capabilities.json`),
so the two stacks cannot drift apart silently.

Properties worth internalising:

- **Default is least privilege.** The column defaults to `view-only`, a token
  with no `role` claim resolves to `view-only`, and a role the matrix does not
  list — unknown, empty, legacy — holds nothing. Every direction fails closed.
- **Grants revoke the target's credentials immediately.** A role change bumps
  the target's auth epoch: every bearer token and session dies at once, and
  the new role applies at their **next sign-in**. The old guidance — wait for
  a token refresh, or ask the target to `logout --all` — is obsolete; the
  server does the revocation itself, and the grant response says so. A no-op
  grant (same role) deliberately does not sign the target out.
- **Refresh cannot resurrect a revoked role.** The role is re-derived from the
  database on every refresh-token rotation, fail-closed: a missing row or a
  DB error mints `view-only`, never the presented token's role. A deleted
  treasurer cannot keep re-minting treasury power off a 14-day refresh family.
- **`ADMIN_ACCOUNT_IDS` overrides the database.** Ids in that allowlist are
  stamped `admin` at issuance regardless of their row. It is the break-glass
  path when the console is unreachable. Granting a non-admin role to an
  allowlisted account now returns an explicit **warning** — the stored role is
  saved, but the account keeps receiving admin tokens until it leaves the
  list — and the Accounts page marks such accounts with an "effective admin"
  badge. Audit the allowlist alongside the database.

### The auditor, honestly

The auditor role is read-only **on the privileged surfaces**: it holds no
mutation capability there, and granting it one is a security incident, not a
tweak. But on their **own** account an auditor remains an ordinary self-scoped
user — the role adds cross-account read scope, it does not subtract
self-service. An auditor can still transact, enrol MFA, and manage cards on
their own account like anyone else. If your compliance model requires an
oversight account that cannot move its own money, keep the auditor account
unfunded rather than assuming the role enforces it.

## 2. The first account is automatically admin

A `BEFORE INSERT` trigger promotes the very first account ever inserted to
`admin`, on every creation path — `create_account`, SSO auto-provision, and
managed-account generate/import. It takes an advisory lock so two concurrent
first-inserts cannot both be promoted.

On a database that already had accounts when the role migration landed, the
migration promotes the **earliest** account instead. Confirm before relying on
the console:

```
SELECT count(*) FROM impala_account WHERE role='admin';
```

> After deploying the role migrations, everyone's existing token lacks the
> claim and is treated as `view-only`. Admins lose the console until they
> refresh. This is expected — say so in the deploy announcement rather than
> fielding it as an incident.

## 3. Onboard an operator

```
# 1. Create the account (custodial: the bridge generates and seals the seed)
impalactl account generate --account dana --first-name Dana --last-name Scully

# 2. Grant the role they need — Accounts page → open account → Role grant
#    (PUT /admin/accounts/{account_id}/role)

# 3. Have them log in and confirm what they actually hold
impalactl login --username dana
impalactl whoami
```

Grant the **narrowest** role that covers the duty:

- Account/MFA management → `token`.
- Reserve and replenishment money operations → `treasurer`.
- Credential and seed custody → `key-custodian`.
- Compliance, reconciliation, incident investigation → `auditor`. Prefer it
  over admin for anything read-only: an auditor token cannot move money or
  change credentials if it leaks.
- Governance (grants, deletion, sync, webhooks, review) → `admin`, and only
  then.

> **`admin` and `key-custodian` are spend authority in practice.** Either can
> import provider credentials and provision seeds, and the confirmation
> prompts on those endpoints stop accidents, not a compromised token. A
> `treasurer` can move reserve money directly. Treat granting any of the three
> as granting access to the treasury — the split exists so you no longer have
> to hand out all of it at once.

Then enrol MFA (§5).

## 4. Change a role, and the guards you will hit

Role changes go through `PUT /admin/accounts/{account_id}/role`.

**The change revokes the target's access on the spot.** Their sessions and
tokens are signed out atomically with the grant (the revocation happens before
commit — a demotion whose revocation did not take is not a demotion), and they
pick up the new role by signing in again. Expect the "why am I logged out"
question; it means the grant worked.

Every change is recorded as an `account.role_changed` event in the admin feed,
carrying the actor, the old role and the new role (§8).

The one guard: **you cannot demote the last remaining admin.**

```
[409 conflict] Cannot demote the last remaining admin
```

This includes moving the last admin to a lateral role — a treasurer,
key-custodian or auditor is **not** an admin, and allowlist-only admins are
deliberately not counted (the allowlist is an env override, not governance).
The guard runs under an advisory lock shared with account deletion, so two
concurrent demotions of the two remaining admins cannot race each other into
zero. Promote the replacement first, then demote. There is no "force" for it,
and that is deliberate — recovering from zero admins means editing the
database or using `ADMIN_ACCOUNT_IDS`.

Demoting an allowlisted account warns instead of refusing:

```
WARNING: this account is on the ADMIN_ACCOUNT_IDS allowlist and will
continue to receive admin tokens until removed from it.
```

Act on that warning — the stored role takes effect only when the account
leaves the list.

## 5. MFA

Enrollment and verification are ordinary user-scoped endpoints:

| Operation | Endpoint |
|---|---|
| Enrol (TOTP or SMS) | `POST /mfa` |
| Read enrollment state | `GET /mfa` |
| Verify a code | `POST /mfa/verify` |

SMS enrollment requires a phone number — `enroll_mfa: missing phone_number for
SMS enrollment` in the logs (as a `warn`) means the request omitted it. An
unrecognized type logs `enroll_mfa: invalid mfa_type '<x>'`.

### Lost second factor

There is **no self-service MFA reset endpoint** and no admin "reset MFA"
operation in the CLI. Recovery is a database operation on the `impala_mfa`
table (migration 005), performed by someone with database access after
verifying identity out of band.

Because it is a manual database change, make it a two-person job and record it:

1. Verify the person's identity through a channel that is not the one they
   lost.
2. Remove or reset their MFA row.
3. Have them re-enrol immediately via `POST /mfa` and verify a code.
4. Note who did it and why — this path leaves no application audit event of
   its own, so the record has to be made deliberately.

> Also revoke their sessions (`impalactl logout --all` as that account, or an
> admin-side revocation) if the loss might be a compromise rather than a new
> phone.

## 6. Offboard

```
# 1. Cut privilege — demote to view-only. The demotion itself revokes every
#    token and session for the account; access ends here, not at deletion.
#    (Promote a replacement admin first if they were the last one.)

# 2. Delete, once the guards below are clear. Deletion revokes credentials
#    again as part of the same transaction, so nothing survives it.
```

`impalactl logout --all` as the target still works as a kill switch when you
cannot reach the console, but it is no longer a required first step — the
demotion is the revocation.

`DELETE /admin/accounts/{account_id}` refuses with a `409 conflict` when:

| Message | Meaning |
|---|---|
| `Cannot delete the last remaining admin` | Promote someone else first |
| `This account is the configured conversion reserve; unset RESERVE_ACCOUNT_ID first` | Its seed signs pool payouts — deleting it would brick the reserve |
| `Account has N in-flight conversion-reserve order(s); resolve or expire them first` | Settle them — see [`conversion-reserve.md`](./conversion-reserve.md) |
| `Account has N unreleased conversion-reserve price lock(s); wait for the watcher to sweep them` | Wait; the watcher releases them on expiry |
| `Account has N unresolved conversion-reserve refund(s); settle them first` | Someone is owed money |

and with a `400 bad_request` when:

```
Admins cannot delete their own account
```

> Every one of these guards protects money or access, not tidiness. If you find
> yourself looking for a way around one, the answer is to resolve the
> underlying state.

**Deletion removes the account's child rows, including its managed seed.** For a
custodial account that means the key is gone. If there is any chance funds
remain at that Stellar address, move them **before** deleting — there is no
recovery afterwards.

## 7. Switching sync mode

```
impalactl sync mode alice --mode mirror
impalactl sync mode alice --mode mirror --force
```

Without `--force`, switching an account that still holds value is refused:

```
[409 conflict] account has a nonzero reserve balance; pass force=true to switch anyway
```

Check the balance (`impalactl account reserves alice`) and understand where it
is going before forcing. The flag exists for deliberate migrations, not for
getting past a surprising error.

## 8. Auditing

```
impalactl activity events --since <cursor>
```

The admin event feed is the record for account and key operations —
`account.role_changed` (actor, old role, new role), `bridge.key_imported`,
`bridge.key_revoked`, `bridge.seed_provisioned` and account lifecycle events.
Reading it requires admin **or auditor** — an auditor can run the poller
without holding any mutation capability. Poll it into your log store rather
than reading it only during incidents; the cursor makes that a three-line loop
(see [`impalactl-operations.md`](./impalactl-operations.md) §7).

Two things that do **not** appear there and need separate handling: MFA resets
done in the database (§5), and `ADMIN_ACCOUNT_IDS` membership (§1).

## Gotchas

- **`whoami` reads the stored token, not the server.** It is the right tool for
  "what does this token actually claim" and the wrong one for "what is this
  account's role now" — especially since a role change revokes the stored
  token: after a grant, `whoami` describes a dead credential until the target
  signs in again.
- **Role changes and deletion revoke the target's credentials themselves.**
  The old "deleting an account does not revoke its tokens first" caveat is
  gone — both operations bump the target's auth epoch atomically with the
  change. `logout --all` remains the manual kill switch.
- **A demoted allowlisted account is still an effective admin.** The warning
  in the grant response and the badge in the Accounts page are the only
  indications — the row's role understates the account's privilege until it
  leaves `ADMIN_ACCOUNT_IDS`.
- **`account generate` versus `account create`.** `generate` makes the bridge
  custodian of a new seed; `create` links an address whose key the user keeps.
  Choose deliberately — it decides who can sign.
- **Open registration is not an onboarding mechanism.**
  `ALLOW_OPEN_REGISTRATION=true` lets `POST /authenticate` set a password on any
  existing credential-less account, including custodial and SSO-only ones. The
  bridge warns at startup when it is on.
