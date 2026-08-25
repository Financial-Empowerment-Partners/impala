# Runbook — Accounts, roles and MFA

**Audience:** whoever onboards and offboards operators, grants privilege, and
handles "I've lost my second factor".

**Prerequisites:** the `admin` role on the target bridge, and `impalactl` or the
admin UI's Accounts page.

**See also:** [`impalactl-operations.md`](./impalactl-operations.md) for the
command detail, [`triage.md`](./triage.md) for what a 401 or 403 actually means.

---

## 1. The role model

Four roles, server-side, carried in the JWT's `role` claim. The database column
is `impala_account.role`, constrained to exactly these values:

| Role | Adds to the row above |
|---|---|
| `view-only` | view accounts, MFA, transactions, cards |
| `device` | + create transactions, manage cards |
| `token` | + manage accounts, manage MFA, review transactions |
| `admin` | + manage roles, delete accounts, sync profiles |

Three properties worth internalising:

- **Default is least privilege.** The column defaults to `view-only`, and a
  token with no `role` claim (minted before the claim existed) resolves to
  `view-only` too. Both directions fail closed.
- **Grants are not immediate.** The role is stamped into the token at issuance,
  so a change applies at the target's **next token refresh**. Have them log out
  and back in.
- **`ADMIN_ACCOUNT_IDS` overrides the database.** Ids in that allowlist are
  stamped `admin` at issuance regardless of their row. It is the break-glass
  path when the console is unreachable — and it is invisible in the Accounts
  page, so an operator can hold admin with a `view-only` row. Audit it
  alongside the database.

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

Grant the **lowest** role that covers the work. `token` covers most
account-management duties; `admin` additionally allows deleting accounts,
granting roles, and every money-moving endpoint in
[`import-keys.md`](./import-keys.md).

> **`admin` is spend authority in practice.** An admin can import provider
> credentials and provision seeds, and the confirmation prompts on those
> endpoints stop accidents, not a compromised admin token. Treat granting
> `admin` as granting access to the treasury.

Then enrol MFA (§5).

## 4. Change a role, and the guard you will hit

Role changes go through `PUT /admin/accounts/{account_id}/role`.

The one guard: **you cannot demote the last remaining admin.**

```
[409 conflict] Cannot demote the last remaining admin
```

Promote the replacement first, then demote. The same rule applies to deletion
(§6). There is no "force" for it, and that is deliberate — recovering from zero
admins means editing the database or using `ADMIN_ACCOUNT_IDS`.

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

Order matters, because deletion is guarded on several money-path conditions.

```
# 1. Cut access immediately — revokes every token and session for the account
impalactl logout --all

# 2. Demote (promote a replacement admin first if they were the last one)

# 3. Delete, once the guards below are clear
```

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

Revoking sessions is what actually ends access; deletion is the cleanup. Do them
in that order.

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
`bridge.key_imported`, `bridge.key_revoked`, `bridge.seed_provisioned` and
account lifecycle events. Poll it into your log store rather than reading it
only during incidents; the cursor makes that a three-line loop (see
[`impalactl-operations.md`](./impalactl-operations.md) §7).

Two things that do **not** appear there and need separate handling: MFA resets
done in the database (§5), and `ADMIN_ACCOUNT_IDS` membership (§1).

## Gotchas

- **`whoami` reads the stored token, not the server.** It is the right tool for
  "what does this token actually claim" and the wrong one for "what is this
  account's role now".
- **Deleting an account does not revoke its tokens first.** Revoke explicitly.
- **`account generate` versus `account create`.** `generate` makes the bridge
  custodian of a new seed; `create` links an address whose key the user keeps.
  Choose deliberately — it decides who can sign.
- **Open registration is not an onboarding mechanism.**
  `ALLOW_OPEN_REGISTRATION=true` lets `POST /authenticate` set a password on any
  existing credential-less account, including custodial and SSO-only ones. The
  bridge warns at startup when it is on.
