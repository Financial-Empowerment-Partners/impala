# Impala card

The impala smartcard implementation provides a means of transacting in a Payala
program or the Stellar network using the impala bridge.

Note that this minimal implementation does not support offline LUKs; only online
transactions are supported.

## Supported APDUs

The following subset of Payala APDUs is provided as part of the Impala compatible
implementation. In addition, a handful of new APDUs is defined for Stellar specific
capabilities.

Two new APDUs are Set Ext Pubkey (50) and Get Ext Pubkey (51) to identify the Stellar
account for online transactions.

---

### Initialize  (44)

This command is used to clear any state in the card, including keys and card ID, and generate new EC and RSA keypairs. This command may only be invoked once.

**Input:**

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| Random Seed | ? | +0 |

**Output:** Boolean Success/Failure.

---

### Update User PIN  (25)

This command is used to update the user’s PIN.

**Input:**

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| PIN | 4 | +0 |

**Output:** Boolean Success/Failure.

---

### Verify PIN  (24)

This command is used to verify the user’s PIN code.

**Input:**

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| PIN | 4 | +0 |

**Output:** Boolean Success/Failure.

---

### Update Master PIN  (43)

This command updates the master PIN.

**Input:**

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| PIN | 4 | +0 |

**Output:** Boolean Success/Failure.

---

### NOP  (2)

This APDU does not get processed. Used to verify communication.

**Input:** *[ NO Input CDATA Payload ]*

**Output:** Boolean Success/Failure.

---

### Get Account ID  (22)

This command gets the Account UUID for the cardholder.

**Input:** *[ NO Input CDATA Payload ]*

**Output:**
| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| Account UUID | 16 | +0 |

---

### Get Version  (100)

Used to obtain the current cardlet version. Required for compatibility checks.

**Input:** *[ NO Input CDATA Payload ]*

**Output:**
| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| Major Version | 2 | +0 |
| Minor Version | 2 | +2 |
| Revision | 2 | +4 |
| Git Short Hash | 7 | +6 |

---

### Sign Auth  (37)

This command is used to sign an authentication challenge proving the identity of the cardholder.

**Input:** *Note that the Account UUID and Milliseconds are opaque ChallengeBytes to card.*

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| Account UUID | 16 | +0 |
| DateTime Millis | 8 | +16 |

 **Output:** 

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| ChallengeBytes | 24 | +0 |
| Signature | 36 | +24 |

---

### Get EC Pubkey  (36)

This command returns the EC public key stored on the card.

**Input:** *[ NO Input CDATA Payload ]*

**Output:** 

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| ECPubKey | 65 | +0 |

---

### Get RSA Pubkey  (7)

This command returns the RSA public key used for encryption via card.

**Input:** *[ NO Input CDATA Payload ]*

**Output:** 

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| RSAPubKey | 128 | +0 |

---

### Get Full Name  (32)

This command returns the name associated with a card.

**Input:** *[ NO Input CDATA Payload ]*

**Output:** 

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| Full Name | 128 | +0 |

---

### Set Full Name  (31)

This command sets the name associated with a card.

**Input:** 

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| Full Name | 128 | +0 |

**Output:** Boolean Success/Failure.

---

### Get User Data  (30)

This is an aggregate command to obtain the card ID, account ID, and name.

**Input:** *[ NO Input CDATA Payload ]*

**Output:** 

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| Account ID | 16 | +0 |
| Card ID | 16 | +16 |
| Full Name | 128 | +32 |

---

### Set Card Data  (38)

This is a convenience method for setting the account ID, card ID, and balance associated with a cardholder.

**Input:** 

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| Account ID | 16 | +0 |
| Card ID | 16 | +16 |
| Signature | 72 | +32 |

**Output:** Boolean Success/Failure.

---

### Is Card Alive  (46)

This command checks if the card is able to process commands.

**Input:** *[ NO Input CDATA Payload ]*

**Output:** Boolean Success/Failure.

---

### Set Ext Pubkey  (50)

Set the public key for an external account on the Stellar network. (ed25519)

**Input:** 

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| Public Key | 65 | +0 |

**Output:** Boolean Success/Failure.

---

### Get Ext Pubkey  (51)

Retrieve the public key for an external account on the Stellar network for this user.

**Input:** *[ NO Input CDATA Payload ]*

**Output:** 

| **Field Name** | **Byte Length** | **CDATA Offset** |
| --- | --- | --- |
| ECPubKey | 65 | +0 |

---
