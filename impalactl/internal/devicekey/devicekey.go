// Package devicekey implements the client end of the device-key MFA factor
// (docs/mfa-card-pin-biometrics.md §4): a P-256 key that signs a bridge
// challenge so the bridge can credit `dev`.
//
// The signed message is pinned byte for byte against the bridge
// (impala-bridge/src/mfa/mod.rs build_device_assertion_message) and the
// Android library (impala-lib DeviceKeyProtocol.kt):
//
//	"IMPALA-DKEY:" (12) ‖ 0x01 ‖ purpose (1) ‖ SHA-256(account id, UTF-8) (32) ‖ challenge (32)
//
// signed ECDSA P-256 / SHA-256, DER, hex on the wire. The public key is the
// 65-byte uncompressed SEC1 point, 130 hex characters.
package devicekey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// Tag is the domain tag every device-key message starts with.
const Tag = "IMPALA-DKEY:"

// Version is the message layout version byte.
const Version byte = 0x01

// Purposes: the byte bound into the signed message, so an assertion made for
// one use can never pass for another.
const (
	PurposeEnroll      byte = 0x01 // POST /mfa/device-keys, over a /mfa/challenge value
	PurposeStepUp      byte = 0x02 // POST /mfa/step-up, over a /mfa/challenge value
	PurposeCardSignIn  byte = 0x03 // POST /auth/card, over the card challenge the card signed
	PurposeSep10SignIn byte = 0x04 // POST /auth/sep10, over the challenge transaction hash
)

// ChallengeLength is the length of every challenge an assertion covers.
const ChallengeLength = 32

// Platform is what this client reports at enrollment. Honest: a key in a
// file on an operator's machine.
const Platform = "impalactl"

// UserVerification is what this client declares at enrollment. A file-held
// key verifies nobody: it is possession only, never biometric.
const UserVerification = "none"

// Message builds the device-key assertion message.
func Message(purpose byte, accountID string, challenge []byte) ([]byte, error) {
	if len(challenge) != ChallengeLength {
		return nil, fmt.Errorf("device-key challenge must be %d bytes, got %d", ChallengeLength, len(challenge))
	}
	if accountID == "" {
		return nil, errors.New("device-key message needs an account id")
	}
	accountHash := sha256.Sum256([]byte(accountID))
	msg := make([]byte, 0, len(Tag)+2+len(accountHash)+len(challenge))
	msg = append(msg, Tag...)
	msg = append(msg, Version, purpose)
	msg = append(msg, accountHash[:]...)
	msg = append(msg, challenge...)
	return msg, nil
}

// Generate creates a new P-256 device key.
func Generate() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PublicKeyHex returns the 65-byte uncompressed SEC1 point as lowercase hex.
func PublicKeyHex(pub *ecdsa.PublicKey) (string, error) {
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return "", fmt.Errorf("encode device public key: %w", err)
	}
	b := ecdhPub.Bytes()
	if len(b) != 65 || b[0] != 0x04 {
		return "", fmt.Errorf("device public key is not a 65-byte uncompressed point")
	}
	return hex.EncodeToString(b), nil
}

// MarshalPrivate encodes a private key as hex PKCS#8 DER, for storage.
func MarshalPrivate(priv *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("encode device private key: %w", err)
	}
	return hex.EncodeToString(der), nil
}

// ParsePrivate decodes a stored private key and checks it is P-256 and that
// it matches the stored public key.
func ParsePrivate(pkcs8Hex, publicHex string) (*ecdsa.PrivateKey, error) {
	der, err := hex.DecodeString(pkcs8Hex)
	if err != nil {
		return nil, fmt.Errorf("device private key is not hex: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse device private key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("device private key is not a P-256 key")
	}
	pub, err := PublicKeyHex(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	if pub != publicHex {
		return nil, errors.New("device private key does not match its stored public key")
	}
	return priv, nil
}

// Sign returns the hex DER ECDSA-SHA256 signature of msg.
func Sign(priv *ecdsa.PrivateKey, msg []byte) (string, error) {
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign with the device key: %w", err)
	}
	return hex.EncodeToString(sig), nil
}

// Assert builds and signs the message for (purpose, account, challenge).
func Assert(priv *ecdsa.PrivateKey, purpose byte, accountID string, challenge []byte) (string, error) {
	msg, err := Message(purpose, accountID, challenge)
	if err != nil {
		return "", err
	}
	return Sign(priv, msg)
}
