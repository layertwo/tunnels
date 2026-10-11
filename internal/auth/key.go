package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// MachineKeyFile is the machine's private key in the config dir; it is 0600 and never sent.
const MachineKeyFile = "machine-key.json"

// assertionLifetime bounds a client assertion. It is single-use, so it need only outlive one token
// request; a couple of minutes covers clock skew.
const assertionLifetime = 2 * time.Minute

// assertionType is what a client_assertion carries, per RFC 7523.
const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// GenerateMachineKey makes the ES256 key pair a machine signs its assertions with. The private key
// stays on the machine; only its public half is ever sent to the broker.
func GenerateMachineKey() (jose.JSONWebKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("auth: generate the machine key: %w", err) // coverage-ignore: crypto/rand.Reader does not fail
	}
	return jose.JSONWebKey{Key: key, Algorithm: string(jose.ES256)}, nil
}

// SaveMachineKey writes the private key at path, readable by the owner only.
func SaveMachineKey(path string, key jose.JSONWebKey) error {
	raw, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("auth: encode the machine key: %w", err)
	}
	if err := WriteFileAtomic(path, raw); err != nil {
		return fmt.Errorf("auth: save the machine key: %w", err)
	}
	return nil
}

// LoadMachineKey reads the private key at path.
func LoadMachineKey(path string) (jose.JSONWebKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("auth: read the machine key: %w", err)
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("auth: %s is damaged (%v)", path, err)
	}
	return key, nil
}

// ClientAssertion signs the JWT a machine uses to authenticate at the token endpoint: iss is the
// identity provider, aud the API resource, sub the machine's client id. It carries iat, a short exp
// and a fresh jti, so the assertion is single-use. now is passed in so callers and tests pin the time.
func ClientAssertion(key jose.JSONWebKey, clientID, issuer, audience string, now time.Time) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("auth: sign the assertion: %w", err)
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuer,
		Subject:  clientID,
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(assertionLifetime)),
		ID:       rand.Text(),
	}).Serialize()
	if err != nil {
		return "", fmt.Errorf("auth: sign the assertion: %w", err) // coverage-ignore: the claims are plain values, so Serialize cannot fail once the signer is built
	}
	return raw, nil
}
