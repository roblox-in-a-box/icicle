package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"icicle/internal/wire"
)

// LoadAuthority keeps the issuer identity across restarts
func LoadAuthority(path string) (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err = rand.Read(seed); err != nil {
			return nil, err
		}
		file, err := os.CreateTemp(filepath.Dir(path), ".icicle-authority-*")
		if err != nil {
			return nil, err
		}
		temporary := file.Name()
		defer os.Remove(temporary)
		_, writeErr := file.Write(seed)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
			return nil, err
		}
		if err = os.Link(temporary, path); errors.Is(err, os.ErrExist) {
			return LoadAuthority(path)
		}
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("authority file must contain a 32 byte Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func ParseAdminKeys(data string) ([]ed25519.PublicKey, error) {
	keys := []ed25519.PublicKey{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		encoded, ok := strings.CutPrefix(line, "ed25519:")
		key, err := base64.RawURLEncoding.DecodeString(encoded)
		if !ok || err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != encoded {
			return nil, fmt.Errorf("invalid admin UniqueUserId %q", line)
		}
		keys = append(keys, ed25519.PublicKey(key))
	}
	return keys, nil
}

func (b *Broker) authorityPolicy() *wire.AuthorityPolicy {
	policy := &wire.AuthorityPolicy{TicketPublicKeys: [][]byte{b.config.SigningKey.Public().(ed25519.PublicKey)}}
	for _, key := range b.config.AdminKeys {
		policy.AdminPublicKeys = append(policy.AdminPublicKeys, key)
	}
	return policy
}
