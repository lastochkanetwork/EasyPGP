package easypgp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"io"
	"time"
)

const nbits = 2048

var packetConfig = &packet.Config{
	DefaultHash:            crypto.SHA256,
	DefaultCipher:          packet.CipherAES256,
	DefaultCompressionAlgo: packet.CompressionZLIB,
	CompressionConfig: &packet.CompressionConfig{
		Level: 9,
	},
	RSABits: nbits,
}

func getPublicKeyFromString(pubkey string) (*packet.PublicKey, error) {
	in := bytes.NewReader([]byte(pubkey))
	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PublicKeyType {
		return nil, errors.New("Invalid public key block")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, errors.New("Error reading public key")
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, errors.New("Invalid public key")
	}
	return key, nil
}

func getPrivateKeyFromString(privkey string) (*packet.PrivateKey, error) {
	in := bytes.NewReader([]byte(privkey))
	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PrivateKeyType {
		return nil, errors.New("Invalid block type")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, errors.New("Error reading private key")
	}

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		return nil, errors.New("Invalid private key")
	}
	return key, nil
}

func createEntityFromKeyPair(keypair *KeyPair, need_privkey bool) (*openpgp.Entity, error) {
	pubkey, err := getPublicKeyFromString(keypair.Pubkey)
	if err != nil {
		return nil, err
	}

	if !need_privkey {
		return createEntityFromKeys(pubkey, nil), nil
	}
	privkey, err := getPrivateKeyFromString(keypair.Privkey)
	if err != nil {
		return nil, err
	}

	return createEntityFromKeys(pubkey, privkey), nil
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packetConfig
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	// keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           nil,
		},
	}
	return &e
}

func GenerateKeyPair() (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, nbits)
	if err != nil {
		return nil, err
	}

	pubkey_buf := bytes.NewBuffer(nil)
	privkey_buf := bytes.NewBuffer(nil)

	err = encodePublicKey(pubkey_buf, key)
	if err != nil {
		return nil, err
	}

	err = encodePrivateKey(privkey_buf, key)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		Pubkey:  pubkey_buf.String(),
		Privkey: privkey_buf.String(),
	}, nil

}

func encodePrivateKey(out io.Writer, key *rsa.PrivateKey) error {
	w, err := armor.Encode(out, openpgp.PrivateKeyType, make(map[string]string))
	if err != nil {
		return err
	}

	pgpKey := packet.NewRSAPrivateKey(time.Now(), key)
	err = pgpKey.Serialize(w)
	if err != nil {
		return err
	}
	return w.Close()
}

func encodePublicKey(out io.Writer, key *rsa.PrivateKey) error {
	w, err := armor.Encode(out, openpgp.PublicKeyType, make(map[string]string))
	if err != nil {
		return err
	}

	pgpKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
	err = pgpKey.Serialize(w)
	if err != nil {
		return err
	}
	return w.Close()
}
