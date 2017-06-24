package easypgp

import (
	"bytes"
	_ "crypto/sha256"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	_ "golang.org/x/crypto/ripemd160"
	"io"
)

func createSignature(what_to_sign string, signing_entity *openpgp.Entity) (string, error) {
	signature_buf := new(bytes.Buffer)
	err := openpgp.ArmoredDetachSign(
		signature_buf,
		signing_entity,
		bytes.NewReader([]byte(what_to_sign)),
		nil,
	)
	if err != nil {
		return "", err
	}

	return signature_buf.String(), nil
}

func encryptRaw(message string, to *openpgp.Entity) (string, error) {
	cipher_buf := new(bytes.Buffer)
	armored, err := armor.Encode(cipher_buf, "Message", make(map[string]string))

	if err != nil {
		return "", err
	}

	encrypted, err := openpgp.Encrypt(armored, []*openpgp.Entity{to}, nil, nil, packetConfig)
	if err != nil {
		return "", err
	}

	// message -> encrypted -> armored -> cipher_buf -> return
	io.Copy(encrypted, bytes.NewReader([]byte(message)))
	encrypted.Close()
	armored.Close()

	return cipher_buf.String(), nil
}

func decryptRaw(cipher string, entity *openpgp.Entity) (string, error) {
	in := bytes.NewReader([]byte(cipher))

	block, err := armor.Decode(in)
	if err != nil {
		return "", err
	}

	if block.Type != "Message" {
		return "", errors.New("Invalid block type")
	}

	md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{entity}, nil, packetConfig)
	if err != nil {
		return "", err
	}

	plaintext_buf := new(bytes.Buffer)
	_, err = io.Copy(plaintext_buf, md.UnverifiedBody)

	return plaintext_buf.String(), err
}

func (msg EncryptedMessage) VerifySignature() (bool, error) {
	sender_entity, err := createEntityFromKeyPair(&KeyPair{Pubkey: msg.SenderPubkey}, false)
	if err != nil {
		return false, err
	}

	pubKey := sender_entity.PrimaryKey
	sig, err := msg.signaturePacket()
	if err != nil {
		return false, err
	}

	hash := sig.Hash.New()
	io.Copy(hash, bytes.NewReader([]byte(msg.Cipher)))

	err = pubKey.VerifySignature(hash, sig)
	if err != nil {
		return false, err
	}
	return true, nil

}

func (msg EncryptedMessage) signaturePacket() (*packet.Signature, error) {
	in := bytes.NewReader([]byte(msg.Signature))

	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.SignatureType {
		return nil, errors.New("Invalid signature")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, err
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, errors.New("Invalid signature")
	}
	return sig, nil
}
