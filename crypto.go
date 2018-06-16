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
	"io/ioutil"
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

func (msg EncryptedMessage) VerifySignatureAgainst(pubkey string) (bool, error) {
	sender_entity, err := createEntityFromKeyPair(&KeyPair{Pubkey: pubkey}, false)
	if err != nil {
		return false, err
	}

	pubKey := sender_entity.PrimaryKey
	sig, err := msg.signaturePacket()
	if err != nil {
		return false, err
	}

	hash := sig.Hash.New()
	io.Copy(hash, bytes.NewReader([]byte(msg.Content.Cipher)))

	err = pubKey.VerifySignature(hash, sig)
	if err != nil {
		return false, err
	}
	return true, nil

}

func (msg EncryptedMessage) VerifySignature() (bool, error) {
	return msg.VerifySignatureAgainst(msg.SenderPubkey)
}

func (msg EncryptedMessage) signaturePacket() (*packet.Signature, error) {
	in := bytes.NewReader([]byte(msg.Content.Signature))

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

func EncryptSymmetric(text, key string) (string, error) {
	encryptionType := "LASTOCHKA SYMMETRIC"

	encbuf := bytes.NewBuffer(nil)
	w, err := armor.Encode(encbuf, encryptionType, nil)
	if err != nil {
		return "", err
	}

	plaintext, err := openpgp.SymmetricallyEncrypt(w, []byte(key), nil, nil)
	if err != nil {
		return "", err
	}
	message := []byte(text)
	_, err = plaintext.Write(message)
	if err != nil {
		return "", err
	}

	plaintext.Close()
	w.Close()
	return encbuf.String(), nil
}

func DecryptSymmetric(cipher, key string) (string, error) {
	decbuf := bytes.NewBuffer([]byte(cipher))
	result, err := armor.Decode(decbuf)
	if err != nil {
		return "", err
	}

	md, err := openpgp.ReadMessage(
		result.Body,
		nil,
		func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			return []byte(key), nil
		},
		nil,
	)

	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
