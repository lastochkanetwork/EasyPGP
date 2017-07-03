package easypgp

// type EncryptedMessage struct {
// 	Cipher       string
// 	Signature    string
// 	SenderPubkey string
// }

// type DecryptedMessage struct {
// 	Text              string
// 	SignatureVerified bool
// }

type KeyPair struct {
	Pubkey  string
	Privkey string
}

func NewKeyPairWithKeys(pubkey string, privkey string) *KeyPair {
	return &KeyPair{
		Pubkey:  pubkey,
		Privkey: privkey,
	}
}

func EncryptAndSign(message string, recepient *KeyPair, sender *KeyPair) (*EncryptedMessage, error) {
	recepient_entity, err := createEntityFromKeyPair(recepient, false)
	if err != nil {
		return nil, err
	}
	sender_entity, err := createEntityFromKeyPair(sender, true)
	if err != nil {
		return nil, err
	}

	cipher, err := encryptRaw(message, recepient_entity)
	if err != nil {
		return nil, err
	}

	signature, err := createSignature(cipher, sender_entity)
	if err != nil {
		return nil, err
	}

	return &EncryptedMessage{
		Content: &CipherWithSignature{
			Cipher:    cipher,
			Signature: signature,
		},
		SenderPubkey: sender.Pubkey,
	}, nil
}

func Decrypt(cipher string, recepient *KeyPair) (string, error) {
	recepient_entity, err := createEntityFromKeyPair(recepient, true)
	if err != nil {
		return "", err
	}

	text, err := decryptRaw(cipher, recepient_entity)
	if err != nil {
		return "", err
	}

	return text, nil
}

func DecryptAndVerify(message *EncryptedMessage, recepient *KeyPair) (*DecryptedMessage, error) {
	recepient_entity, err := createEntityFromKeyPair(recepient, true)
	if err != nil {
		return nil, err
	}

	text, err := decryptRaw(message.Content.Cipher, recepient_entity)
	if err != nil {
		return nil, err
	}

	signature_ok, err := message.VerifySignature()
	if err != nil {
		return nil, err
	}

	return &DecryptedMessage{
		Text:        text,
		SignatureOk: signature_ok,
	}, nil
}
