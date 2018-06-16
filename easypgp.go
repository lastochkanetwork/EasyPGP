package easypgp

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

func NewEmptyEncryptedMessage() *EncryptedMessage {
	return &EncryptedMessage{Content: &CipherWithSignature{}}
}

func Encrypt(message string, recipient *KeyPair) (*EncryptedMessage, error) {
	recipient_entity, err := createEntityFromKeyPair(recipient, false)
	if err != nil {
		return nil, err
	}

	cipher, err := encryptRaw(message, recipient_entity)
	if err != nil {
		return nil, err
	}

	return &EncryptedMessage{
		Content: &CipherWithSignature{
			Cipher: cipher,
		},
	}, nil
}

func EncryptAndSign(message string, recipient *KeyPair, sender *KeyPair) (*EncryptedMessage, error) {
	recipient_entity, err := createEntityFromKeyPair(recipient, false)
	if err != nil {
		return nil, err
	}
	sender_entity, err := createEntityFromKeyPair(sender, true)
	if err != nil {
		return nil, err
	}

	cipher, err := encryptRaw(message, recipient_entity)
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

func Decrypt(cipher string, recipient *KeyPair) (string, error) {
	recipient_entity, err := createEntityFromKeyPair(recipient, true)
	if err != nil {
		return "", err
	}

	text, err := decryptRaw(cipher, recipient_entity)
	if err != nil {
		return "", err
	}

	return text, nil
}

func DecryptAndVerify(message *EncryptedMessage, recipient *KeyPair) (*DecryptedMessage, error) {
	recipient_entity, err := createEntityFromKeyPair(recipient, true)
	if err != nil {
		return nil, err
	}

	text, err := decryptRaw(message.Content.Cipher, recipient_entity)
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

func Sign(message string, signer *KeyPair) (string, error) {
	signer_entity, err := createEntityFromKeyPair(signer, true)
	if err != nil {
		return "", err
	}

	signature, err := createSignature(message, signer_entity)
	if err != nil {
		return "", err
	}

	return signature, nil
}

func Verify(message string, signature string, signer_pubkey string) (bool, error) {
	msg := EncryptedMessage{
		Content: &CipherWithSignature{
			Cipher:    message,
			Signature: signature,
		},
	}

	return msg.VerifySignatureAgainst(signer_pubkey)
}
