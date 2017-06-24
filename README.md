# EasyPGP
<a href="https://godoc.org/github.com/EncryptedTimeline/EasyPGP"><img src="https://godoc.org/github.com/encryptedtimeline/easypgp?status.svg"></a>

PGP library for iOS available through gomobile

To use EasyPGP you would need to install gomobile tools, following [tutorial](https://github.com/golang/go/wiki/Mobile).

After that you can build `EasyPGP.framework`:

```
go get github.com/encryptedtimeline/easypgp
gomobile bind -target=ios -o EasyPGP.framework  github.com/encryptedtimeline/easypgp
```

After adding `EasyPGP.framework` to your project you can straight-forward use it.

Swift example:

```swift
let pubkey1  = "-----BEGIN PGP PUBLIC KEY BLOCK-----...."
let privkey1 = "-----BEGIN PGP PRIVATE KEY BLOCK-----...."
let pubkey2  = "-----BEGIN PGP PUBLIC KEY BLOCK-----...."
let privkey2 = "-----BEGIN PGP PRIVATE KEY BLOCK-----...."


let sender = EasypgpNewKeyPairWithKeys(pubkey1, privkey1)
let receiver = EasypgpNewKeyPairWithKeys(pubkey2, nil)
let receiver_with_privkey = EasypgpNewKeyPairWithKeys(pubkey2, privkey2)


let msg = EasypgpEncryptAndSign("hello, world!", receiver, sender, nil)
NSLog((msg?.cipher())!)

let decrypted = EasypgpDecryptAndVerify(msg, receiver_with_privkey, nil)
NSLog((decrypted?.text())!)
```
